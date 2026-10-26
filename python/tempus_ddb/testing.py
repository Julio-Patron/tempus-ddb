"""Conformance test suite for Tempus ActionAdapter implementations.

This module provides standard test fixtures and assertions to verify that any
custom mediated executor adapter satisfies the Tempus zero-trust security invariants:
- Atomic single-use permit consumption
- Strict credential isolation
- Deterministic outcome receipts
- Crash recovery that records UNKNOWN instead of retrying
"""

import json
import os
import tempfile
import time
from typing import Any, Callable, Dict, Optional

from . import TempusDDB, gen_keys
from .executor_runtime import ActionAdapter, ExecutorRuntime


class AdapterConformanceHarness:
    """Test harness that runs standard verification suites against an ActionAdapter."""

    def __init__(
        self,
        adapter_factory: Callable[[], ActionAdapter],
        valid_action_type: str,
        valid_resource: str,
        valid_input: Dict[str, Any],
        valid_money: Optional[Dict[str, Any]] = None,
        tenant_id: str = "tenant-conformance",
    ):
        self.adapter_factory = adapter_factory
        self.valid_action_type = valid_action_type
        self.valid_resource = valid_resource
        self.valid_input = valid_input
        self.valid_money = valid_money
        self.tenant_id = tenant_id

    def create_environment(self, tmpdir: str) -> Dict[str, Any]:
        """Set up isolated Gate and Executor databases and keys."""
        gate_db = os.path.join(tmpdir, "gate.db")
        exec_db = os.path.join(tmpdir, "exec.db")
        gate_keys = os.path.join(tmpdir, "gate.keys.json")
        agent_keys = os.path.join(tmpdir, "agent.keys.json")
        exec_keys = os.path.join(tmpdir, "exec.keys.json")

        gen_keys(gate_keys)
        gen_keys(agent_keys)
        gen_keys(exec_keys)

        gate = TempusDDB(gate_db, gate_keys)

        with open(gate_keys, "r", encoding="utf-8") as f:
            gate_id = json.load(f)["public_key"]
        with open(agent_keys, "r", encoding="utf-8") as f:
            agent_id = json.load(f)["public_key"]
        with open(exec_keys, "r", encoding="utf-8") as f:
            exec_id = json.load(f)["public_key"]

        gate.register_agent(gate_id, "gate-root", '{"can_delegate":true}')
        gate.register_agent(agent_id, "agent-conformance", "{}")
        gate.register_agent(exec_id, "exec-conformance", "{}")
        # The gate denies everything without a policy. This throwaway harness gate gets
        # an explicit policy scoped to the conformance tenant and its own executor.
        gate.install_policy(
            json.dumps(
                {
                    "schema_version": "tempus.policy-bundle.v1",
                    "policy_version": "tempus.conformance-harness.v1",
                    "tenant_id": self.tenant_id,
                    "constraints": {
                        "allowed_action_types": ["*"],
                        "allowed_resources": ["*"],
                        "allowed_executors": [exec_id],
                        "max_ttl_seconds": 86400,
                        "max_input_bytes": 65536,
                    },
                }
            )
        )

        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_keys,
            trusted_gate_id=gate_id,
            trusted_tenant_id=self.tenant_id,
        )

        return {
            "gate": gate,
            "runtime": runtime,
            "gate_id": gate_id,
            "agent_id": agent_id,
            "agent_keys": agent_keys,
            "exec_id": exec_id,
            "exec_keys": exec_keys,
            "exec_db": exec_db,
        }

    def issue_permit(
        self,
        env: Dict[str, Any],
        action_type: Optional[str] = None,
        idempotency_key: str = "idemp-001",
        custom_input: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Issue a signed authorization permit from the Gate."""
        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": self.tenant_id,
            "agent_id": env["agent_id"],
            "idempotency_key": idempotency_key,
            "action_type": action_type or self.valid_action_type,
            "resource": self.valid_resource,
            "requested_at": int(time.time() * 1_000_000),
            "input": custom_input if custom_input is not None else self.valid_input,
        }
        if self.valid_money:
            intent["money"] = self.valid_money

        auth_resp_str = env["gate"].request_action(
            json.dumps(intent), env["agent_keys"], 60
        )
        auth_resp = json.loads(auth_resp_str)
        if auth_resp.get("authorization", {}).get("decision") != "ALLOWED":
            raise RuntimeError(f"Gate denied permit: {auth_resp}")
        return auth_resp_str

    def run_all_checks(self) -> None:
        """Execute all zero-trust conformance checks against the adapter."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            env = self.create_environment(tmpdir)
            adapter = self.adapter_factory()

            # 1. Check valid execution & verifiable receipt
            permit_1 = self.issue_permit(env, idempotency_key="chk-valid-01")
            receipt_str = env["runtime"].execute_permit(permit_1, adapter)
            receipt = json.loads(receipt_str)
            if receipt.get("status") != "SUCCEEDED":
                raise AssertionError(f"Expected SUCCEEDED, got {receipt}")

            # 2. Check atomic single consumption (replay prevention)
            replay_failed = False
            try:
                env["runtime"].execute_permit(permit_1, adapter)
            except Exception as exc:
                replay_failed = True
                if not (
                    "consumed" in str(exc).lower() or "already" in str(exc).lower()
                ):
                    raise AssertionError(f"Unexpected replay error message: {exc}")
            if not replay_failed:
                raise AssertionError(
                    "Second execution of consumed permit MUST be rejected"
                )

            # 3. Check unsupported action rejection
            permit_unsupported = self.issue_permit(
                env,
                action_type="unsupported.fake.action",
                idempotency_key="chk-unsupported-02",
            )
            unsupported_receipt_str = env["runtime"].execute_permit(
                permit_unsupported, adapter
            )
            unsupported_receipt = json.loads(unsupported_receipt_str)
            if unsupported_receipt.get("status") != "FAILED":
                raise AssertionError(
                    f"Expected FAILED for unsupported action, got {unsupported_receipt}"
                )
