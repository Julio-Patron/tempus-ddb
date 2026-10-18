"""Unit tests for the deep ExecutorRuntime and ActionAdapter seam."""

import json
import os
import tempfile
import time
from typing import Any, Dict, Set

import pytest
from tempus_ddb import TempusDDB, gen_keys
from tempus_ddb.executor_runtime import (
    ExecutionResult,
    ExecutorRuntime,
    UnknownExecutionError,
)


class StubSuccessAdapter:
    """Stub adapter that returns SUCCEEDED for valid actions."""

    @property
    def supported_actions(self) -> Set[str]:
        return {"custom:echo", "custom:write"}

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        return ExecutionResult(
            status="SUCCEEDED",
            payload={"echo": intent.get("input", {}), "executed": True},
        )


class StubFailingAdapter:
    """Stub adapter that returns FAILED for testing deterministic error receipts."""

    @property
    def supported_actions(self) -> Set[str]:
        return {"custom:echo", "custom:fail"}

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        return ExecutionResult(
            status="FAILED",
            payload={
                "error_code": "STUB_DETERMINISTIC_ERROR",
                "message": "Downstream refused",
            },
        )


class StubAmbiguousAdapter:
    """Stub adapter that simulates network timeouts or server 500s."""

    @property
    def supported_actions(self) -> Set[str]:
        return {"custom:timeout"}

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        raise RuntimeError("HTTP 500 Internal Server Error: Gateway timeout")


def _setup_gate_and_agents(tmpdir, tenant_id="tenant-runtime-test"):
    gate_db = os.path.join(tmpdir, "gate.db")
    exec_db = os.path.join(tmpdir, "exec.db")
    gate_key = os.path.join(tmpdir, "gate.keys.json")
    agent_key = os.path.join(tmpdir, "agent.keys.json")
    exec_key = os.path.join(tmpdir, "executor.keys.json")

    gen_keys(gate_key)
    gen_keys(agent_key)
    gen_keys(exec_key)

    gate = TempusDDB(gate_db, gate_key)

    with open(gate_key, "r", encoding="utf-8") as f:
        gate_id = json.load(f)["public_key"]
    with open(agent_key, "r", encoding="utf-8") as f:
        agent_id = json.load(f)["public_key"]
    with open(exec_key, "r", encoding="utf-8") as f:
        exec_id = json.load(f)["public_key"]

    gate.register_agent(gate_id, "gate-root", '{"can_delegate":true}')
    gate.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    gate.register_agent(agent_id, "test-agent", "{}")
    gate.register_agent(exec_id, "test-executor", "{}")

    return gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key


def _create_permit(
    gate,
    tenant_id,
    agent_id,
    agent_key,
    action_type="custom:echo",
    idempotency_key="idemp-001",
):
    intent = {
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "idempotency_key": idempotency_key,
        "action_type": action_type,
        "resource": "https://example.com/api/echo",
        "requested_at": int(time.time() * 1_000_000),
        "input": {"msg": "hello world"},
    }
    auth_resp_str = gate.request_action(json.dumps(intent), agent_key, 60)
    auth_resp = json.loads(auth_resp_str)
    assert auth_resp["authorization"]["decision"] == "ALLOWED"
    return auth_resp_str


def test_executor_runtime_success():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-runtime"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
        )
        adapter = StubSuccessAdapter()
        permit = _create_permit(
            gate, tenant_id, agent_id, agent_key, "custom:echo", "idemp-success-01"
        )

        receipt_str = runtime.execute_permit(permit, adapter)
        receipt = json.loads(receipt_str)

        assert receipt["status"] == "SUCCEEDED"
        assert receipt["action_id"] is not None


def test_executor_runtime_unsupported_action():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-runtime"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
        )
        adapter = StubSuccessAdapter()
        permit = _create_permit(
            gate,
            tenant_id,
            agent_id,
            agent_key,
            "custom:unsupported",
            "idemp-unsupported-01",
        )

        receipt_str = runtime.execute_permit(permit, adapter)
        receipt = json.loads(receipt_str)

        assert receipt["status"] == "FAILED"
        assert "ERR_UNSUPPORTED_ACTION" in receipt_str


def test_executor_runtime_replay_rejection():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-runtime"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
        )
        adapter = StubSuccessAdapter()
        permit = _create_permit(
            gate, tenant_id, agent_id, agent_key, "custom:echo", "idemp-replay-01"
        )

        # First execution succeeds
        receipt_str = runtime.execute_permit(permit, adapter)
        assert json.loads(receipt_str)["status"] == "SUCCEEDED"

        # Second execution must fail closed (permit already consumed)
        with pytest.raises(Exception) as exc_info:
            runtime.execute_permit(permit, adapter)
        assert (
            "consumed" in str(exc_info.value).lower()
            or "already" in str(exc_info.value).lower()
        )


def test_executor_runtime_ambiguous_network_failure():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-runtime"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
        )
        adapter = StubAmbiguousAdapter()
        permit = _create_permit(
            gate, tenant_id, agent_id, agent_key, "custom:timeout", "idemp-ambiguous-01"
        )

        with pytest.raises(UnknownExecutionError) as exc_info:
            runtime.execute_permit(permit, adapter)
        assert "UNKNOWN" in str(exc_info.value)
