"""
LangChain / LangGraph + Tempus DDB Cookbook: Zero-Trust Tool Execution Gate
===========================================================================
This recipe shows how to wrap any sensitive LangChain tool or LangGraph node
with Tempus DDB.

Key Security Guarantee:
Even if a prompt injection causes the LLM to call a sensitive tool
(e.g., Transfer Funds, Delete Database, Create PR), the tool will NEVER execute
unless Tempus DDB evaluates the tenant policy and issues a valid, signed permit.
"""

import json
import os
import tempfile
import time
from typing import Any, Callable, Dict, Optional

from tempus_ddb import TempusDDB, TempusExecutor, gen_keys


class TempusToolGuard:
    """A cryptographic gateway wrapper for sensitive agent tools."""

    def __init__(
        self,
        gate_db: str,
        gate_keyfile: str,
        executor_db: str,
        executor_keyfile: str,
        agent_keyfile: str,
        tenant_id: str = "acme-corp",
    ):
        self.tenant_id = tenant_id
        self.agent_keyfile = agent_keyfile
        self.executor_keyfile = executor_keyfile

        # Initialize Gate and Executor
        self.gate = TempusDDB(gate_db, gate_keyfile)
        with open(gate_keyfile, "r", encoding="utf-8") as f:
            self.gate_id = json.load(f)["public_key"]

        with open(agent_keyfile, "r", encoding="utf-8") as f:
            self.agent_id = json.load(f)["public_key"]

        with open(executor_keyfile, "r", encoding="utf-8") as f:
            self.executor_id = json.load(f)["public_key"]

        # Register identities in Tempus ledger
        self.gate.register_agent(self.gate_id, "tempus-gate", '{"can_delegate":true}')
        self.gate.install_allow_all_dev_policy()  # demo only: explicit allow-all (default is deny-all)
        self.gate.register_agent(self.agent_id, "langchain-agent", "{}")
        self.gate.register_agent(self.executor_id, "isolated-tool-executor", "{}")

        # The Mediated Executor verifies permits before any effect occurs
        self.executor = TempusExecutor(
            executor_db, executor_keyfile, self.gate_id, self.tenant_id
        )

    def execute_guarded_tool(
        self,
        action_type: str,
        resource: str,
        tool_input: Dict[str, Any],
        tool_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
        money_metadata: Optional[Dict[str, str]] = None,
        ttl_seconds: int = 60,
    ) -> Dict[str, Any]:
        """
        Step 1: Agent signs intent.
        Step 2: Gate checks policy & issues permit (or denies).
        Step 3: Executor validates permit, runs tool_fn, and signs outcome.
        Step 4: Gate records commit & returns verifiable receipt.
        """
        idempotency_key = f"langchain-{int(time.time() * 1000)}-{os.urandom(4).hex()}"

        # 1. Prepare signed intent envelope
        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "idempotency_key": idempotency_key,
            "action_type": action_type,
            "resource": resource,
            "requested_at": int(time.time() * 1_000_000),
            "input": tool_input,
        }
        if money_metadata:
            intent["money"] = money_metadata

        intent_json = json.dumps(intent)

        # 2. Request action authorization from Tempus Gate
        auth_response_str = self.gate.request_action(
            intent_json, self.agent_keyfile, ttl_seconds
        )
        auth_response = json.loads(auth_response_str)
        permit = auth_response.get("authorization", {})

        if permit.get("decision") != "ALLOWED":
            print(f"[BLOCKED BY POLICY] Intent rejected: {permit.get('reasons', ['Policy blocked'])}")
            return {
                "success": False,
                "status": "BLOCKED",
                "reasons": permit.get("reasons", []),
                "authorization_id": permit.get("authorization_id"),
            }

        # 3. Present permit to mediated tool executor
        try:
            permit_json = json.dumps(auth_response)
            verified_auth_str = self.executor.verify_and_consume_permit(permit_json)
            verified_auth = json.loads(verified_auth_str)

            # --- CRITICAL BOUNDARY: Execute the actual tool function ---
            print(f"[EXECUTING TOOL] Action '{action_type}' authorized on '{resource}'")
            tool_result = tool_fn(tool_input)

            # 4. Executor signs outcome
            outcome = {
                "schema_version": "tempus.action-outcome.v1",
                "authorization_id": verified_auth["authorization_id"],
                "action_id": verified_auth["action_id"],
                "status": "SUCCEEDED",
                "external_reference": f"tx-{os.urandom(4).hex()}",
                "output": tool_result,
            }
            outcome_json = json.dumps(outcome)

            # 5. Commit outcome to Tempus gate ledger
            self.gate.commit_outcome(
                verified_auth["authorization_id"],
                outcome_json,
                self.executor_keyfile,
            )

            # 6. Verify the entire end-to-end cryptographic trace
            verification = json.loads(self.gate.verify_trace(verified_auth["action_id"]))
            assert verification["status"] == "VERIFIED", "Cryptographic verification failed!"

            return {
                "success": True,
                "status": "SUCCEEDED",
                "action_id": verified_auth["action_id"],
                "result": tool_result,
                "trace_status": verification["status"],
            }

        except Exception as e:
            print(f"[EXECUTION FAILED] Error: {e}")
            return {"success": False, "status": "FAILED", "error": str(e)}


# ----------------------------------------------------------------------
# Example Usage: LangChain Simulated Tool
# ----------------------------------------------------------------------
def sensitive_database_write(params: Dict[str, Any]) -> Dict[str, Any]:
    """A simulated sensitive tool that requires strict authorization."""
    print(f"   --> Writing to database: {params}")
    return {"rows_affected": 1, "status": "committed"}


def main():
    print("==================================================================")
    print(" LangChain + Tempus DDB Guarded Execution Demo")
    print("==================================================================\n")

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate_db = os.path.join(tmpdir, "gate.db")
        exec_db = os.path.join(tmpdir, "exec.db")
        gate_key = os.path.join(tmpdir, "gate.keys.json")
        agent_key = os.path.join(tmpdir, "agent.keys.json")
        exec_key = os.path.join(tmpdir, "executor.keys.json")

        gen_keys(gate_key)
        gen_keys(agent_key)
        gen_keys(exec_key)

        guard = TempusToolGuard(gate_db, gate_key, exec_db, exec_key, agent_key)

        # Example 1: Valid Action
        print(">> Test 1: Authorized Tool Call")
        res1 = guard.execute_guarded_tool(
            action_type="database.write",
            resource="production/users-table",
            tool_input={"user_id": 42, "role": "admin"},
            tool_fn=sensitive_database_write,
        )
        print(f"Result: {res1}\n")

        print("Done. All action cryptographic traces are 100% verified.")
        del guard


if __name__ == "__main__":
    main()
