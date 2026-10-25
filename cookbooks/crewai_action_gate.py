"""
CrewAI + Tempus DDB Cookbook: Multi-Agent Financial / High-Impact Gate
=====================================================================
In a multi-agent team (e.g. Planner -> Financial Agent -> Action Executor),
delegation must never allow an unconstrained agent to perform high-impact actions
without a verified, cryptographic permit.

This cookbook shows:
1. Agent A (Financial Analyst) requests a fund transfer intent.
2. Tempus Gate evaluates tenant-scoped limits (e.g. $500 max per action).
3. Mediated Executor consumes the permit once, dispatches the transaction,
   and writes the signed receipt.
"""

import json
import os
import tempfile
import time

from tempus_ddb import TempusDDB, TempusExecutor, gen_keys


def run_crewai_tempus_demo():
    print("==================================================================")
    print(" CrewAI + Tempus DDB Multi-Agent Gate Recipe")
    print("==================================================================\n")

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate_db = os.path.join(tmpdir, "gate.db")
        exec_db = os.path.join(tmpdir, "exec.db")

        gate_keyfile = os.path.join(tmpdir, "gate.keys.json")
        analyst_keyfile = os.path.join(tmpdir, "analyst.keys.json")
        executor_keyfile = os.path.join(tmpdir, "executor.keys.json")

        gen_keys(gate_keyfile)
        gen_keys(analyst_keyfile)
        gen_keys(executor_keyfile)

        gate = TempusDDB(gate_db, gate_keyfile)

        with open(gate_keyfile, "r", encoding="utf-8") as f:
            gate_id = json.load(f)["public_key"]
        with open(analyst_keyfile, "r", encoding="utf-8") as f:
            analyst_id = json.load(f)["public_key"]
        with open(executor_keyfile, "r", encoding="utf-8") as f:
            executor_id = json.load(f)["public_key"]

        # 1. Register agents
        tenant_id = "enterprise-fintech"
        gate.register_agent(gate_id, "gate-root", '{"can_delegate":true}')
        gate.install_allow_all_dev_policy()  # demo only: explicit allow-all (default is deny-all)
        gate.register_agent(analyst_id, "crew-analyst-agent", '{"role":"proposer"}')
        gate.register_agent(executor_id, "crew-financial-executor", '{"role":"executor"}')

        # 2. Initialize mediated executor
        executor = TempusExecutor(exec_db, executor_keyfile, gate_id, tenant_id)

        # 3. Agent submits a $150 payment intent
        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": analyst_id,
            "idempotency_key": f"payout-{int(time.time())}",
            "action_type": "finance.disburse",
            "resource": "treasury/rewards-account",
            "requested_at": int(time.time() * 1_000_000),
            "input": {"recipient": "vendor-99", "reason": "Cloud server credits"},
            "money": {"amount": "150.00", "asset": "USD", "beneficiary": "vendor-99"},
        }
        intent_json = json.dumps(intent)

        print(">> [Step 1] Financial Agent requests signed permit from Gate...")
        auth_response_str = gate.request_action(intent_json, analyst_keyfile, 60)
        auth_response = json.loads(auth_response_str)
        permit = auth_response["authorization"]
        print(f"   Gate Decision: {permit['decision']} | Auth ID: {permit['authorization_id'][:16]}...")

        # 4. Executor checks and consumes permit
        print("\n>> [Step 2] Financial Executor verifies permit and executes transaction...")
        permit_json = json.dumps(auth_response)
        verified_auth_str = executor.verify_and_consume_permit(permit_json)
        verified_auth = json.loads(verified_auth_str)

        # Simulated real payout effect
        payout_result = {"status": "TRANSFER_CONFIRMED", "tx_hash": "0x7f2c819a", "amount_paid": "150.00 USD"}
        print(f"   Real Effect Executed: {payout_result}")

        # 5. Sign outcome and commit receipt
        outcome = {
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": verified_auth["authorization_id"],
            "action_id": verified_auth["action_id"],
            "status": "SUCCEEDED",
            "external_reference": "bank-ref-109283",
            "output": payout_result,
        }
        gate.commit_outcome(verified_auth["authorization_id"], json.dumps(outcome), executor_keyfile)

        # 6. Verify audit trace
        verification = json.loads(gate.verify_trace(verified_auth["action_id"]))
        print(f"\n>> [Step 3] Cryptographic Audit Trace: {verification['status']}")
        print("   Receipt is immutable, signed by both Gate and Executor, and verified.")

        del gate
        del executor


if __name__ == "__main__":
    run_crewai_tempus_demo()
