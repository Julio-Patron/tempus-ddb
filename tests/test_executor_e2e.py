import json
import time
from pathlib import Path

import pytest

# We import the built library
# Make sure to run `python -m maturin build` and install it or run from the built extension
from tempus_ddb import TempusDDB, TempusExecutor, gen_keys


class MockPurchasingAPI:
    """The protected downstream service that only trusts the executor."""

    def __init__(self):
        self.credits = 0
        self.purchase_count = 0

    def add_credits(self, amount: int):
        self.credits += amount
        self.purchase_count += 1
        return {"credits_added": amount, "total_credits": self.credits}


class ExecutorProxy:
    """The mediated executor proxy that sits in front of the API."""

    def __init__(
        self,
        db_path: str,
        keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        api: MockPurchasingAPI,
    ):
        self.executor = TempusExecutor(
            db_path, keyfile, trusted_gate_id, trusted_tenant_id
        )
        self.api = api

    def process_purchase_request(self, permit_json: str):
        try:
            # 1. Enforced mediation: Consume permit atomically
            # This verifies signature, expiration, and prevents double-spend via sqlite.
            auth_str = self.executor.verify_and_consume_permit(permit_json)
            auth = json.loads(auth_str)

            permit_obj = json.loads(permit_json)
            authorized_amount = permit_obj["intent"]["input"]["amount"]

            # 2. Effect: Call the real API
            result = self.api.add_credits(authorized_amount)

            # 3. Complete execution: Sign outcome
            outcome = self.executor.complete_execution(
                auth["authorization_id"],
                auth["action_id"],
                "SUCCEEDED",
                json.dumps(result),
            )
            return json.loads(outcome)

        except Exception as e:
            return {"error": str(e)}


def setup_test_env(tmp_path: Path):
    gate_db = tmp_path / "gate.db"
    exec_db = tmp_path / "executor.db"
    gate_keyfile = tmp_path / "gate.keys.json"
    agent_keyfile = tmp_path / "agent.keys.json"
    executor_keyfile = tmp_path / "executor.keys.json"

    gen_keys(str(gate_keyfile))
    gen_keys(str(agent_keyfile))
    gen_keys(str(executor_keyfile))

    gate = TempusDDB(str(gate_db), str(gate_keyfile))

    with gate_keyfile.open(encoding="utf-8") as f:
        gate_id = json.load(f)["public_key"]
    with agent_keyfile.open(encoding="utf-8") as f:
        agent_id = json.load(f)["public_key"]
    with executor_keyfile.open(encoding="utf-8") as f:
        executor_id = json.load(f)["public_key"]

    gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
    gate.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    gate.register_agent(agent_id, "test-agent", "{}")
    gate.register_agent(executor_id, "test-executor", "{}")

    api = MockPurchasingAPI()
    proxy = ExecutorProxy(
        str(exec_db), str(executor_keyfile), gate_id, "test-tenant", api
    )

    return gate, proxy, api, agent_id, str(agent_keyfile)


def test_successful_purchase_and_replay_prevention(tmp_path):
    gate, proxy, api, agent_id, agent_keyfile = setup_test_env(tmp_path)

    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "test-tenant",
            "agent_id": agent_id,
            "idempotency_key": "purchase-001",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        }
    )

    # Agent gets a permit from the gate
    auth_result = json.loads(gate.request_action(intent, agent_keyfile, 60))
    permit = json.dumps(auth_result)

    # 1. Valid execution
    outcome = proxy.process_purchase_request(permit)
    assert "error" not in outcome
    assert outcome["status"] == "SUCCEEDED"
    assert outcome["output"]["credits_added"] == 100
    assert api.purchase_count == 1

    # 2. Replay prevention (Agent tries to reuse the SAME permit)
    outcome2 = proxy.process_purchase_request(permit)
    assert "error" in outcome2
    assert "already consumed or action ID re-used" in outcome2["error"]
    # The API should not have been called again!
    assert api.purchase_count == 1


def test_expired_permit(tmp_path):
    gate, proxy, api, agent_id, agent_keyfile = setup_test_env(tmp_path)

    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "test-tenant",
            "agent_id": agent_id,
            "idempotency_key": "purchase-002",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 50},
        }
    )

    # Agent gets a permit but it expires immediately (0 seconds)
    # Wait, the rust implementation adds TTL to current time. We might need a small sleep if TTL is 1 sec.
    auth_result = json.loads(gate.request_action(intent, agent_keyfile, 1))
    permit = json.dumps(auth_result)

    time.sleep(1.1)

    outcome = proxy.process_purchase_request(permit)
    assert "error" in outcome
    assert "Permit has expired" in outcome["error"]
    assert api.purchase_count == 0


def test_tampered_permit(tmp_path):
    gate, proxy, api, agent_id, agent_keyfile = setup_test_env(tmp_path)

    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "test-tenant",
            "agent_id": agent_id,
            "idempotency_key": "purchase-003",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        }
    )

    auth_result = json.loads(gate.request_action(intent, agent_keyfile, 60))
    # Agent tries to change the decision or something in the authorization
    auth_result["authorization"]["decision"] = (
        "ALLOWED"  # Even if allowed, changing a byte breaks signature
    )
    auth_result["authorization"]["action_id"] = "fake-action"
    permit = json.dumps(auth_result)

    outcome = proxy.process_purchase_request(permit)
    assert "error" in outcome
    assert (
        "Invalid gate signature" in outcome["error"]
        or "Authorization ID mismatch" in outcome["error"]
    )
    assert api.purchase_count == 0


def test_cross_tenant_permit(tmp_path):
    gate, proxy, api, agent_id, agent_keyfile = setup_test_env(tmp_path)

    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "wrong-tenant",
            "agent_id": agent_id,
            "idempotency_key": "purchase-004",
            "action_type": "purchase",
            "resource": "api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"amount": 100},
        }
    )

    auth_result = json.loads(gate.request_action(intent, agent_keyfile, 60))
    permit = json.dumps(auth_result)

    outcome = proxy.process_purchase_request(permit)
    assert "error" in outcome
    assert "Cross-tenant permit rejected" in outcome["error"]
    assert api.purchase_count == 0


if __name__ == "__main__":
    pytest.main(["-v", __file__])
