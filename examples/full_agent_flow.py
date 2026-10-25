"""End-to-end autonomous B2A authorization and execution example."""

import gc
import json
import tempfile
import time
from pathlib import Path

from tempus_ddb import TempusDDB, gen_keys


def public_key(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)["public_key"]


def main():
    with tempfile.TemporaryDirectory(prefix="tempus-agent-flow-") as directory:
        root = Path(directory)
        db_path = root / "agent-flow.db"
        gate_keys = root / "gate.keys.json"
        agent_keys = root / "agent.keys.json"
        executor_keys = root / "executor.keys.json"

        for path in [gate_keys, agent_keys, executor_keys]:
            gen_keys(str(path))

        gate_id = public_key(gate_keys)
        agent_id = public_key(agent_keys)
        executor_id = public_key(executor_keys)
        gate = TempusDDB(str(db_path), str(gate_keys))
        gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
        gate.install_allow_all_dev_policy()  # demo only: explicit allow-all (default is deny-all)
        gate.register_agent(agent_id, "mission-agent", "{}")
        gate.register_agent(executor_id, "mission-executor", "{}")

        intent = json.dumps({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "example-org",
            "agent_id": agent_id,
            "idempotency_key": "mission-001",
            "action_type": "execute_mission",
            "resource": "robot/fleet-7",
            "requested_at": time.time_ns() // 1_000,
            "input": {"target": "zone-4", "safety_distance": 30},
            "money": None,
        })
        authorization = json.loads(gate.request_action(intent, str(agent_keys), 60))
        permit = authorization["authorization"]
        print(f"Authorization: {permit['decision']} ({permit['authorization_id']})")
        if permit["decision"] != "ALLOWED":
            raise RuntimeError("The example intent was unexpectedly blocked.")

        # A real executor verifies the permit, then uses credentials unavailable to
        # the requesting agent. This sample effect is intentionally local.
        observed_result = {"target_reached": True, "distance_maintained": 35}
        outcome = json.dumps({
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": permit["authorization_id"],
            "action_id": permit["action_id"],
            "status": "SUCCEEDED",
            "external_reference": "robot-run-001",
            "output": observed_result,
        })
        receipt = json.loads(
            gate.commit_outcome(permit["authorization_id"], outcome, str(executor_keys))
        )
        verification = json.loads(gate.verify_trace(permit["action_id"]))
        print(f"Execution receipt: {receipt['receipt']['receipt_id']}")
        print(json.dumps(verification, indent=2))

        del gate
        gc.collect()


if __name__ == "__main__":
    main()
