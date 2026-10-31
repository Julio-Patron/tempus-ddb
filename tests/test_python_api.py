"""
Python API tests for the Tempus gate (permits, receipts, bundles).

These tests require the package to be installed:
    pip install -e .

Run with:
    pytest tests/test_python_api.py -v
"""

import json
import time

import pytest
from tempus_ddb import TempusDDB, gen_keys


def test_invalid_keyfile_raises(tmp_path):
    db_path = tmp_path / "test.db"
    bad_key = tmp_path / "bad.json"
    bad_key.write_text('{"not": "valid"}')

    with pytest.raises(Exception):
        TempusDDB(str(db_path), str(bad_key))


def test_b2a_python_api_round_trip(tmp_path):
    gate_keyfile = tmp_path / "gate.keys.json"
    agent_keyfile = tmp_path / "agent.keys.json"
    executor_keyfile = tmp_path / "executor.keys.json"
    db_path = tmp_path / "b2a.db"
    for path in [gate_keyfile, agent_keyfile, executor_keyfile]:
        gen_keys(str(path))
    gate_id = json.loads(gate_keyfile.read_text())["public_key"]
    agent_id = json.loads(agent_keyfile.read_text())["public_key"]
    executor_id = json.loads(executor_keyfile.read_text())["public_key"]

    db = TempusDDB(str(db_path), str(gate_keyfile))
    db.register_agent(gate_id, "tempus-gate", json.dumps({"can_delegate": True}))
    db.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    db.register_agent(agent_id, "agent", "{}")
    db.register_agent(executor_id, "executor", "{}")

    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "python-test",
            "agent_id": agent_id,
            "idempotency_key": "python-action-001",
            "action_type": "write_file",
            "resource": "workspace/report.json",
            "requested_at": time.time_ns() // 1_000,
            "input": {"digest": "abc123"},
        }
    )
    authorization = json.loads(db.request_action(intent, str(agent_keyfile), 60))
    assert authorization["authorization"]["decision"] == "ALLOWED"
    authorization_id = authorization["authorization"]["authorization_id"]
    action_id = authorization["authorization"]["action_id"]
    outcome = json.dumps(
        {
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": authorization_id,
            "action_id": action_id,
            "status": "SUCCEEDED",
            "output": {"digest": "def456"},
        }
    )
    receipt = json.loads(
        db.commit_outcome(authorization_id, outcome, str(executor_keyfile))
    )
    assert receipt["receipt"]["status"] == "SUCCEEDED"
    verification = json.loads(db.verify_trace(action_id))
    assert verification["status"] == "VERIFIED"
    assert verification["phase"] == "COMPLETED"
