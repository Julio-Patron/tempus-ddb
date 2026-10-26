"""
Basic Python API tests for Tempus DDB.

These tests require the package to be installed:
    pip install -e .

Run with:
    pytest tests/test_python_api.py -v
"""

import json
import sqlite3
import time

import pytest
from tempus_ddb import TempusDDB, gen_keys


def test_gen_keys_and_record_genesis(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"

    gen_keys(str(keyfile))
    assert keyfile.exists()

    db = TempusDDB(str(db_path), str(keyfile))

    payload = json.dumps({"action": "test_action", "value": 42})
    rules = json.dumps({"rule": "always_true"})

    result = db.record(payload, rules, genesis=True)
    assert result is not None

    result_str = result if isinstance(result, str) else json.dumps(result)
    assert "latest_hash" in result_str or "output" in result_str


def test_record_with_parent_and_validate(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"

    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    # Genesis record
    payload1 = json.dumps({"step": 1, "decision": "start"})
    rules1 = json.dumps({})
    db.record(payload1, rules1, genesis=True)

    # Child record
    payload2 = json.dumps({"step": 2, "decision": "follow_up"})
    rules2 = json.dumps({})
    db.record(payload2, rules2, genesis=False)

    # Validation must succeed
    validation = db.validate()
    assert validation is not None
    val_str = str(validation).lower()
    assert "invalid" not in val_str and "error" not in val_str


def test_multiple_records_and_repeated_validate(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"

    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    # Multiple decisions
    for i in range(5):
        payload = json.dumps({"step": i, "data": f"decision-{i}"})
        rules = json.dumps({"step": i})
        db.record(payload, rules, genesis=(i == 0))

    validation = db.validate()
    val_str = str(validation).lower()
    assert "invalid" not in val_str


def test_invalid_keyfile_raises(tmp_path):
    db_path = tmp_path / "test.db"
    bad_key = tmp_path / "bad.json"
    bad_key.write_text('{"not": "valid"}')

    with pytest.raises(Exception):
        TempusDDB(str(db_path), str(bad_key))


def test_record_without_genesis_fails_without_parent(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"

    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    payload = json.dumps({"step": 2})
    rules = json.dumps({})

    with pytest.raises(Exception) as exc:
        db.record(payload, rules, genesis=False)

    assert "parent" in str(exc.value).lower() or "genesis" in str(exc.value).lower()


def test_validate_detects_tampering(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"

    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    db.record(json.dumps({"original": True}), json.dumps({}), genesis=True)

    # Tamper with a persisted decision while leaving the signature unchanged.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE decisions SET payload = ?", (json.dumps({"original": False}),)
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(Exception) as exc:
        db.validate()
    val_str = str(exc.value).lower()
    # It should report something wrong
    assert "invalid" in val_str or "error" in val_str or "mismatch" in val_str


def test_record_accepts_both_string_and_dict_like(tmp_path):
    """Ensure the API accepts JSON strings as expected by CLI and MCP."""
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"
    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    # As strings (what CLI passes)
    result = db.record(
        json.dumps({"action": "string_payload"}),
        json.dumps({"rule": "string"}),
        genesis=True,
    )
    assert result is not None


def test_second_genesis_fails_without_idempotency(tmp_path):
    """Idempotency keys are not implemented; a second genesis must be rejected."""
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"
    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    p = json.dumps({"action": "second_genesis_test"})
    r = json.dumps({})

    res1 = db.record(p, r, genesis=True)
    assert res1 is not None

    with pytest.raises(Exception) as exc:
        db.record(p, r, genesis=True)
    assert "genesis" in str(exc.value).lower() or "exists" in str(exc.value).lower()


def test_validate_on_empty_or_single_record(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"
    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    # Validate before any records
    val = db.validate()
    assert val is not None

    db.record(json.dumps({"only": "one"}), json.dumps({}), genesis=True)
    val2 = db.validate()
    assert "valid" in str(val2).lower() or "success" in str(val2).lower()


def test_record_chaining_via_payload(tmp_path):
    keyfile = tmp_path / "keys.json"
    db_path = tmp_path / "test.db"
    gen_keys(str(keyfile))
    db = TempusDDB(str(db_path), str(keyfile))

    h1 = json.loads(db.record(json.dumps({"step": 1}), json.dumps({}), genesis=True))
    parent = h1.get("latest_hash") or h1.get("output", {}).get("latest_hash")

    h2 = json.loads(
        db.record(
            json.dumps({"step": 2, "parent": parent}), json.dumps({}), genesis=False
        )
    )
    assert h2 is not None

    val = db.validate()
    assert "valid" in str(val).lower() or "success" in str(val).lower()


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
