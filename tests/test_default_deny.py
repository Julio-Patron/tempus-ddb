"""Default-deny: without an installed policy the gate must BLOCK, never allow."""

import json
import sqlite3
import time

import pytest
from tempus_ddb import TempusDDB, gen_keys


def _gate(tmp_path):
    for name in ("gate", "agent"):
        gen_keys(str(tmp_path / f"{name}.keys.json"))
    ids = {
        name: json.loads((tmp_path / f"{name}.keys.json").read_text())["public_key"]
        for name in ("gate", "agent")
    }
    db_path = str(tmp_path / "tempus.db")
    gate_keys = str(tmp_path / "gate.keys.json")
    gate = TempusDDB(db_path, gate_keys)
    gate.register_agent(ids["gate"], "gate", '{"can_delegate":true}')
    gate.register_agent(ids["agent"], "agent", "{}")
    return gate, db_path, gate_keys, ids["agent"], str(tmp_path / "agent.keys.json")


def _request(
    gate, agent_id, agent_keys, key, tenant="acme", action="github.delete_repo"
):
    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant,
            "agent_id": agent_id,
            "idempotency_key": key,
            "action_type": action,
            "resource": "evil/x",
            "requested_at": time.time_ns() // 1_000,
            "input": {},
        }
    )
    return json.loads(gate.request_action(intent, agent_keys, 60))


def _assert_not_installed(result):
    receipt = result["authorization"]
    assert receipt["decision"] == "BLOCKED"
    assert receipt["reason_codes"] == ["POLICY_NOT_INSTALLED"]
    assert "policy_bundle" not in result


def test_no_policy_blocks_delete_repo_and_receipt_verifies(tmp_path):
    gate, _, _, agent_id, agent_keys = _gate(tmp_path)
    assert json.loads(gate.list_policies()) == []  # nothing seeded on registration
    result = _request(gate, agent_id, agent_keys, "deny-1")
    _assert_not_installed(result)
    verification = json.loads(gate.verify_trace(result["authorization"]["action_id"]))
    assert verification["status"] == "VERIFIED"


def test_tenant_without_its_own_policy_is_blocked(tmp_path):
    gate, _, _, agent_id, agent_keys = _gate(tmp_path)
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": "acme-v1",
                "tenant_id": "acme",
                "constraints": {
                    "allowed_action_types": ["github.delete_repo"],
                    "allowed_resources": ["*"],
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
                },
            }
        )
    )
    acme = _request(gate, agent_id, agent_keys, "acme-1", tenant="acme")
    assert acme["authorization"]["decision"] == "ALLOWED"  # valid policy still works
    other = _request(gate, agent_id, agent_keys, "other-1", tenant="other")
    _assert_not_installed(other)


def test_deleting_policies_from_the_database_and_reopening_stays_blocked(tmp_path):
    gate, db_path, gate_keys, agent_id, agent_keys = _gate(tmp_path)
    gate.install_allow_all_dev_policy()
    assert (
        _request(gate, agent_id, agent_keys, "pre")["authorization"]["decision"]
        == "ALLOWED"
    )
    del gate
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM active_policy_attestations")
        conn.execute("DELETE FROM policy_bundles")
    for attempt in ("post-1", "post-2"):  # reopen twice: no re-seeding on open
        reopened = TempusDDB(db_path, gate_keys)
        _assert_not_installed(_request(reopened, agent_id, agent_keys, attempt))


def test_baseline_left_by_an_older_gate_is_ignored(tmp_path):
    gate, db_path, gate_keys, agent_id, agent_keys = _gate(tmp_path)
    gate.install_allow_all_dev_policy()
    del gate
    with sqlite3.connect(db_path) as conn:  # looks like a pre-default-deny database
        conn.execute("UPDATE policy_bundles SET policy_version = 'tempus.baseline.v1'")
        conn.execute(
            "UPDATE active_policy_attestations SET policy_version = 'tempus.baseline.v1'"
        )
    reopened = TempusDDB(db_path, gate_keys)
    _assert_not_installed(_request(reopened, agent_id, agent_keys, "legacy"))


def test_allow_all_dev_is_explicit_warns_and_allows(tmp_path):
    gate, _, _, agent_id, agent_keys = _gate(tmp_path)
    with pytest.warns(UserWarning, match="allow-all development policy"):
        bundle = json.loads(gate.install_allow_all_dev_policy())
    assert bundle["policy_version"].startswith("tempus.dev-allow-all.v1")
    assert bundle["tenant_id"] == "*"
    for tenant in ("acme", "never-seen-tenant"):
        result = _request(gate, agent_id, agent_keys, f"dev-{tenant}", tenant=tenant)
        assert result["authorization"]["decision"] == "ALLOWED"
        assert result["authorization"]["policy_version"] == bundle["policy_version"]
    # idempotent while active
    assert (
        json.loads(gate.install_allow_all_dev_policy())["policy_digest"]
        == (bundle["policy_digest"])
    )


def test_forged_no_policy_receipt_cannot_become_allowed(tmp_path):
    gate, db_path, _, agent_id, agent_keys = _gate(tmp_path)
    result = _request(gate, agent_id, agent_keys, "forge")
    action_id = result["authorization"]["action_id"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE action_authorizations SET authorization_json = "
            "replace(replace(authorization_json,'POLICY_NOT_INSTALLED','POLICY_ALLOWED'),"
            "'BLOCKED','ALLOWED') WHERE action_id = ?",
            (action_id,),
        )
    assert json.loads(gate.verify_trace(action_id))["status"] == "INVALID"
