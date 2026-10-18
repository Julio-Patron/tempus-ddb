"""Hardening of the independent verifiers, from an independent forge of the evidence
bundle: ambiguous or unsigned content must not verify, and exit codes must be clear.
Attacks are reused from that forge (duplicate keys, extra fields, empty keys, ...)."""

import json

import pytest
from test_cli import run_cli
from test_independent_verify import TENANT, make_world


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    w = make_world(tmp_path_factory.mktemp("harden"), "real")
    root = w["root"]
    bundle = root / "bundle.json"
    code, out, err = run_cli(
        [
            "export-bundle",
            "--action-id",
            w["action_id"],
            "--out",
            str(bundle),
            "--create-checkpoint",
        ],
        cwd=root,
    )
    assert code == 0, out + err
    chk, stream = root / "chk.json", root / "stream.json"
    for sub, path in (("create", chk), ("export", stream)):
        code, out, err = run_cli(
            ["checkpoint", sub, "--tenant-id", TENANT, "--out", str(path)], cwd=root
        )
        assert code == 0, out + err
    w.update(
        bundle=json.loads(bundle.read_text()),
        chk=chk,
        stream=stream,
    )
    return w


def _write(world, name, text):
    path = world["root"] / name
    path.write_text(text)
    return str(path)


def _verify_bundle(world, text, *extra, key=None):
    path = _write(world, "candidate.bundle.json", text)
    return run_cli(
        [
            "verify-bundle",
            "--bundle",
            path,
            "--gate-public-key",
            key or world["gate"],
            *extra,
        ],
        cwd=world["root"],
    )


def _verify_receipt(world, text):
    path = _write(world, "candidate.receipt.json", text)
    return run_cli(
        ["verify-receipt", "--receipt", path, "--gate-public-key", world["gate"]],
        cwd=world["root"],
    )


# ---------------------------------------------------------- 1. duplicate JSON keys


def test_the_untouched_bundle_and_trace_verify(world):
    code, out, err = _verify_bundle(world, json.dumps(world["bundle"]))
    assert code == 0, out + err
    code, out, err = _verify_receipt(world, json.dumps(world["trace"]))
    assert code == 0, out + err


DUPLICATES = [
    # (old fragment, replacement): the signed value is 25.00 / ALLOWED / SUCCEEDED
    ('"amount": "25.00"', '"amount": "9999.00", "amount": "25.00"'),
    ('"amount": "25.00"', '"amount": "25.00", "amount": "9999.00"'),
    ('"decision": "ALLOWED"', '"decision": "BLOCKED", "decision": "ALLOWED"'),
    ('"status": "SUCCEEDED"', '"status": "FAILED", "status": "SUCCEEDED"'),
]


@pytest.mark.parametrize("old,new", DUPLICATES)
def test_duplicate_keys_make_a_bundle_invalid(world, old, new):
    text = json.dumps(world["bundle"])
    assert old in text
    code, out, err = _verify_bundle(world, text.replace(old, new, 1))
    assert code == 2, out + err
    result = json.loads(out)
    assert result["status"] == "INVALID"
    assert "DUPLICATE_JSON_KEY" in result["errors"]


@pytest.mark.parametrize("old,new", DUPLICATES)
def test_duplicate_keys_make_a_receipt_invalid(world, old, new):
    text = json.dumps(world["trace"])
    assert old in text
    code, out, err = _verify_receipt(world, text.replace(old, new, 1))
    assert code == 2, out + err
    assert "DUPLICATE_JSON_KEY" in json.loads(out)["errors"]


def test_duplicate_top_level_bundle_keys_are_invalid(world):
    text = json.dumps(world["bundle"])
    for extra in (', "trace": {}', ', "checkpoint": null'):
        code, out, err = _verify_bundle(world, text[:-1] + extra + "}")
        assert code == 2, out + err
        assert "DUPLICATE_JSON_KEY" in json.loads(out)["errors"]


def test_duplicate_keys_make_a_checkpoint_or_stream_invalid(world):
    chk, stream = world["chk"].read_text(), world["stream"].read_text()
    first_key = next(iter(json.loads(chk)))
    dup_chk = chk.replace("{", "{" + json.dumps(first_key) + ": 0,", 1)
    dup_stream = stream.replace("{", '{"event_id": "x", ', 1)
    for name, c, s in (("c", dup_chk, stream), ("s", chk, dup_stream)):
        code, out, err = run_cli(
            [
                "checkpoint",
                "verify",
                "--checkpoint",
                _write(world, f"dup-{name}.chk.json", c),
                "--stream",
                _write(world, f"dup-{name}.stream.json", s),
                "--gate-public-key",
                world["gate"],
            ],
            cwd=world["root"],
        )
        assert code == 2, out + err
        assert json.loads(out)["reason_code"] == "DUPLICATE_JSON_KEY"


def test_duplicate_keys_in_the_stored_database_trace_are_invalid(world, tmp_path):
    import shutil
    import sqlite3

    shutil.copytree(world["root"], tmp_path / "db")
    root = tmp_path / "db"
    connection = sqlite3.connect(root / "tempus.db")
    (raw,) = connection.execute(
        "SELECT authorization_json FROM action_authorizations WHERE action_id = ?",
        (world["action_id"],),
    ).fetchone()
    marker = '"action_type":"purchase"'
    assert marker in raw
    connection.execute(
        "UPDATE action_authorizations SET authorization_json = ? WHERE action_id = ?",
        (
            raw.replace(marker, '"action_type":"other",' + marker, 1),
            world["action_id"],
        ),
    )
    connection.commit()
    connection.close()
    for extra in ([], ["--gate-public-key", world["gate"]]):
        code, out, err = run_cli(
            ["verify-trace", "--action-id", world["action_id"], *extra], cwd=root
        )
        assert code == 2, out + err
        assert "DUPLICATE_JSON_KEY" in json.loads(out)["errors"]


# ------------------------------------------------- 2. unknown (unsigned) fields


def _with(world, mutate):
    bundle = json.loads(json.dumps(world["bundle"]))
    mutate(bundle)
    return json.dumps(bundle)


@pytest.mark.parametrize(
    "where,mutate",
    [
        ("bundle", lambda b: b.__setitem__("note", "approved by CFO")),
        ("trace", lambda b: b["trace"].__setitem__("note", "x")),
        ("checkpoint wrapper", lambda b: b["checkpoint"].__setitem__("note", "x")),
    ],
)
def test_unknown_fields_make_a_bundle_invalid(world, where, mutate):
    code, out, err = _verify_bundle(world, _with(world, mutate))
    assert code == 2, f"{where}: {out}{err}"
    result = json.loads(out)
    assert result["status"] == "INVALID"
    assert any(error.startswith("UNKNOWN_FIELD") for error in result["errors"])
    assert any("note" in error for error in result["errors"])


def test_unknown_field_in_a_standalone_trace_is_invalid(world):
    trace = json.loads(json.dumps(world["trace"]))
    trace["note"] = "x"
    code, out, err = _verify_receipt(world, json.dumps(trace))
    assert code == 2, out + err
    assert any(e.startswith("UNKNOWN_FIELD") for e in json.loads(out)["errors"])


# ------------------------------------------- 3. an empty key is never "unpinned"


@pytest.mark.parametrize("empty", ["", " ", "   \t"])
def test_empty_gate_key_is_a_usage_error_on_every_verifier(world, empty):
    root = world["root"]
    extra_checkpoint = [
        "--checkpoint",
        str(world["chk"]),
        "--stream",
        str(world["stream"]),
    ]
    commands = [
        ["verify-trace", "--action-id", world["action_id"]],
        ["checkpoint", "verify", *extra_checkpoint],
        ["verify-receipt", "--receipt", str(root / "trace.json")],
        ["verify-bundle", "--bundle", str(root / "bundle.json")],
    ]
    for command in commands:
        code, out, err = run_cli([*command, "--gate-public-key", empty], cwd=root)
        assert code == 1, f"{command[0]} {empty!r}: exit {code}\n{out}{err}"
        assert "VERIFIED" not in out
        assert "empty" in err


def test_empty_executor_key_is_a_usage_error(world):
    code, out, err = run_cli(
        [
            "verify-trace",
            "--action-id",
            world["action_id"],
            "--gate-public-key",
            world["gate"],
            "--executor-public-key",
            "",
        ],
        cwd=world["root"],
    )
    assert code == 1 and "empty" in err and "VERIFIED" not in out


def test_python_api_empty_key_is_an_error_and_none_is_the_documented_unpinned_mode(
    world,
):
    from tempus_ddb import TempusDDB, verify_checkpoint

    db = TempusDDB(str(world["root"] / "tempus.db"), str(world["root"] / "keys.json"))
    for empty in ("", " "):
        with pytest.raises(Exception):
            db.verify_trace(world["action_id"], empty)
        with pytest.raises(Exception):
            verify_checkpoint(
                world["chk"].read_text(), world["stream"].read_text(), empty
            )
    unpinned = json.loads(db.verify_trace(world["action_id"], None))
    assert unpinned["trust"]["independent"] is False


# ------------------------- 4. VERIFIED must say what was decided / executed

import time  # noqa: E402

from tempus_ddb import gen_keys  # noqa: E402
from test_independent_verify import _pub  # noqa: E402


def _make_blocked_world(base):
    """No policy installed: the gate signs a BLOCKED receipt (default-deny)."""
    root = base / "blocked"
    root.mkdir()
    assert run_cli(["init"], cwd=root)[0] == 0
    agent_keys = root / "agent.keys.json"
    gen_keys(str(agent_keys))
    code, out, err = run_cli(
        ["register-agent", "--alias", "buyer", "--agent-keyfile", str(agent_keys)],
        cwd=root,
    )
    assert code == 0, out + err
    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": TENANT,
            "agent_id": _pub(agent_keys),
            "idempotency_key": "pay-1",
            "action_type": "purchase",
            "resource": "vendor/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {},
            "money": {"amount": "25.00", "asset": "USD", "beneficiary": "v-1"},
        }
    )
    code, out, err = run_cli(
        ["request-action", "--intent", intent, "--agent-keyfile", str(agent_keys)],
        cwd=root,
    )
    permit = json.loads(out)
    action_id = permit["authorization"]["action_id"]
    return {
        "root": root,
        "gate": _pub(root / "keys.json"),
        "action_id": action_id,
        "decision": permit["authorization"]["decision"],
    }


@pytest.fixture(scope="module")
def scenarios(world, tmp_path_factory):
    base = tmp_path_factory.mktemp("scenarios")
    found = {
        "done": world,
        "failed": make_world(base, "failed", status="FAILED"),
        "no_exec": make_world(base, "noexec", execute=False),
        "blocked": _make_blocked_world(base),
    }
    assert found["blocked"]["decision"] == "BLOCKED"
    blocked = found["blocked"]
    blocked["trace_json"] = run_cli(
        ["trace", "--action-id", blocked["action_id"]], cwd=blocked["root"]
    )[1]
    (blocked["root"] / "trace.json").write_text(blocked["trace_json"])
    for name, w in found.items():
        for variant, extra in (("nochk", []), ("chk", ["--create-checkpoint"])):
            path = w["root"] / f"{variant}.bundle.json"
            code, out, err = run_cli(
                ["export-bundle", "--action-id", w["action_id"], "--out", str(path)]
                + extra,
                cwd=w["root"],
            )
            assert code == 0, f"{name}/{variant}: {out}{err}"
            w[variant] = str(path)
    return found


def _bundle_cli(w, variant, *extra):
    return run_cli(
        [
            "verify-bundle",
            "--bundle",
            w[variant],
            "--gate-public-key",
            w["gate"],
            *extra,
        ],
        cwd=w["root"],
    )


@pytest.mark.parametrize(
    "name,decision,execution_status",
    [
        ("done", "ALLOWED", "SUCCEEDED"),
        ("failed", "ALLOWED", "FAILED"),
        ("no_exec", "ALLOWED", None),
        ("blocked", "BLOCKED", None),
    ],
)
def test_verified_output_states_decision_and_execution_status(
    scenarios, name, decision, execution_status
):
    w = scenarios[name]
    code, out, err = _bundle_cli(w, "chk")
    assert code == 0, out + err
    result = json.loads(out)
    assert result["decision"] == decision
    assert result["execution_status"] == execution_status
    code, out, err = run_cli(
        [
            "verify-trace",
            "--action-id",
            w["action_id"],
            "--gate-public-key",
            w["gate"],
        ],
        cwd=w["root"],
    )
    assert code == 0, out + err
    traced = json.loads(out)
    assert (traced["decision"], traced["execution_status"]) == (
        decision,
        execution_status,
    )
    code, out, err = run_cli(
        [
            "verify-receipt",
            "--receipt",
            str(w["root"] / "trace.json"),
            "--gate-public-key",
            w["gate"],
        ],
        cwd=w["root"],
    )
    assert code == 0, out + err
    assert json.loads(out)["decision"] == decision


def test_invalid_results_do_not_report_a_decision_or_execution_status(scenarios):
    w = scenarios["done"]
    bundle = json.loads(open(w["chk"]).read())
    auth = bundle["trace"]["authorization"]["authorization"]
    auth["decision"] = "BLOCKED"
    path = w["root"] / "flipped.bundle.json"
    path.write_text(json.dumps(bundle))
    w["flipped"] = str(path)
    code, out, err = _bundle_cli(w, "flipped")
    assert code == 2
    result = json.loads(out)
    assert result["decision"] is None and result["execution_status"] is None


@pytest.mark.parametrize(
    "name,variant,flags,code",
    [
        ("done", "chk", [], 0),
        (
            "done",
            "chk",
            [
                "--require-execution",
                "--require-checkpoint",
                "--require-decision",
                "ALLOWED",
            ],
            0,
        ),
        ("failed", "chk", [], 0),
        ("failed", "chk", ["--require-execution"], 2),
        ("no_exec", "chk", ["--require-execution"], 2),
        ("failed", "nochk", [], 0),
        ("failed", "nochk", ["--require-checkpoint"], 2),
        ("blocked", "chk", ["--require-decision", "BLOCKED"], 0),
        ("blocked", "chk", ["--require-decision", "ALLOWED"], 2),
        ("blocked", "chk", ["--require-execution"], 2),
        ("done", "chk", ["--require-decision", "BLOCKED"], 2),
    ],
)
def test_require_flags_on_verify_bundle(scenarios, name, variant, flags, code):
    got, out, err = _bundle_cli(scenarios[name], variant, *flags)
    assert got == code, f"{name}/{variant} {flags}: {out}{err}"
    result = json.loads(out)
    if code == 2:
        assert result["status"] == "INVALID"
        assert any(e.startswith("REQUIREMENT_NOT_MET") for e in result["errors"])
    else:
        assert result["status"] == "VERIFIED"


def test_require_flags_on_verify_receipt_and_verify_trace(scenarios):
    for name, wanted in (("done", 0), ("failed", 2), ("no_exec", 2), ("blocked", 2)):
        w = scenarios[name]
        trace_args = ["--action-id", w["action_id"], "--gate-public-key", w["gate"]]
        code, out, err = run_cli(
            ["verify-trace", *trace_args, "--require-execution"], cwd=w["root"]
        )
        assert code == wanted, f"verify-trace {name}: {out}{err}"
        code, out, err = run_cli(
            [
                "verify-receipt",
                "--receipt",
                str(w["root"] / "trace.json"),
                "--gate-public-key",
                w["gate"],
                "--require-execution",
                "--require-decision",
                "ALLOWED",
            ],
            cwd=w["root"],
        )
        assert code == wanted, f"verify-receipt {name}: {out}{err}"
