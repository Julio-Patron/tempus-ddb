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
