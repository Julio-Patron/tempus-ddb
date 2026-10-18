"""Numbers that JSON text can spell several ways must not be signed or verified.

serde_json reads an integer outside i64/u64 and every float as an f64, so the gate used to
round them before signing and the verifier accepted any spelling with the same f64
(`...567890` verified as `...567891`, `0.1` as `1e-1`). Signed documents now contain only
integers in i64/u64 range; decimals and huge values must be strings.

The legacy fixtures are bundles signed by the previous gate: a real gate key, an outcome
whose output holds the float `0.1`, and one holding rounded huge integers.
"""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Set

import pytest
from tempus_ddb.executor_runtime import ExecutionResult, ExecutorRuntime
from test_cli import run_cli
from test_executor_runtime import _create_permit, _setup_gate_and_agents
from test_independent_verify import make_world

FIXTURES = Path(__file__).parent / "fixtures"
LEGACY_GATE = "8c250b2e82b06de5c76b93e4ab139213626b6c42c5931c747f48a7cf712d540a"
FLOAT_TEXT = '"output":{"f":0.1}'
BIGINT_TEXT = (
    '"output":{"g":1.8446744073709552e+19,"h":1.2345678901234568e+29,'
    '"k":-9.223372036854776e+18}'
)


def _verify(tmp_path, text, command="verify-bundle", flag="--bundle"):
    path = tmp_path / "candidate.json"
    path.write_text(text)
    return run_cli(
        [command, flag, str(path), "--gate-public-key", LEGACY_GATE], cwd=tmp_path
    )


def _legacy(name):
    return (FIXTURES / name).read_text()


FLOAT_ATTACKS = [
    '"output":{"f":0.10}',
    '"output":{"f":1e-1}',
    '"output":{"f":1E-1}',
    '"output":{"f":1.0e-1}',
    '"output":{"f":0.1e0}',
    '"output":{"f":1e-01}',
    '"output":{"f":0.1000000000000000055511151231257827}',
]
BIGINT_ATTACKS = [
    BIGINT_TEXT.replace("1.2345678901234568e+29", "123456789012345678901234567891"),
    BIGINT_TEXT.replace("1.2345678901234568e+29", "123456789012345678901234567000"),
    BIGINT_TEXT.replace("1.2345678901234568e+29", "123456789012345678901234567890.0"),
    BIGINT_TEXT.replace("1.8446744073709552e+19", "18446744073709551617"),
    BIGINT_TEXT.replace("1.8446744073709552e+19", "18446744073709552000"),
    BIGINT_TEXT.replace("-9.223372036854776e+18", "-9223372036854775810"),
]


@pytest.mark.parametrize("attack", FLOAT_ATTACKS)
def test_other_spellings_of_a_signed_float_are_invalid(tmp_path, attack):
    text = _legacy("legacy_float_bundle.json")
    assert FLOAT_TEXT in text
    code, out, err = _verify(tmp_path, text.replace(FLOAT_TEXT, attack))
    assert code == 2, out + err
    assert json.loads(out)["status"] == "INVALID"


@pytest.mark.parametrize("attack", BIGINT_ATTACKS)
def test_other_spellings_of_a_rounded_huge_integer_are_invalid(tmp_path, attack):
    text = _legacy("legacy_bigint_bundle.json")
    assert BIGINT_TEXT in text
    code, out, err = _verify(tmp_path, text.replace(BIGINT_TEXT, attack))
    assert code == 2, out + err
    assert json.loads(out)["status"] == "INVALID"


@pytest.mark.parametrize(
    "name", ["legacy_float_bundle.json", "legacy_bigint_bundle.json"]
)
def test_documents_with_non_exact_numbers_are_invalid_even_unmodified(tmp_path, name):
    """Documented break: bundles signed with such numbers can no longer verify."""
    code, out, err = _verify(tmp_path, _legacy(name))
    assert code == 2, out + err
    result = json.loads(out)
    assert result["status"] == "INVALID"
    assert any("NON_EXACT_NUMBER" in e for e in result["errors"])
    assert result["checks"]["execution"] == "FAILED"


def test_receipt_verifier_rejects_them_too(tmp_path):
    trace = json.loads(_legacy("legacy_float_bundle.json"))["trace"]
    code, out, err = _verify(tmp_path, json.dumps(trace), "verify-receipt", "--receipt")
    assert code == 2, out + err
    assert any("NON_EXACT_NUMBER" in e for e in json.loads(out)["errors"])


# ------------------------------------------------------- the gate refuses at origin


@pytest.fixture(scope="module")
def permit_world(tmp_path_factory):
    return make_world(tmp_path_factory.mktemp("exact"), "w", execute=False)


def _commit(world, output):
    root = world["root"]
    receipt = world["permit"]["authorization"]
    outcome = root / "outcome.json"
    outcome.write_text(
        json.dumps(
            {
                "schema_version": "tempus.action-outcome.v1",
                "authorization_id": receipt["authorization_id"],
                "action_id": receipt["action_id"],
                "status": "SUCCEEDED",
                "output": output,
            }
        )
    )
    return run_cli(
        [
            "commit-outcome",
            "--authorization-id",
            receipt["authorization_id"],
            "--outcome",
            str(outcome),
            "--executor-keyfile",
            str(root / "executor.keys.json"),
        ],
        cwd=root,
    )


def test_gate_refuses_non_exact_numbers_then_accepts_exact_ones(permit_world):
    refused = [
        {"h": 123456789012345678901234567890},
        {"g": 18446744073709551616},
        {"k": -9223372036854775809},
        {"f": 0.1},
        {"f": 2.0},
        {"nested": [{"deep": 1e300}]},
    ]
    for output in refused:
        code, out, err = _commit(permit_world, output)
        assert code == 1, f"{output} was accepted: {out}{err}"
        assert "NON_EXACT_NUMBER" in err
    exact = {
        "amount": "25.00",
        "huge": "123456789012345678901234567890",
        "i64_min": -9223372036854775808,
        "u64_max": 18446744073709551615,
        "n": 9007199254740993,
    }
    code, out, err = _commit(permit_world, exact)
    assert code == 0, out + err
    code, out, err = run_cli(
        ["trace", "--action-id", permit_world["action_id"]], cwd=permit_world["root"]
    )
    output = json.loads(out)["execution"]["outcome"]["output"]
    assert output == exact
    assert '"n": 9007199254740993' in json.dumps(json.loads(out)["execution"])


# ------------------------------------------- the packaged executor path stays usable


class FloatPayloadAdapter:
    """A downstream API answered with JSON containing floats and a huge integer."""

    @property
    def supported_actions(self) -> Set[str]:
        return {"custom:echo"}

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        return ExecutionResult(
            status="SUCCEEDED",
            payload=json.loads(
                '{"price": 0.1, "big": 123456789012345678901234567890, "n": 7}'
            ),
        )


def test_executor_turns_float_and_huge_payload_numbers_into_exact_strings():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant = "tenant-exact"
        gate, gate_id, agent_id, _, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant)
        )
        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant,
        )
        permit = _create_permit(
            gate, tenant, agent_id, agent_key, "custom:echo", "exact-1"
        )
        receipt = json.loads(runtime.execute_permit(permit, FloatPayloadAdapter()))
        assert receipt["status"] == "SUCCEEDED", receipt
        assert receipt["output"] == {
            "price": "0.1",
            "big": "123456789012345678901234567890",
            "n": 7,
        }, receipt
        assert os.path.exists(exec_db)


# ----------- a custom adapter whose result cannot be JSON must not lose the effect


class PayloadAdapter:
    """A custom adapter: the external effect happens, then a Python object comes back."""

    def __init__(self, payload):
        self.payload = payload
        self.executed = 0

    @property
    def supported_actions(self) -> Set[str]:
        return {"custom:echo"}

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        self.executed += 1  # the irreversible effect
        return ExecutionResult(status="SUCCEEDED", payload=self.payload)


def _run_adapter(payload, key):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant = "tenant-degrade"
        gate, gate_id, agent_id, _, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant)
        )
        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant,
        )
        adapter = PayloadAdapter(payload)
        permit = _create_permit(gate, tenant, agent_id, agent_key, "custom:echo", key)
        receipt = json.loads(runtime.execute_permit(permit, adapter))
        assert adapter.executed == 1
        return receipt


def _nested(depth):
    value: Any = "leaf"
    for _ in range(depth):
        value = [value]
    return value


def test_decimal_and_datetime_become_exact_strings_and_the_effect_is_recorded():
    import datetime
    import decimal

    when = datetime.datetime(2026, 10, 17, 23, 0, tzinfo=datetime.timezone.utc)
    receipt = _run_adapter(
        {
            "amount": decimal.Decimal("19.990"),
            "big": decimal.Decimal("123456789012345678901234567890.5"),
            "sci": decimal.Decimal("1E+3"),
            "at": when,
            "day": when.date(),
            "list": [decimal.Decimal("0.10")],
        },
        "dec-1",
    )
    assert receipt["status"] == "SUCCEEDED", receipt
    assert receipt["output"] == {
        "amount": "19.990",
        "big": "123456789012345678901234567890.5",
        "sci": "1E+3",
        "at": "2026-10-17T23:00:00+00:00",
        "day": "2026-10-17",
        "list": ["0.10"],
    }


@pytest.mark.parametrize(
    "name,payload",
    [
        ("too deep", _nested(200)),
        ("bytes", {"raw": b"\xff\x00"}),
        ("object", {"obj": object()}),
        ("set", {"s": {1, 2}}),
    ],
)
def test_unrepresentable_results_are_recorded_degraded_not_as_failed(name, payload):
    receipt = _run_adapter(payload, f"deg-{name}".replace(" ", "-"))
    assert receipt["status"] == "SUCCEEDED", receipt
    output = receipt["output"]
    if name == "too deep":
        assert output["_tempus_output_degraded"] is True
        assert "nesting" in output["reason"]
        assert len(output["repr"]) <= 512
    elif name == "bytes":
        assert output == {"raw": "b'\\xff\\x00'"}
    elif name == "set":
        assert output == {"s": "{1, 2}"}
    else:
        assert output["obj"].startswith("<object object at ")


def test_cyclic_result_is_recorded_degraded_and_the_repr_is_bounded():
    cyclic: list = []
    cyclic.append(cyclic)
    receipt = _run_adapter({"loop": cyclic, "pad": "x" * 5000}, "cyc-1")
    assert receipt["status"] == "SUCCEEDED", receipt
    assert receipt["output"]["_tempus_output_degraded"] is True
    assert len(json.dumps(receipt["output"])) < 2000


# ----------- legacy ledger: documented as giving no exact-number guarantee

ROOT = Path(__file__).parent.parent


def _legacy_section() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Legacy ledger")
    return readme[start : readme.index("\n## ", start + 1)]


def test_readme_and_changelog_say_the_legacy_ledger_is_not_verifiable_evidence():
    section = _legacy_section()
    assert "not verifiable evidence" in section
    assert "exact-number" in section
    assert "tempus verify" in section
    unreleased = (
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split("\n## [", 2)[1]
    )
    assert "legacy ledger" in unreleased.lower()
    assert "not verifiable evidence" in unreleased


def test_legacy_ledger_still_validates_an_edited_number_which_is_why_it_is_documented():
    """Pins the limit the docs describe: `verify` hashes the parsed (f64) value."""
    import sqlite3

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db = os.path.join(tmpdir, "legacy.db")
        code, out, err = run_cli(["init", "--allow-all-dev"], cwd=tmpdir)
        assert code == 0, (out, err)
        code, out, err = run_cli(
            [
                "--db",
                db,
                "record",
                "--genesis",
                "--payload",
                '{"v":1e2,"big":123456789012345678901234567890}',
                "--rules",
                '{"r":1}',
            ],
            cwd=tmpdir,
        )
        assert code == 0, (out, err)
        for old, new in (("1e2", "100.0"), ("567890}", "567891}")):
            conn = sqlite3.connect(db)
            conn.execute(
                "update decisions set payload = replace(payload, ?, ?)", (old, new)
            )
            conn.commit()
            conn.close()
            code, out, err = run_cli(["--db", db, "verify"], cwd=tmpdir)
            assert code == 0 and "valid" in out, (old, new, out, err)


# ----------- CLI: numbers JSON cannot spell exactly use the same code and message


@pytest.fixture(scope="module")
def permit_world_cli(tmp_path_factory):
    return make_world(tmp_path_factory.mktemp("exact-cli"), "c", execute=False)


def _commit_raw_output(world, raw_output):
    """commit-outcome with the output spelled exactly as given (no json.dumps)."""
    root = world["root"]
    receipt = world["permit"]["authorization"]
    outcome = root / "outcome-raw.json"
    outcome.write_text(
        '{"schema_version":"tempus.action-outcome.v1","authorization_id":"%s",'
        '"action_id":"%s","status":"SUCCEEDED","output":%s}'
        % (receipt["authorization_id"], receipt["action_id"], raw_output)
    )
    return run_cli(
        [
            "commit-outcome",
            "--authorization-id",
            receipt["authorization_id"],
            "--outcome",
            str(outcome),
            "--executor-keyfile",
            str(root / "executor.keys.json"),
        ],
        cwd=root,
    )


@pytest.mark.parametrize(
    "raw",
    [
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":-Infinity}',
        '{"a":1e400}',
        '{"a":-1e400}',
        '{"a":-0}',
    ],
)
def test_cli_refuses_nan_infinity_overflow_and_negative_zero_as_non_exact(
    permit_world_cli, raw
):
    code, out, err = _commit_raw_output(permit_world_cli, raw)
    assert code == 1, f"{raw} was accepted: {out}{err}"
    assert "NON_EXACT_NUMBER" in err, err
    assert "must be valid JSON" not in err, err


# ----------- docs: duplicate keys at the gate, and the common-breakage guide


def test_readme_documents_gate_duplicate_keys_and_the_common_breakages():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "parse_canonical" in readme and "last value of a repeated" in readme
    start = readme.index("### Common cases that now break, and how to fix them")
    section = readme[start : readme.index("\n## ", start)]
    for needle in (
        "time.time_ns() // 1000",
        "money.amount",
        "$.input.price",
        "metadata",
    ):
        assert needle in section, needle
    unreleased = (
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split("\n## [", 2)[1]
    )
    assert "parse_canonical" in unreleased
    assert "Common cases that now break" in unreleased


def test_gate_keeps_the_last_value_of_a_repeated_key_as_documented():
    """Pins the documented behaviour: the gate does not reject repeated keys on input."""
    from tempus_ddb import TempusDDB
    from test_independent_verify import TENANT, _pub

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        world = make_world(Path(tmpdir), "dup", execute=False)
        root = world["root"]
        agent_keys = root / "agent.keys.json"
        db = TempusDDB(str(root / "tempus.db"), str(root / "keys.json"))
        raw = (
            '{"schema_version":"tempus.action-intent.v1","tenant_id":"%s","agent_id":"%s",'
            '"idempotency_key":"dup-1","action_type":"purchase","resource":"vendor/a",'
            '"resource":"vendor/b","requested_at":%d,"input":{},"money":{"amount":"9999.00",'
            '"amount":"25.00","asset":"USD","beneficiary":"v-1"}}'
        ) % (TENANT, _pub(agent_keys), time.time_ns() // 1000)
        permit = json.loads(db.request_action(raw, str(agent_keys), 30))
        assert permit["intent"]["resource"] == "vendor/b"
        assert permit["intent"]["money"]["amount"] == "25.00"


# ----------- D1: conversion code that raises inside the adapter's own objects


class _BadFloat(float):
    def __repr__(self):
        raise RuntimeError("boom repr")


class _BadDecimal(__import__("decimal").Decimal):
    def __str__(self):
        raise RuntimeError("boom str")


class _BadDatetime(__import__("datetime").datetime):
    def isoformat(self, *args, **kwargs):
        raise RuntimeError("boom isoformat")


class _BadDict(dict):
    def items(self):
        raise RuntimeError("boom items")


class _BadList(list):
    def __iter__(self):
        raise RuntimeError("boom iter")


class _BadKey:
    def __str__(self):
        raise RuntimeError("boom key")

    __hash__ = object.__hash__


def _bad_payloads():

    return {
        "float-repr": {"v": _BadFloat(1.5)},
        "decimal-str": {"v": _BadDecimal("1.5")},
        "datetime-isoformat": {"v": _BadDatetime(2026, 1, 1)},
        "dict-items": _BadDict(a=1),
        "list-iter": {"v": _BadList([1])},
        "key-str": {_BadKey(): 1},
        "nested": {"ok": [1, {"v": _BadFloat(2.5)}]},
    }


@pytest.mark.parametrize("name", list(_bad_payloads()))
def test_conversion_that_raises_is_degraded_not_recorded_as_failed(name):
    receipt = _run_adapter(_bad_payloads()[name], f"d1-{name}")
    assert receipt["status"] == "SUCCEEDED", receipt
    assert receipt["output"]["_tempus_output_degraded"] is True
    assert (
        "RuntimeError" in receipt["output"]["reason"]
        or "not representable" in (receipt["output"]["reason"])
    )


# ----------- D2: the conversion is bounded in nodes and size


def _shared_dag(depth):
    node: Any = "x"
    for _ in range(depth):
        node = [node, node]  # 2**depth nodes when walked as a tree
    return node


def test_exponential_shared_references_degrade_quickly_instead_of_expanding():
    started = time.monotonic()
    receipt = _run_adapter({"dag": _shared_dag(22)}, "d2-dag")  # 4M nodes as a tree
    assert time.monotonic() - started < 5
    assert receipt["status"] == "SUCCEEDED", receipt
    output = receipt["output"]
    assert output["_tempus_output_degraded"] is True
    assert "too large" in output["reason"]
    assert len(output["repr"]) <= 512


def test_a_deeply_shared_dag_does_not_kill_the_process():
    # 2**40 nodes as a tree: this would be killed by the OOM killer without a budget.
    receipt = _run_adapter({"dag": _shared_dag(40)}, "d2-dag-40")
    assert receipt["output"]["_tempus_output_degraded"] is True


@pytest.mark.parametrize(
    "name,payload",
    [
        ("big-string", {"blob": "x" * (5 * 1024 * 1024)}),
        ("many-nodes", {"items": list(range(250_000))}),
        ("big-keys", {("k%d" % i) + "y" * 100_000: 1 for i in range(50)}),
    ],
)
def test_oversized_results_are_degraded_with_the_marker(name, payload):
    receipt = _run_adapter(payload, f"d2-{name}")
    assert receipt["status"] == "SUCCEEDED", receipt
    assert receipt["output"]["_tempus_output_degraded"] is True
    assert "too large" in receipt["output"]["reason"]
    assert len(json.dumps(receipt["output"])) < 2000


def test_results_within_the_budget_are_untouched():
    payload = {"blob": "x" * 900_000, "items": list(range(20_000))}
    receipt = _run_adapter(payload, "d2-fits")
    assert receipt["output"] == payload
