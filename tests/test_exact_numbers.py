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
