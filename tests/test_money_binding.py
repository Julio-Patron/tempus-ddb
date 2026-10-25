"""The policy and the executors must read the same money fields.

The policy used to evaluate `money.amount_minor` and `money.currency` when present, while
the payment executor sent `money.amount` and `money.asset`: `{"amount":"99999.00",
"amount_minor":1}` was ALLOWED under a limit of 10000.00 and the transport received
99999.00, and `{"currency":"USD","asset":"EUR"}` passed a USD-only list and paid in EUR.
The gate now refuses an intent whose money fields disagree (before anything is signed),
and the payment executor derives amount and asset from the same canonical reading.
"""

import json
import tempfile
import time

import pytest
from tempus_ddb.executor_runtime import ExecutorRuntime
from tempus_ddb.payment_executor import PaymentActionAdapter, PaymentExecutorError
from test_executor_runtime import _setup_gate_and_agents

TENANT = "tenant-money"


class RecordingTransport:
    def __init__(self):
        self.calls = []

    def disburse(self, secret_key, amount, asset, beneficiary, metadata):
        self.calls.append((amount, asset, beneficiary))
        return {"status": "SETTLED"}


def _world(tmpdir):
    gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
        _setup_gate_and_agents(tmpdir, TENANT)
    )
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": "money-v1",
                "tenant_id": TENANT,
                "constraints": {
                    "allowed_action_types": ["payment.charge"],
                    "allowed_resources": ["*"],
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
                    "allowed_currencies": ["USD"],
                    "max_money_amount_minor": 1000000,
                },
            }
        )
    )
    return gate, gate_id, agent_id, exec_db, exec_key, agent_key


def _intent(agent_id, key, money):
    return json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": TENANT,
            "agent_id": agent_id,
            "idempotency_key": key,
            "action_type": "payment.charge",
            "resource": "treasury/main",
            "requested_at": int(time.time() * 1_000_000),
            "input": {},
            "money": money,
        }
    )


INCOHERENT = [
    # the policy read amount_minor=1, the executor sent 99999.00
    ("amount-vs-minor", {"amount": "99999.00", "amount_minor": 1, "asset": "USD"}),
    (
        "amount-vs-minor-over",
        {"amount": "1.00", "amount_minor": 100000000, "asset": "USD"},
    ),
    # the policy read currency=USD, the executor sent asset=EUR
    ("currency-vs-asset", {"amount": "1.00", "currency": "USD", "asset": "EUR"}),
    ("case-differs", {"amount": "1.00", "currency": "USD", "asset": "usd"}),
    # fields the policy skipped because of their type, but the executor stringified
    ("minor-as-string", {"amount": "99999.00", "amount_minor": "1", "asset": "USD"}),
    ("minor-negative", {"amount": "99999.00", "amount_minor": -1, "asset": "USD"}),
    ("currency-not-string", {"amount": "1.00", "currency": 1, "asset": "USD"}),
    ("asset-not-string", {"amount": "1.00", "currency": "USD", "asset": ["EUR"]}),
    ("amount-not-string", {"amount": 99999, "amount_minor": 1, "asset": "USD"}),
]


@pytest.mark.parametrize("name,money", INCOHERENT, ids=[n for n, _ in INCOHERENT])
def test_gate_refuses_money_fields_that_disagree(name, money):
    money = {**money, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(_intent(agent_id, f"k-{name}", money), agent_key, 30)
        assert "TEMPUS_INVALID_CONTRACT" in str(excinfo.value), excinfo.value


COHERENT = [
    ("amount-asset", {"amount": "25.00", "asset": "USD"}, ("25.00", "USD")),
    (
        "one-decimal",
        {"amount": "25.5", "amount_minor": 2550, "currency": "USD"},
        ("25.5", "USD"),
    ),
    ("minor-currency", {"amount_minor": 2500, "currency": "USD"}, ("25.00", "USD")),
    (
        "both-same",
        {"amount": "25.00", "amount_minor": 2500, "currency": "USD", "asset": "USD"},
        ("25.00", "USD"),
    ),
]


@pytest.mark.parametrize("name,money,sent", COHERENT, ids=[c[0] for c in COHERENT])
def test_coherent_money_is_allowed_and_the_executor_sends_what_the_policy_read(
    name, money, sent
):
    money = {**money, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(tmpdir)
        permit = gate.request_action(
            _intent(agent_id, f"k-{name}", money), agent_key, 30
        )
        assert json.loads(permit)["authorization"]["decision"] == "ALLOWED"
        transport = RecordingTransport()
        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=TENANT,
        )
        adapter = PaymentActionAdapter(transport=transport)
        receipt = json.loads(runtime.execute_permit(permit, adapter))
        assert receipt["status"] == "SUCCEEDED", receipt
        assert transport.calls == [(sent[0], sent[1], "b")]


def test_policy_still_blocks_what_it_reads_over_the_limit():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        for key, money in (
            ("over-amount", {"amount": "10000.01", "asset": "USD"}),
            ("over-minor", {"amount_minor": 1000001, "currency": "USD"}),
            ("wrong-asset", {"amount": "1.00", "asset": "EUR"}),
        ):
            money["beneficiary"] = "b"
            result = json.loads(
                gate.request_action(_intent(agent_id, key, money), agent_key, 30)
            )
            assert result["authorization"]["decision"] == "BLOCKED", key
            assert "POLICY_MONEY_DENIED" in result["authorization"]["reason_codes"]


@pytest.mark.parametrize("name,money", INCOHERENT, ids=[n for n, _ in INCOHERENT])
def test_payment_adapter_refuses_disagreeing_fields_on_its_own(name, money):
    """Defence in depth for an adapter used outside the gate's re-evaluation."""
    transport = RecordingTransport()
    adapter = PaymentActionAdapter(transport=transport)
    with pytest.raises(PaymentExecutorError):
        adapter.execute_action(
            {"action_type": "payment.charge", "money": {**money, "beneficiary": "b"}}
        )
    assert transport.calls == []


def test_a_bundle_signed_by_the_old_gate_with_disagreeing_money_no_longer_verifies():
    """Fixture built with 31e51d7: amount 99999.00 / amount_minor 1 was ALLOWED then."""
    from pathlib import Path

    from test_cli import run_cli

    here = Path(__file__).parent
    key = "8a9aa692f69dff06944ac6e57b57f6d07f24d6db700a7f5865948bd835058423"
    code, out, err = run_cli(
        [
            "verify-bundle",
            "--bundle",
            str(here / "fixtures" / "legacy_money_bypass_bundle.json"),
            "--gate-public-key",
            key,
        ]
    )
    result = json.loads(out)
    assert code == 2 and result["status"] == "INVALID", (out, err)
    assert any("amount_minor" in e and "disagree" in e for e in result["errors"])
