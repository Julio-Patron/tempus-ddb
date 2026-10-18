"""N5-1: the gate and the payment executor accept exactly the same `money.amount` strings.

If the gate allows what the executor then refuses, the single-use permit is consumed and
the receipt is FAILED (the gate used to accept "5.", the executor refuses it). The cases
below run through the real gate and `canonical_money` / `PaymentActionAdapter`, and the
verdicts must be equal. Attacks: forge-5 audit (`n5.py`, `variants.py`).
"""

import tempfile

import pytest
from tempus_ddb.payment_executor import (
    PaymentActionAdapter,
    PaymentExecutorError,
)
from test_money_binding import RecordingTransport, _intent, _world

AMOUNTS_BOTH_ACCEPT = [
    "0",
    "0.0",
    "5",
    "5.5",
    "5.50",
    "05.00",
    "000",
    "25.00",
    "10000.00",
    "184467440737095516.15",  # u64::MAX minor units
]

AMOUNTS_BOTH_REFUSE = [
    "5.",
    "0.",
    "100.",
    ".5",
    ".",
    "5.5.",
    "5.555",
    "-5",
    "+5",
    " 5",
    "5 ",
    "5\n",
    "1e3",
    "0x10",
    "5,00",
    "Infinity",
    "NaN",
    "",
]


# N5-2 (Unicode digits, u64 cap) cases are added with their own commit.
UNICODE_AND_CAP = []


def _gate_verdict(gate, agent_id, agent_key, key, money):
    """True if the gate accepts the money envelope (allowed or blocked by limits)."""
    try:
        gate.request_action(_intent(agent_id, key, money), agent_key, 30)
        return True
    except Exception as exc:
        assert "TEMPUS_INVALID_CONTRACT" in str(exc), exc
        return False


def _executor_verdict(money):
    transport = RecordingTransport()
    adapter = PaymentActionAdapter(transport=transport)
    try:
        adapter.execute_action({"action_type": "payment.charge", "money": money})
        return True
    except PaymentExecutorError:
        assert transport.calls == []
        return False


@pytest.mark.parametrize(
    "amount,accepted",
    [(a, True) for a in AMOUNTS_BOTH_ACCEPT]
    + [(a, False) for a in AMOUNTS_BOTH_REFUSE + UNICODE_AND_CAP],
)
def test_gate_and_executor_agree_on_every_amount_spelling(amount, accepted):
    money = {"amount": amount, "asset": "USD", "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        gate_verdict = _gate_verdict(gate, agent_id, agent_key, "k-amount", money)
    assert gate_verdict == accepted, f"gate on {amount!r}"
    assert _executor_verdict(money) == accepted, f"executor on {amount!r}"
