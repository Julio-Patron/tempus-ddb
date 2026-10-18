"""Unified Mediated Executor Runtime for Tempus B2A Security Gate.

This module provides the deep ExecutorRuntime engine and ActionAdapter interface
to ensure all mediated executors enforce identical permit verification, atomic
single-consumption, credential isolation, and crash recovery that records an
unknown outcome instead of retrying.
"""

import argparse
import datetime
import decimal
import json
import sys
from typing import Any, Dict, NamedTuple, Optional, Protocol, Set

from ._tempus_ddb import TempusExecutor

_I64_MIN, _U64_MAX = -(2**63), 2**64 - 1


MAX_OUTPUT_DEPTH = 64  # well inside the parser's 128 levels
MAX_REPR_CHARS = 512


class _Unrepresentable(ValueError):
    """The adapter result has no faithful JSON form."""


def _bounded_repr(value: Any) -> str:
    try:
        text = repr(value)
    except Exception:  # a hostile or broken __repr__ must not lose the effect
        return f"<unrepresentable {type(value).__name__}>"
    return (
        text
        if len(text) <= MAX_REPR_CHARS
        else text[:MAX_REPR_CHARS] + "...<truncated>"
    )


def exact_json(value: Any, _depth: int = 0) -> Any:
    """Make a payload safe to sign: only integers in i64/u64 range stay numbers.

    The gate refuses signed documents that hold floats or larger integers, because JSON
    text can spell them several ways and the verifier could not tell which was signed. A
    downstream API answer is not under the executor's control, so such numbers become
    strings (`0.1` -> "0.1", a 30-digit integer -> its exact digits) instead of making the
    outcome of an effect that already happened impossible to record.

    Python values JSON has no form for are converted too: `Decimal` -> its exact string
    (`Decimal("19.990")` -> "19.990"), `datetime`/`date`/`time` -> ISO 8601, and anything
    else (bytes, sets, arbitrary objects) -> a bounded `repr`. Nesting deeper than
    MAX_OUTPUT_DEPTH, and cycles, raise `_Unrepresentable` (see `sanitize_output`).
    """
    if _depth > MAX_OUTPUT_DEPTH:
        raise _Unrepresentable(f"nesting deeper than {MAX_OUTPUT_DEPTH} levels")
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value if _I64_MIN <= value <= _U64_MAX else str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, dict):
        return {
            (key if isinstance(key, str) else str(key)): exact_json(item, _depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [exact_json(item, _depth + 1) for item in value]
    return _bounded_repr(value)


def sanitize_output(payload: Any) -> str:
    """JSON text of an adapter result that can always be signed.

    Criterion: a result the adapter *returned* is evidence about an effect that already
    happened, so a result that cannot be converted (too deep, cyclic, code in the adapter's
    own objects raising in `__repr__` / `__str__` / `isoformat` / `items`, ...) never turns
    into a recorded FAILED: the outcome keeps the adapter's own status and carries a marker
    with a bounded `repr` instead. An exception *raised by the adapter* is a different
    case: the runtime cannot know whether the effect happened, so it records FAILED (or
    UNKNOWN for ambiguous transport errors).
    """
    try:
        return json.dumps(exact_json(payload))
    except Exception as exc:  # incl. code inside the adapter's own objects (__repr__...)
        reason = str(exc) if isinstance(exc, _Unrepresentable) else type(exc).__name__
        return json.dumps(
            {
                "_tempus_output_degraded": True,
                "reason": f"adapter result not representable as JSON: {reason}",
                "repr": _bounded_repr(payload),
            }
        )


class ExecutorRuntimeError(RuntimeError):
    """Base error for runtime and permit verification failures."""


class UnknownExecutionError(ExecutorRuntimeError):
    """The outcome is ambiguous (e.g. timeout or 5xx); must not be retried automatically."""

    def __init__(self, observation: str):
        super().__init__(f"Execution outcome is UNKNOWN: {observation}")
        self.observation = observation


class AmbiguousTransportError(ExecutorRuntimeError):
    """Raised by adapters when an external effect outcome cannot be definitively known."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ExecutionResult(NamedTuple):
    """Outcome of an adapter execution."""

    status: str  # "SUCCEEDED" or "FAILED"
    payload: Dict[str, Any]


class ActionAdapter(Protocol):
    """Protocol that all service-specific mediated adapters must implement."""

    @property
    def supported_actions(self) -> Set[str]:
        """Set of action_type strings handled by this adapter."""
        ...

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        """Execute the external effect with isolated credentials and return ExecutionResult."""
        ...


class ExecutorRuntime:
    """Deep execution engine managing atomic consumption, isolation, and outcome signing."""

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        executor_pool_size: int = 8,
        gate_db: Optional[str] = None,
    ):
        self._executor_db = executor_db
        self._executor_keyfile = executor_keyfile
        self._trusted_gate_id = trusted_gate_id
        self._trusted_tenant_id = trusted_tenant_id
        self._pool_size = executor_pool_size
        self._gate_db = gate_db
        self._executor = TempusExecutor(
            executor_db,
            executor_keyfile,
            trusted_gate_id,
            trusted_tenant_id,
            executor_pool_size,
            gate_db,
        )

    @property
    def raw_executor(self) -> TempusExecutor:
        """Underlying native TempusExecutor."""
        return self._executor

    def execute_permit(self, permit_json: str, adapter: ActionAdapter) -> str:
        """Enforce atomic permit consumption, invoke adapter, and sign outcome receipt."""
        # 1. Enforce atomic single-consumption and schema verification
        consumed_auth_str = self._executor.verify_and_consume_permit(permit_json)
        consumed_auth = json.loads(consumed_auth_str)
        auth_id = consumed_auth["authorization_id"]
        action_id = consumed_auth["action_id"]

        try:
            permit_data = json.loads(permit_json)
            intent = permit_data.get("intent") or permit_data.get(
                "authorization", {}
            ).get("intent", {})
            action_type = intent.get("action_type")

            if action_type not in adapter.supported_actions:
                err_code = getattr(
                    adapter, "unsupported_error_code", "ERR_UNSUPPORTED_ACTION"
                )
                error_payload = {
                    "error_code": err_code,
                    "message": f"Action '{action_type}' is not supported by {adapter.__class__.__name__}",
                }
                return self._executor.complete_execution(
                    auth_id,
                    action_id,
                    "FAILED",
                    json.dumps(error_payload),
                )

            # 2. Invoke adapter with isolated credentials
            result = adapter.execute_action(intent)
            status = (
                result.status if result.status in {"SUCCEEDED", "FAILED"} else "FAILED"
            )
            output_json = sanitize_output(result.payload)

            # 3. Complete and sign execution receipt
            return self._executor.complete_execution(
                auth_id,
                action_id,
                status,
                output_json,
            )

        except AmbiguousTransportError as exc:
            observation = self._executor.mark_unknown(auth_id, exc.reason)
            raise UnknownExecutionError(observation) from exc
        except UnknownExecutionError:
            raise
        except Exception as exc:
            err_msg = str(exc)
            # Check if this was a fatal network ambiguity
            if (
                "500" in err_msg
                or "timeout" in err_msg.lower()
                or "socket" in err_msg.lower()
                or "connection reset" in err_msg.lower()
            ):
                observation = self._executor.mark_unknown(
                    auth_id,
                    f"TRANSPORT_AMBIGUOUS: {exc.__class__.__name__}",
                )
                raise UnknownExecutionError(observation) from exc

            return self._executor.complete_execution(
                auth_id,
                action_id,
                "FAILED",
                json.dumps({"error_code": "EXECUTION_EXCEPTION", "message": err_msg}),
            )

    @classmethod
    def run_cli(
        cls,
        description: str,
        adapter_factory: Any,
        argv: Optional[list] = None,
        extra_args_fn: Optional[Any] = None,
    ) -> None:
        """Standard CLI runner for mediated executor entrypoints."""
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--permit", required=True, help="Path to permit JSON file")
        parser.add_argument(
            "--executor-db", required=True, help="Path to executor SQLite DB"
        )
        parser.add_argument(
            "--executor-keyfile", required=True, help="Path to executor keys JSON"
        )
        parser.add_argument(
            "--gate-id", required=True, help="Trusted Tempus Gate public key"
        )
        parser.add_argument("--tenant-id", required=True, help="Expected tenant ID")
        parser.add_argument(
            "--executor-pool-size", type=int, default=8, help="Connection pool size"
        )
        parser.add_argument(
            "--gate-db",
            default=None,
            help="Optional path to Tempus Gate SQLite DB for revocation and replay verification",
        )

        if extra_args_fn:
            extra_args_fn(parser)

        args = parser.parse_args(argv)

        with open(args.permit, "r", encoding="utf-8") as f:
            permit_content = f.read()

        runtime = cls(
            executor_db=args.executor_db,
            executor_keyfile=args.executor_keyfile,
            trusted_gate_id=args.gate_id,
            trusted_tenant_id=args.tenant_id,
            executor_pool_size=args.executor_pool_size,
            gate_db=args.gate_db,
        )

        adapter = adapter_factory(args)
        try:
            receipt = runtime.execute_permit(permit_content, adapter)
            print(receipt)
        except Exception as exc:
            print(f"Execution failed: {exc}", file=sys.stderr)
            sys.exit(1)
