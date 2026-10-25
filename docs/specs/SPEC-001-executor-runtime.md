# SPEC-001: Unified Mediated Executor Runtime (ExecutorRuntime)

**Status:** ready-for-agent  
**Domain Context:** [CONTEXT.md](../../CONTEXT.md)  
**Target Milestone:** 0.5 (Local Durability & Execution Seam Deepening)

---

## Problem Statement

When autonomous AI agents request external effects across multiple services (GitHub, HTTP webhooks, Slack, Payment gateways), each mediated executor currently implements its own boilerplate for:
1. Parsing and validating the gate authorization permit (`tempus.authorization-receipt.v1`).
2. Checking permit validity, expiry, and `ALLOWED` decision.
3. Managing atomic single-consumption transitions (`STARTED` ➔ `SUCCEEDED` / `FAILED` / `UNKNOWN`).
4. Signing the canonical outcome (`tempus.action-outcome.v1`) using the executor identity.
5. Emitting the linked execution receipt and managing crash recovery without accidental replays.

This duplication makes the mediated executor modules **shallow** (their interfaces mirror the database and cryptography complexity) and increases the risk of divergent failure modes, inconsistent retry behavior, or subtle security leaks across adapters.

---

## Solution

Create a deep **`ExecutorRuntime`** engine in the core package that owns the complete execution lifecycle, atomic permit consumption state machine, crash recovery, and outcome signing behind a single, narrow seam.

Specific mediated executors (GitHub, HTTP, Slack, Payment, and future third-party executors) become thin **Adapters** that only provide their service-specific payload validator, credentials loader, and network transport.

---

## User Stories

1. As a Security Engineer, I want all mediated executors to use the exact same atomic permit consumption engine, so that no adapter can accidentally execute without marking the permit as consumed.
2. As a Security Engineer, I want the execution runtime to enforce strict credential isolation, so that the requesting agent's payload never touches downstream API secrets directly.
3. As an Agent Developer, I want unambiguous failure responses when an expired or previously consumed permit is presented, so that my agent handles authorization rejections deterministically.
4. As an Operator, I want interrupted executions (`STARTED`) to transition automatically to a signed `UNKNOWN` outcome on restart, so that ambiguous external effects are never retried blindly.
5. As an Adapter Developer, I want to create a new mediated executor by implementing a single `ActionHandler` protocol (~30 lines), so that I don't have to rewrite cryptographic signing or database locking code.
6. As an Auditor, I want identical, dual-signed cryptographic receipts (`tempus.execution-receipt.v1`) regardless of whether the action targeted GitHub, Slack, or a custom webhook, so that forensic verification is uniform.
7. As a CI/Platform Maintainer, I want all executor invariant tests to run against a single in-process execution seam, so that test execution is fast, exhaustive, and free of duplicated mocking.

---

## Implementation Decisions

### Architectural Seam & Module Structure
- A new deep module `ExecutorRuntime` is created in `python/tempus_ddb/executor_runtime.py` (interfacing with `TempusExecutor` in `_tempus_ddb`).
- The `ExecutorRuntime` encapsulates:
  - Permit deserialization, signature validation, expiry check, and `ALLOWED` decision verification.
  - State machine transition: `STARTED` ➔ `SUCCEEDED` | `FAILED` | `UNKNOWN`.
  - Outcome canonicalization and Ed25519 signing.
  - Connection pooling and atomic SQLite transaction boundary.
  - Restart crash recovery (detecting abandoned `STARTED` records and signing `UNKNOWN` receipts).

### Adapter Protocol Boundary
- An `ActionAdapter` abstract protocol is defined with two simple methods:
  - `validate_intent(intent: Dict[str, Any]) -> None`: Validates resource allowlists, payload shapes, and required arguments.
  - `execute(intent: Dict[str, Any], credentials: Dict[str, str]) -> ExecutionResult`: Executes the actual external API call and returns an external reference/payload.

### Existing Adapters Refactored
- `github_executor.py`, `http_executor.py`, `slack_executor.py`, and `payment_executor.py` are refactored to register their `ActionAdapter` with `ExecutorRuntime.run_cli(...)`.
- CLI entrypoints preserve 100% backward compatibility in flags (`--permit-file`, `--db`, `--keyfile`, `--vault-*`).

---

## Testing Decisions

### What Makes a Good Test
- Tests must verify observable external behavior and cryptographic invariants at the `ExecutorRuntime` boundary, never internal private helpers.
- Tests must verify:
  1. Valid unconsumed permit ➔ atomic consumption + valid signed receipt.
  2. Expired permit ➔ rejection without calling the adapter handler.
  3. Replay / already-consumed permit ➔ rejection with `ERR_PERMIT_ALREADY_CONSUMED`.
  4. Ambiguous transport failure (timeout, reset, disconnect, TLS, EOF, HTTP 5xx) ➔ signed `UNKNOWN` observation (never retried). Any other exception, including a validation error, ➔ signed `FAILED`. Classification is by exception type, not by the message text.
  5. Deterministic crash recovery on restarted runtime instances.

### Modules Tested & Prior Art
- Test suite: `tests/test_executor_runtime.py`, `tests/test_executor_e2e.py`, `tests/test_github_executor.py`, `tests/test_new_executors.py`.
- Prior art in `tests/test_adversarial.py` (replay and tamper tests) is expanded to cover all adapters via the common test harness.

---

## Out of Scope

- Distributed consensus-backed permit stores (scheduled for Milestone 0.6).
- Cloud WORM storage checkpoints (scheduled for Milestone 0.5/0.6).
- Human-in-the-loop interactive approvals (explicitly out of scope per product principles).

---

## Further Notes

- Wire contracts (`tempus.action-intent.v1`, `tempus.authorization-receipt.v1`, `tempus.action-outcome.v1`, `tempus.execution-receipt.v1`) remain strictly unchanged.
