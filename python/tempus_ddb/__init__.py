"""
Tempus - The cryptographic toll gate for autonomous agent actions.

This package issues signed, single-use permits before autonomous effects and records
tamper-evident execution receipts. Every receipt and evidence bundle carries a
`verify_url` that opens the public browser verifier on that evidence.

Core Components:
- TempusDDB: the gate (identities, signed policies, permits, receipts, checkpoints).
- TempusExecutor: Low-level permit verifier and single-consumption helper.
- ExecutorRuntime: Deep engine managing atomic consumption, isolation, and outcome signing.
- ActionAdapter: Unified protocol for implementing credential-isolated adapters.
- AdapterConformanceHarness: Standard test harness to verify custom adapter compliance.
- GitHubExecutorAdapter / GitHubActionAdapter: Credential-isolated executor for bound GitHub writes.
- HttpExecutorAdapter / HttpActionAdapter: Credential-isolated HTTPS webhook executor.
- SlackExecutorAdapter / SlackActionAdapter: Credential-isolated Slack message executor.
- PaymentExecutorAdapter / PaymentActionAdapter: Financial disburse/transfer executor with money envelope.
- gen_keys: Utility to generate Ed25519 key pairs.
- verify_receipt / verify_bundle / verify_checkpoint: Independent verification with a pinned gate public key (no database).
- bundle_digest: SHA-256 of a canonical bundle without its verify_url (what the link carries).
- main_sync: Entry point for the MCP server.

Typical usage:
    from tempus_ddb import TempusDDB, ExecutorRuntime, gen_keys

    gen_keys("keys.json")
    gate = TempusDDB("tempus.db", "keys.json")
"""

__version__ = "0.6.0"

from ._tempus_ddb import (
    TempusDDB,
    TempusExecutor,
    bundle_digest,
    gen_keys,
    verify_bundle,
    verify_checkpoint,
    verify_receipt,
)
from .executor_runtime import (
    ActionAdapter,
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
    UnknownExecutionError,
)
from .github_executor import GitHubActionAdapter, GitHubExecutorAdapter
from .http_executor import HttpActionAdapter, HttpExecutorAdapter
from .mcp_server import main_sync
from .payment_executor import PaymentActionAdapter, PaymentExecutorAdapter
from .slack_executor import SlackActionAdapter, SlackExecutorAdapter
from .testing import AdapterConformanceHarness

__all__ = [
    "ActionAdapter",
    "AdapterConformanceHarness",
    "AmbiguousTransportError",
    "ExecutionResult",
    "ExecutorRuntime",
    "GitHubActionAdapter",
    "GitHubExecutorAdapter",
    "HttpActionAdapter",
    "HttpExecutorAdapter",
    "PaymentActionAdapter",
    "PaymentExecutorAdapter",
    "SlackActionAdapter",
    "SlackExecutorAdapter",
    "TempusDDB",
    "TempusExecutor",
    "UnknownExecutionError",
    "__version__",
    "bundle_digest",
    "gen_keys",
    "main_sync",
    "verify_bundle",
    "verify_checkpoint",
    "verify_receipt",
]
