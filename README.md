<div align="center">
  <img src="assets/logo.png" alt="Tempus DDB" width="180" />

# Tempus DDB

### The B2A (Bot-to-Agent) Security Gate for Autonomous Agent Actions

**Zero-trust authorization · Single-use cryptographic permits · Tamper-evident receipts · MCP native**

<p align="center">
  <a href="https://github.com/elbuilder77/tempus-ddb/actions/workflows/ci.yml"><img src="https://github.com/elbuilder77/tempus-ddb/actions/workflows/ci.yml/badge.svg" alt="CI Build" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-passing-brightgreen.svg?logo=github" alt="Tests" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb/releases"><img src="https://img.shields.io/github/v/release/elbuilder77/tempus-ddb?color=blue&logo=github" alt="GitHub Release" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/pypi/v/tempus-ddb.svg?logo=pypi&logoColor=white&color=blue" alt="PyPI Version" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/pypi/dm/tempus-ddb.svg?color=success" alt="PyPI Downloads" /></a>
  <a href="https://pypi.org/project/tempus-ddb/"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python&logoColor=white" alt="Python 3.10+" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" /></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-blue.svg?logo=shield" alt="Security Policy" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb/discussions"><img src="https://img.shields.io/badge/community-discussions-orange.svg?logo=github" alt="Community Discussions" /></a>
</p>

---

### ⚡ Quick Install
```bash
git clone https://github.com/elbuilder77/tempus-ddb.git
cd tempus-ddb
pip install -e ".[dev]"      # compiles the Rust extension: needs a Rust toolchain (see Install)
tempus --version
```
> The PyPI release (`pip install tempus-ddb`, 0.5.3) predates default-deny and independent
> verification: it still seeds an allow-all policy on `tempus init` and has no
> `verify-receipt`, `export-bundle`, `verify-bundle` or `--allow-all-dev`. The flows in
> this README need the source install above until a new release is published.

### 🚀 [Try the Live Interactive Trace Demo →](https://julio-patron.github.io/tempus-ddb/)
*Verify real cryptographic hashes, Ed25519 signatures, and tamper detection directly in your browser.*

---
</div>

> **Status: beta (`0.5.3` milestone line).** Signed policy, identity lifecycle,
> Vault-backed signing, mediated executor runtime (GitHub, HTTP, Slack, Payment),
> hash-linked event streaming, and signed monotonic checkpoints are implemented.
> Distributed multi-container gate service is in progress (0.6).
>
> [Project site](https://elbuilder77.github.io/tempus-ddb/) ·
> [Integration guide](https://elbuilder77.github.io/tempus-ddb/docs.html) ·
> [Architecture Blueprints](docs/blueprints/README.md) ·
> [Cookbooks](cookbooks/README.md) ·
> [Interactive trace demo](https://elbuilder77.github.io/tempus-ddb/trace.html) ·
> [Roadmap](ROADMAP.md) · [Security](SECURITY.md) ·
> [Threat model](THREAT_MODEL.md) · [Contributing](CONTRIBUTING.md)

---

## 💡 ¿Qué resuelve Tempus? / What Tempus Solves

When autonomous AI agents take actions (calling external APIs, issuing database writes, creating pull requests, moving funds), **they must not approve their own requests or directly hold privileged downstream credentials**.

Tempus DDB creates an enforced **B2A (Bot-to-Agent / Bot-to-Action) Security Boundary**:

1. 🛑 **Zero-Trust Authorization Toll:** The agent cryptographically signs its *intent*. It cannot execute directly.
2. 📜 **Signed, Deterministic Policy:** Tempus evaluates tenant policy and issues an expiring, single-use signed permit (`ALLOWED` or `BLOCKED`).
3. 🔒 **Credential Isolation:** The mediated executor—not the AI agent—holds downstream secrets (e.g. `GITHUB_TOKEN`, API keys) and only executes when presented with a valid, unconsumed permit.
4. 🧾 **Tamper-Evident Receipts:** Both the executor and Tempus gate sign the outcome, generating an immutable, mathematically verifiable cryptographic trace.

> **Product Invariant:** *No Tempus permit, no effect; every effect produces a verifiable receipt.*

---

## ⚔️ Why Tempus vs Traditional RBAC / MCP Gateways?

In 2026, several MCP governance proxies (such as Bifrost, Obot, MCPX, MintMCP) manage agent access using role-based access control (RBAC). **Tempus DDB solves a completely different, deeper architectural problem:**

| Dimension | Traditional MCP Gateways (RBAC / Proxies) | Tempus DDB (B2A Toll Gate) |
|---|---|---|
| **Security Model** | **Authorize & Forward (*"Trust"*):** Checks rules, forwards requests, and trusts the agent and downstream service. | **Cryptographic Toll (*"Zero-Trust"*):** Agent signs intent; Gate issues single-use permit; Executor consumes permit atomically. |
| **Credential Boundary** | Agent or Gateway proxy holds raw API keys and database credentials. | **Strict Credential Isolation:** Agent *never* sees or handles downstream secrets (`GITHUB_TOKEN`, Slack tokens, API keys). |
| **Replay & Loop Prevention** | Advisory rate limits; repeated calls within role permissions pass through. | **Single-use permits:** Each permit can be consumed once: the gate rejects a second, different outcome for the same permit and the executor runtime rejects a reused permit (single-instance deployments; multi-instance consumption is not yet proven). |
| **Tamper Detection** | Server application logs (which can be modified, truncated, or forged). | **Dual-signed receipts:** Cryptographically linked (Ed25519 + SHA-256). Anyone holding the gate's public key can check them offline with `verify-receipt` / `verify-bundle`; this detects altered or forged receipts, not omitted ones (see *Independent verification*). |
| **Financial / High-Impact Actions** | Unstructured JSON payloads. | **Universal `money` Contract:** Hard limits, currency enforcement, and tenant-scoped asset ceilings. |

---

## 🔍 Interactive Trace Demo

Inspect how Tempus binds the entire lifecycle (Intent ➔ Authorization ➔ Execution ➔ Receipt) with Ed25519 signatures and SHA-256 state hashes:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TEMPUS B2A PROTOCOL FLOW                          │
├─────────────────┬─────────────────┬───────────────────┬─────────────────────┤
│  01 / INTENT    │  02 / POLICY    │  03 / EXECUTION   │  04 / VERIFICATION  │
│  Agent signs    │  Gate issues    │  Executor verifies│  End-to-end receipt │
│  exact payload  │  single-use     │  permit & acts    │  cryptographically │
│                 │  permit         │  with isolated key│  linked & immutable │
│   [ BOUND ]     │   [ ALLOWED ]   │    [ CONSUMED ]   │    [ VERIFIED ]     │
└────────┬────────┴────────┬────────┴─────────┬─────────┴──────────┬──────────┘
         │                 │                  │                    │
         ▼                 ▼                  ▼                    ▼
   Signed Intent ──► Expiring Permit ──► Execution Receipt ──► Auditable Trace
```

👉 **[Launch Interactive In-Browser Demo](https://elbuilder77.github.io/tempus-ddb/trace.html)** — *Test tamper detection, hash validation, and signature verification live.*

---

The `0.5.3` implementation establishes the local permit protocol, signed policy
bundles, rotation and revocation, unified mediated `ExecutorRuntime` (GitHub, HTTP/Webhooks, Slack, and Pluggable Payments), Vault Transit signing, single-instance replay protection, and cryptographically signed monotonic checkpoints for verifiable disaster recovery. Read
[THREAT_MODEL.md](THREAT_MODEL.md) before relying on the current security boundary.

## What is implemented

- **[Enterprise Architecture & Product Blueprints](docs/blueprints/README.md)**: Production implementation guides for
  [DevOps over MCP (OpenClaw, Hermes Agent, Cursor, Claude, Windsurf)](docs/blueprints/devops-mcp/product-blueprint.md)
  and [Financial Toll Gates for Multi-Agent Crews (CrewAI, LangGraph, AutoGen)](docs/blueprints/payments-crewai/product-blueprint.md).
- Stable machine contracts with explicit `schema_version` values (`.v1`).
- Separate Ed25519 identities for the Tempus gate, requesting agent, and executor.
- Immutable, gate-signed agent registration receipts. Registrations cannot be silently
  overwritten.
- Signed, versioned deterministic policy bundles. Each permit binds its policy digest,
  reproducible evidence digest, closed reason codes, and executor constraints.
- Tenant-scoped delegation, signed key rotation and revocation, historical key-at-time
  verification, and emergency invalidation of unconsumed permits.
- A provider-neutral signer boundary shared by the gate and executor. Local Ed25519 and
  Vault Transit use the same exact-byte contract; a signing timeout, error, unexpected key version or signature that does not verify aborts the operation and no receipt is issued.
- `ALLOWED` or `BLOCKED` authorization before execution.
- Short-lived permits, deterministic action IDs, and idempotency conflict detection.
- Single-consumption execution receipts; an identical retry is idempotent and a
  conflicting second outcome is rejected.
- End-to-end verification of intent, gate authorization, executor outcome, and receipt
  linkage.
- A unified mediated `ExecutorRuntime` with conformance testing for third-party adapters.
- Signed executor observations for `STARTED`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`, with
  restart recovery that never retries an ambiguous external effect.
- Pre-packaged reference executors for GitHub (`github.create_issue`, `github.create_pull_request`), HTTP/Webhooks, Slack, and Pluggable Payments.
- Money is optional metadata in the same universal action envelope; financial and
  non-financial actions use the same protocol.
- Append-only hash-linked event streams (`tempus.event-stream-event.v1`) and signed monotonic checkpoints (`tempus.checkpoint.v1`) for tamper and rollback detection.
- Disaster recovery and offline reconciliation tooling (`tempus checkpoint create / export / verify`).
- An autonomous MCP surface that hides administrative, legacy, and destructive tools by
  default.

## B2A flow

```text
agent signs intent
        │
        ▼
Tempus request_action ── BLOCKED ──► signed denial trace
        │ ALLOWED
        ▼
single-use, expiring permit
        │
        ▼
executor performs effect and signs outcome
        │
        ▼
Tempus commit_outcome ──► final signed execution receipt
        │
        ▼
human or machine calls verify_trace
```

Tempus becomes an unavoidable toll when the executor exclusively holds the downstream
credential. The packaged GitHub adapter implements that boundary for its supported
actions in a single-instance deployment. Operators must ensure the requesting agent
cannot read the executor's environment or key material.

## Install

Python 3.10 or newer is required.

### 1. From PyPI (Standard & Verified)
> **Not enough for this README yet.** PyPI 0.5.3 does not include default-deny or
> independent verification (`verify-receipt`, `export-bundle`, `verify-bundle`,
> `--allow-all-dev`); use section 3 (from source) to follow the commands below.

Tempus DDB is published to PyPI using **Trusted Publishing (OIDC)** and **Sigstore provenance attestations** on every artifact:
```bash
python -m pip install tempus-ddb
```

### 2. From GitHub Release Wheels & SBOM
Download the pre-built native wheel matching your platform or the SPDX SBOM from [GitHub Releases v0.5.3](https://github.com/elbuilder77/tempus-ddb/releases/tag/v0.5.3):
```bash
pip install ./tempus_ddb-0.5.3-<platform>.whl
```

### 3. From Source (Development)

Building from source compiles the Rust extension, so you need a **Rust toolchain**
(minimum supported version `rust-version = "1.88"`, see `Cargo.toml`; the repository
pins `1.99.1` in `rust-toolchain.toml`, which `rustup` installs for you on first build)
plus a C linker (`build-essential` / Xcode command line tools / MSVC build tools).
The PyPI and release wheels above need no Rust.

```bash
# Install Rust once (https://rustup.rs), then reopen your shell or: . "$HOME/.cargo/env"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/elbuilder77/tempus-ddb.git
cd tempus-ddb
pip install -e ".[dev]"      # builds the extension with maturin; takes a few minutes
tempus --version
```

## Bootstrap identities

`tempus init` creates the local gate key and database, then records the gate as the
signed delegation root. This is deployment-time bootstrap, not a human approval step
for each action.

```bash
tempus init
tempus keygen --output agent.keys.json
tempus keygen --output executor.keys.json

tempus register-agent --alias purchasing-agent --agent-keyfile agent.keys.json \
  --metadata '{"tenant_id":"acme"}'
tempus register-agent --alias purchasing-executor --agent-keyfile executor.keys.json \
  --metadata '{"tenant_id":"acme"}'
tempus conformance --signer
# Next: install a policy (below). Until then the gate denies every action and
# `tempus doctor --json` reports `active_policy: FAIL`.
```

The gate signer configuration is the global `--keyfile` and defaults to `keys.json`.
Production deployments should use the non-secret Vault Transit configuration described
in [docs/VAULT_TRANSIT_SIGNER.md](docs/VAULT_TRANSIT_SIGNER.md); the workload authenticates
to Vault without placing a private key in the file.

## Install a signed policy bundle

**Default-deny.** A gate with no installed policy denies every action: the signed
receipt is `BLOCKED` with the reason code `POLICY_NOT_INSTALLED`. Nothing is seeded by
`tempus init`, by the first registration, or when the database is reopened, and a
tenant without its own policy is denied as well. Install a policy before expecting any
`ALLOWED` receipt.

Policies define allowed tenants, agents, actions, resources, rate ceilings, minor-unit
currency limits, and authorized executors.

Write a policy for your tenant, naming the executor identity you registered above (the
`public_key` field of `executor.keys.json`), then install it:

```bash
EXECUTOR_PUB=$(python -c "import json; print(json.load(open('executor.keys.json'))['public_key'])")
cat > acme-github-policy.json <<EOF
{
  "schema_version": "tempus.policy-bundle.v1",
  "policy_version": "acme-github-v1",
  "tenant_id": "acme",
  "constraints": {
    "allowed_action_types": ["github.create_issue", "github.create_pull_request"],
    "allowed_resources": ["acme/*"],
    "allowed_executors": ["$EXECUTOR_PUB"],
    "max_ttl_seconds": 60,
    "max_input_bytes": 16384,
    "allowed_currencies": ["USD"]
  }
}
EOF

tempus install-policy --policy acme-github-policy.json
tempus list-policies
```

The same template ships as `config/policy.github.example.json` in the source tree, with a
`REPLACE_WITH_EXECUTOR_ED25519_PUBLIC_KEY` placeholder that you must replace;
`install-policy` refuses a file that still contains a `REPLACE_WITH_` placeholder.

### Local development only: `--allow-all-dev`

To try the flow without writing a policy, opt in explicitly. This installs a signed
policy that **allows every action, resource and executor** for every tenant without its
own policy. The CLI prints a warning, `tempus doctor` reports `active_policy: FAIL`
while it is active, and every receipt carries the `tempus.dev-allow-all.v1.*`
`policy_version`. Never use it in production.

```bash
tempus init --allow-all-dev            # or, on an existing gate:
tempus install-policy --allow-all-dev
```

Equivalents: `TempusDDB.install_allow_all_dev_policy()` (Python, emits a `UserWarning`),
`SqliteStorage::install_allow_all_dev_policy()` and
`tempus-ddb-core install-allow-all-dev` (Rust). It is not exposed through MCP, so an
agent cannot switch the gate to allow-all. Installing a real policy for the same
tenant `*` later replaces it; a gate whose active `*` policy is not the dev one refuses
`--allow-all-dev` (`TEMPUS_DEV_ALLOW_ALL_REFUSED`).

Upgrading: a database seeded by an older gate still contains `tempus.baseline.v1`.
It is now ignored (the gate denies). Install a real policy, or opt in with
`--allow-all-dev` for development.

Policy evaluation is deterministic and rejects unknown constraints, floating-point input,
oversized input, tenant/resource/action mismatches, excessive TTL, disallowed executors,
and money metadata outside the configured currency or minor-unit ceiling.

## End-to-end from the CLI

The whole B2A cycle without Python, continuing from the policy installed above (tenant
`acme`, `agent.keys.json`, `executor.keys.json`). Run it in the directory where you ran
`tempus init`.

```bash
# 1. The agent's signed intent. `requested_at` is microseconds since the Unix epoch.
AGENT_PUB=$(python -c "import json; print(json.load(open('agent.keys.json'))['public_key'])")
cat > intent.json <<EOF
{
  "schema_version": "tempus.action-intent.v1",
  "tenant_id": "acme",
  "agent_id": "$AGENT_PUB",
  "idempotency_key": "issue-2026-001",
  "action_type": "github.create_issue",
  "resource": "acme/widgets",
  "requested_at": $(python -c "import time; print(time.time_ns() // 1000)"),
  "input": {"title": "Rotate the staging key", "body": "Opened through Tempus."}
}
EOF

# 2. request-action: the gate evaluates the policy and prints the permit
#    (`tempus.authorization-result.v1`, ALLOWED or a signed BLOCKED denial).
#    This file is the `permit.json` the packaged executors consume.
tempus request-action --intent intent.json --agent-keyfile agent.keys.json \
  --ttl-seconds 60 > permit.json
AUTH_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['authorization_id'])")
ACTION_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['action_id'])")
python -c "import json; print(json.load(open('permit.json'))['authorization']['decision'])"   # ALLOWED

# 3. The executor performs the effect (see "Packaged Mediated Executors"), then the
#    outcome it reports is committed to the gate, signed with the executor key.
#    Here the outcome is written by hand to keep the walkthrough offline.
cat > outcome.json <<EOF
{
  "schema_version": "tempus.action-outcome.v1",
  "authorization_id": "$AUTH_ID",
  "action_id": "$ACTION_ID",
  "status": "SUCCEEDED",
  "external_reference": "acme/widgets#17"
}
EOF
tempus commit-outcome --authorization-id "$AUTH_ID" --outcome outcome.json \
  --executor-keyfile executor.keys.json > execution.json

# 4. Verify against the gate public key you pinned out of band (no trust in the database)
GATE_PUB=$(python -c "import json; print(json.load(open('keys.json'))['public_key'])")
tempus trace --action-id "$ACTION_ID" > receipt.json
tempus verify-receipt --receipt receipt.json --gate-public-key "$GATE_PUB" \
  --require-decision ALLOWED --require-execution
tempus verify-trace --action-id "$ACTION_ID" --gate-public-key "$GATE_PUB" --strict \
  --require-decision ALLOWED --require-execution

# 5. One self-contained file for an auditor, verified with only that file and the key
tempus export-bundle --action-id "$ACTION_ID" --out evidence.json --create-checkpoint
tempus verify-bundle --bundle evidence.json --gate-public-key "$GATE_PUB" \
  --require-decision ALLOWED --require-execution --require-checkpoint
```

`request-action` signs the intent with `--agent-keyfile` before the gate sees it. A policy that does not allow the intent still produces a permit file,
with `"decision": "BLOCKED"` and reason codes; it is a signed denial and no executor will
act on it. See *Independent verification* below for what the verify commands do and do
not prove.

## Checkpoints & Disaster Recovery

Tempus allows generating cryptographically signed monotonic checkpoints and exporting hash-linked event streams without database downtime:

```bash
# 1. Create a signed monotonic checkpoint for a tenant
tempus checkpoint create --tenant-id acme --out checkpoint-acme.json

# 2. Export the incremental event stream
tempus checkpoint export --tenant-id acme --from-seq 1 --out stream-acme.json

# 3. Cryptographically verify stream integrity and rollback absence offline.
#    Pin the gate public key: without it the check is NOT independent.
tempus checkpoint verify --checkpoint checkpoint-acme.json --stream stream-acme.json \
    --gate-public-key <gate-public-key-hex|file>
```

See [docs/BACKUP_AND_DISASTER_RECOVERY.md](docs/BACKUP_AND_DISASTER_RECOVERY.md) for complete disaster recovery, hot backup, and reconciliation procedures.

## Python quickstart

```python
import json
import time
from tempus_ddb import TempusDDB, gen_keys

gen_keys("gate.keys.json")
gen_keys("agent.keys.json")
gen_keys("executor.keys.json")

gate = TempusDDB("tempus.db", "gate.keys.json")

with open("gate.keys.json", encoding="utf-8") as handle:
    gate_id = json.load(handle)["public_key"]
with open("agent.keys.json", encoding="utf-8") as handle:
    agent_id = json.load(handle)["public_key"]
with open("executor.keys.json", encoding="utf-8") as handle:
    executor_id = json.load(handle)["public_key"]

gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
gate.register_agent(agent_id, "purchasing-agent", "{}")
gate.register_agent(executor_id, "purchasing-executor", "{}")

# Default-deny: without an installed policy every request is BLOCKED
# (POLICY_NOT_INSTALLED). Install a signed policy for the tenant first.
gate.install_policy(json.dumps({
    "schema_version": "tempus.policy-bundle.v1",
    "policy_version": "acme-purchasing-v1",
    "tenant_id": "acme",
    "constraints": {
        "allowed_action_types": ["purchase"],
        "allowed_resources": ["vendor-api/*"],
        "allowed_executors": [executor_id],
        "max_ttl_seconds": 60,
        "max_input_bytes": 16384,
        "allowed_currencies": ["USD"],
        "max_money_amount_minor": 5000,
    },
}))
# Development shortcut only: gate.install_allow_all_dev_policy() allows everything.

intent = json.dumps({
    "schema_version": "tempus.action-intent.v1",
    "tenant_id": "acme",
    "agent_id": agent_id,
    "idempotency_key": "purchase-2026-07-16-001",
    "action_type": "purchase",
    "resource": "vendor-api/compute-credits",
    "requested_at": time.time_ns() // 1_000,
    "input": {"sku": "compute-credits"},
    "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"},
})

authorization = json.loads(gate.request_action(intent, "agent.keys.json", 60))
permit = authorization["authorization"]
assert permit["decision"] == "ALLOWED"

# The executor performs the external effect only after checking the permit.
outcome = json.dumps({
    "schema_version": "tempus.action-outcome.v1",
    "authorization_id": permit["authorization_id"],
    "action_id": permit["action_id"],
    "status": "SUCCEEDED",
    "external_reference": "vendor-tx-9182",
    "output": {"credits_added": 1000},
})

receipt = gate.commit_outcome(
    permit["authorization_id"],
    outcome,
    "executor.keys.json",
)
verification = json.loads(gate.verify_trace(permit["action_id"]))
assert verification["status"] == "VERIFIED"
assert verification["phase"] == "COMPLETED"
```

For remote transports, use `request_action_signed(...)` and
`commit_outcome_signed(...)`. The requesting agent and executor sign locally, so their
private keys and keyfiles never enter the gate process.

## 📚 Cookbooks & Framework Integrations

Explore practical integration recipes in the [cookbooks/](cookbooks/) directory:

- [🦜🔗 **LangChain & LangGraph Guard**](cookbooks/langchain_agent_guard.py) — Wrap sensitive tools (DB writes, payouts) so they run only with a signed, single-use permit.
- [👥 **CrewAI Multi-Agent Financial Gate**](cookbooks/crewai_action_gate.py) — Multi-agent delegation where executors require signed gate permits before executing effects.
- [🔌 **Claude Desktop & Cursor MCP Quickstart**](cookbooks/mcp_cursor_claude_quickstart.md) — Connect Tempus DDB as an autonomous Model Context Protocol server in 2 minutes.

```bash
# Run the LangChain guard recipe
python cookbooks/langchain_agent_guard.py

# Run the CrewAI financial gate recipe
python cookbooks/crewai_action_gate.py
```

## Demos and Scenarios

The repository includes runnable end-to-end demonstrations covering security guards, B2A flow, and tamper detection:
Examples create ephemeral databases and keys and remove them when they finish.

### 1. Commercial Demo (`examples/commercial_demo.py`)
Demonstrates the Phase 2 mediated-executor foundation and bypass prevention against a
simulated downstream API.
```bash
python examples/commercial_demo.py
```
**Key checks performed:**
- **Direct Bypass Attempt:** Rejected (agent lacks downstream API secret token).
- **Authorized Execution:** Agent signs intent &rarr; Tempus Gate validates &rarr; Mediated Executor verifies permit &rarr; API executed.
- **Replay Guard:** Re-using a consumed permit is rejected by the Executor.
- **Expiry Guard:** Expired permits are rejected.
- **Tamper Guard:** Altered permit fields invalidate the signature and are rejected.
- **Cross-Tenant Guard:** Permits issued for a different tenant ID are blocked.
- **Trace Verification:** Full cryptographic audit trace verification passes end-to-end.

### 2. Decision Chain Scenario (`examples/decision_chain.py`)
Simulates an autonomous bot lifecycle (Genesis &rarr; Decision 1 &rarr; Decision 2) with chain validation and JSON export:
```bash
python examples/decision_chain.py
```

### 3. CLI Tamper Detection (`examples/tamper_detection_cli.py`)
Demonstrates tamper detection using the Rust CLI by simulating unauthorized modifications to recorded traces:
```bash
python examples/tamper_detection_cli.py
```

### 4. Code Examples (`examples/`)
Additional standalone scripts in `examples/`:
- `examples/basic_record.py`: Basic decision recording.
- `examples/full_agent_flow.py`: Complete multi-agent authorization flow.
- `examples/verify_chain.py`: Cryptographic chain verification.

```bash
python examples/full_agent_flow.py
```

## Packaged Mediated Executors

Tempus includes four official, credential-isolated executors out of the box. The requesting AI agent *never* holds downstream API keys or secrets.

**Where `permit.json` comes from.** It is the output of `tempus request-action` (see
*End-to-end from the CLI*): `tempus request-action --intent intent.json --agent-keyfile
agent.keys.json > permit.json`. `--gate-id` is the gate's public key (the `public_key`
in the gate's `keys.json`, also printed by `tempus whoami`), `--tenant-id` must match the
permit's tenant, and `--executor-keyfile` must be the identity that the policy lists in
`allowed_executors`. The executor verifies the permit, consumes it once in its own
`--executor-db` (a second run of the same permit is refused), performs the action with the
credential only it holds, and prints its signed result. Reporting that outcome to the gate
(so it appears in the trace) is the separate `tempus commit-outcome` step, as the cookbooks
do. An expired permit (`--ttl-seconds`) or a `BLOCKED` one is rejected.

### 1. GitHub Executor (`tempus-github-executor`)
Performs audited GitHub REST writes with an isolated `GITHUB_TOKEN`:
- `github.create_issue`: `owner/repository` with allowlisted `title`, `body`, `labels`.
- `github.create_pull_request`: `owner/repository` with allowlisted `title`, `head`, `base`, `body`, `draft`.

```bash
tempus-github-executor \
  --permit permit.json \
  --executor-db github-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme
```

### 2. HTTP & Webhook Executor (`tempus-http-executor`)
Executes HTTPS POST/PUT webhooks and external API mutations while isolating authorization headers:
- Supported actions: `http.post`, `http.put`, `webhook.send`.

```bash
tempus-http-executor \
  --permit permit.json \
  --executor-db http-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --auth-header "Bearer <isolated-api-secret>"
```

### 3. Slack Executor (`tempus-slack-executor`)
Dispatches channel alerts and notifications while isolating `SLACK_BOT_TOKEN`:
- Supported actions: `slack.post_message`, `slack.send_alert`.

```bash
tempus-slack-executor \
  --permit permit.json \
  --executor-db slack-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --token "xoxb-<isolated-slack-bot-token>"
```

### 4. Pluggable Financial Adapter (`tempus-payment-executor`)
Reference pluggable executor that enforces the universal `money` envelope (`amount` or `amount_minor`, `asset` or `currency`, `beneficiary`; fields that disagree are refused) and minor-unit limits with credential isolation:
- Supported actions: `finance.disburse`, `finance.transfer`, `payment.charge`.
- **Bring Your Own Provider:** Implements a pluggable `PaymentTransport` interface. Shipped with a deterministic mock transport for verification and testing; plug in your real Stripe/Wise API client at the transport boundary without exposing payment keys to the AI agent.

```bash
tempus-payment-executor \
  --permit permit.json \
  --executor-db pay-executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <gate-public-key> \
  --tenant-id acme \
  --secret-key "sk_live_<isolated-payment-key>"
```

## Performance Benchmarks

Tempus DDB includes a benchmarking tool to evaluate transaction throughput and validation latency:

```bash
python examples/benchmark.py --records 1000
```

To output machine-readable JSON:
```bash
python examples/benchmark.py --records 1000 --json
```

**Optimizations active in v0.2.1+:**
- SQLite Write-Ahead Logging (`WAL` mode) with `PRAGMA synchronous = NORMAL` and `busy_timeout = 5000`.
- In-memory key caching to prevent disk I/O bottlenecks during hot-path transactions.
- Max LTO release compilation (`opt-level = 3`, `lto = true`, `codegen-units = 1`).

## Stable contracts

| Contract | Schema |
|---|---|
| Agent intent | `tempus.action-intent.v1` |
| Authorization response | `tempus.authorization-result.v1` |
| Signed permit | `tempus.authorization-receipt.v1` |
| Signed deterministic policy | `tempus.policy-bundle.v1` |
| Policy evidence | `tempus.policy-evidence.v1` |
| Identity lifecycle event | `tempus.identity-lifecycle-event.v1` |
| Executor outcome | `tempus.action-outcome.v1` |
| Execution response | `tempus.execution-result.v1` |
| Signed execution receipt | `tempus.execution-receipt.v1` |
| Executor state observation | `tempus.executor-observation.v1` |
| Complete trace | `tempus.action-trace.v1` |
| Verification result | `tempus.trace-verification.v1` |

Authorization decisions are `ALLOWED` or `BLOCKED`. Execution outcomes are `SUCCEEDED`
or `FAILED`. Executor observations are `STARTED`, `SUCCEEDED`, `FAILED`, or `UNKNOWN`.
Trace verification is `VERIFIED` or `INVALID`.

Phase 3 fields are additive to the v1 authorization contracts. Executors require and
verify them, while historical Phase 2 receipts keep their original signature semantics.
See [COMPATIBILITY.md](COMPATIBILITY.md) for support/deprecation rules and
[MIGRATION_0.4.md](MIGRATION_0.4.md) for the `0.3.x` upgrade procedure.

## MCP autonomous mode

The default MCP surface exposes only machine-to-machine execution and read-only audit
operations. The agent and executor must sign their own payloads; the gate never receives
their keyfile paths:

| Tool | Purpose |
|---|---|
| `tempus_request_action_signed` | Verify a locally signed intent and obtain a signed, expiring permit |
| `tempus_commit_outcome_signed` | Consume a permit with an executor-signed result |
| `tempus_get_trace` | Read authorization and execution evidence |
| `tempus_verify_trace` | Verify the complete action trace |
| `tempus_list_agents` | Read signed agent identities |
| `tempus_list_policies` | Read active and retired signed policy bundles |
| `tempus_list_identity_events` | Read signed rotation and revocation events |

Configuration:

```json
{
  "mcpServers": {
    "tempus": {
      "command": "tempus",
      "args": ["mcp", "start"],
      "env": {
        "TEMPUS_MODE": "autonomous",
        "TEMPUS_GATE_KEYFILE": "keys.json"
      }
    }
  }
}
```

Provisioning should run separately from the agent-facing MCP process. The following
flags are deliberately off by default:

| Flag | Unlocks |
|---|---|
| `TEMPUS_ADMIN_TOOLS=1` | init, key generation, signed agent registration, whoami |
| `TEMPUS_LEGACY_TOOLS=1` | old voluntary `record`, list, export, count, validate tools |
| `TEMPUS_DESTRUCTIVE_TOOLS=1` | demo-only cleanup |
| `TEMPUS_LOCAL_KEYFILE_TOOLS=1` | development-only `tempus_request_action` and `tempus_commit_outcome` tools that accept local keyfile paths |

## Human audit

Humans are readers, not approvers:

```bash
tempus trace --action-id <action-id>
tempus verify-trace --action-id <action-id> --gate-public-key <hex|file>
tempus list-agents
tempus list-policies
tempus identity-events
```

The public [trace demo](https://elbuilder77.github.io/tempus-ddb/trace.html) is a
synthetic, browser-only illustration of hashes, signatures and record binding. A future
read-only audit console must derive its views from these contracts; it is not in the
current source line.

## Independent verification (pinned gate key)

`verify-trace` without a key checks the database against **its own** root of trust, so a
completely forged database (attacker keys, fake payment) verifies against itself. The
output says so (`"trust": {"independent": false}` plus a warning). To verify
independently, pin the gate's public key, obtained out of band (the operator publishes
the output of `tempus whoami`), instead of trusting the database:

```bash
# Operator: publish the gate PUBLIC key (never the key file) and hand out receipts
tempus whoami                                   # prints the gate "Public Key"
tempus trace --action-id <action-id> > receipt.json

# Verifier: no database, no gate private key; the key is pinned by you
tempus verify-receipt --receipt receipt.json --gate-public-key <64-hex|file>
tempus verify-receipt --receipt receipt.json --gate-public-key <hex> \
    --executor-public-key <executor-hex>        # optionally pin the executor too
tempus verify-trace --action-id <id> --gate-public-key <hex> --strict
tempus checkpoint verify --checkpoint chk.json --stream stream.json --gate-public-key <hex>
```

`verify-receipt` takes a trace (`tempus.action-trace.v1`), a permit
(`tempus.authorization-result.v1`) or an outcome (`tempus.execution-result.v1`); `-` reads
stdin. Exit code `0` is VERIFIED, `2` is INVALID (tampered receipt, wrong key, or a
database signed by someone else) and `1` is a usage or I/O error (a missing or invalid
argument, an unreadable file, an empty key); the two never share a code. `--strict` refuses to run
without `--gate-public-key`. Python: `verify_receipt(json, gate_pub, executor_pubs=None)`,
`verify_checkpoint(chk, stream, gate_pub)` and `TempusDDB.verify_trace(id, gate_pub)`.

### Evidence bundle: one file, verified offline

```bash
# Operator: one file per action (add --create-checkpoint to sign a fresh checkpoint
# first so the bundle can show ledger inclusion)
tempus export-bundle --action-id <action-id> --out evidence.json --create-checkpoint

# Verifier: only the file and the pinned gate public key; no database, no private keys
tempus verify-bundle --bundle evidence.json --gate-public-key <64-hex|file> \
    [--executor-public-key <hex>]
```

The bundle (`tempus.evidence-bundle.v1`) holds the trace (intent, agent signature, permit,
signed policy used to reproduce the decision, outcome and signed receipts) and, if one
covers the action, the gate-signed checkpoint with the tenant's event stream. It contains no
private keys: every field is a public document or a hash. The verifier re-checks every
signature and hash against the pinned key, reproduces the decision from the signed policy,
and, with a checkpoint, checks that the permit and outcome events are in the signed ledger.
Same exit codes as above (0 VERIFIED, 2 INVALID, 1 usage). Python:
`TempusDDB.export_bundle(id)` and `verify_bundle(json, gate_pub, executor_pubs=None)`.

### What VERIFIED means, and how strict it is

- A document that repeats a JSON object key anywhere (`"amount":"9999.00","amount":"25.00"`)
  is `INVALID` (`DUPLICATE_JSON_KEY`): parsers disagree on which value wins. This check is
  made when *verifying* documents. It is **not** made by the gate when it receives an
  intent, outcome, policy or metadata (`parse_canonical`): there the last value of a repeated
  key wins, and what is signed holds only that value (through the CLI, Python's `json.loads`
  already collapses it before the gate sees it). So a repeated key cannot produce an
  ambiguous signed document, but the gate will not tell the sender that its input was
  ambiguous; do not generate JSON with repeated keys.
- Fields outside the schema at the top level of a bundle, in its `trace` or in its
  `checkpoint` wrapper are `INVALID` (`UNKNOWN_FIELD (<path>)`): they would be unsigned
  text travelling inside a verified file.
- A key file (`--gate-public-key FILE`) is the root of trust, so it is read strictly: bare
  hex, or a JSON object whose `public_key` / `gate_public_key` (one, or both with the same
  value) is a non-empty string. Repeated keys, an empty or non-string field, or two fields
  with different keys are usage errors (exit 1).
- Numbers in signed documents must be integers in the i64/u64 range. A float, or a larger
  integer, can be spelled several ways for one stored value (`0.1` / `1e-1`, `...567890` /
  `...567891`), so the gate refuses it when it arrives (`NON_EXACT_NUMBER`) and the
  verifiers report a document containing one as `INVALID`. Send decimals and large values as
  strings (`"amount": "25.00"`). The packaged executors convert such numbers in a
  downstream answer to strings before signing the outcome.
- `output_degraded` in the result tells you when the executor runtime could not represent
  the adapter's result in full (too large, too deep, cyclic, conversion error) and recorded
  a bounded summary under `_tempus_output_degraded` with the adapter's own status. It is
  `true` / `false`, or `null` when nothing verified; the CLI prints a NOTE on stderr. The
  marker is written by the executor: anyone holding the executor key can sign one by hand,
  so it is a visible signal, not proof of how the output was produced.
- `--gate-public-key` and `--executor-public-key` must not be empty: an empty value (for
  example an unset shell variable) is a usage error (exit 1), never "unpinned".
- `VERIFIED` alone does not say that the action was allowed or executed: a `BLOCKED`
  decision, a `FAILED` outcome, or a permit with no outcome or checkpoint all verify. The
  result shows `decision` and `execution_status` (both `null` unless the result is
  `VERIFIED`), and these flags turn an unmet expectation into exit 2 (`INVALID`,
  `REQUIREMENT_NOT_MET (...)`): `--require-decision ALLOWED|BLOCKED`,
  `--require-execution` (a verified outcome with status `SUCCEEDED`) and, on
  `verify-bundle`, `--require-checkpoint`. A script that only looks at the exit code should
  pass the ones that matter to it.

What a pinned verification (receipt or bundle) does **not** show; the result lists these in
`trust.not_checked`:

- **Completeness.** A bundle that leaves out the outcome is still a valid permit-only
  bundle (the verifier reports `phase: AUTHORIZED` or `EXPIRED`, `execution: NOT_PRESENT`).
  Nothing proves that other actions, retries or outcomes are not hidden from you.
- **Single use across the system.** Whether the permit was consumed only once is gate
  state; a document cannot prove it, even with a checkpoint.
- **Agent registration at issue time** and, unless you pin it, **the executor identity**:
  the pinned gate signature attests both.
- **Ledger inclusion without a checkpoint.** Only a bundle with a checkpoint shows the
  events are in the gate's signed ledger, and only as of that checkpoint's time. A gate
  that signs two diverging ledgers is not detected from one bundle.
- **Gate key compromise.** The guarantee is only as good as the secrecy of the gate key and
  the out-of-band way you obtained its public key.
- **Privacy.** The bundle includes the intent and outcome as recorded, and the checkpoint
  stream exposes ids, types, timestamps and hashes (not contents) of every event of that
  tenant up to the checkpoint. Streams over `--max-stream-events` (default 10000) are
  omitted, not truncated.

### Common cases that now break, and how to fix them

Since signed documents may only hold integers in the i64/u64 range as numbers, code written
for earlier versions can hit `NON_EXACT_NUMBER` (the message names the path, for example
`$.requested_at`). The usual causes:

| What you send | Result | Fix |
| --- | --- | --- |
| `requested_at` from `time.time()` (a float, seconds) | `NON_EXACT_NUMBER ... $.requested_at` | An integer in microseconds: `time.time_ns() // 1000` |
| `money.amount` as a number (`25.5`) | `NON_EXACT_NUMBER ... $.money.amount`; an integer (`25`) gives `money.amount must be a decimal string` | A string with at most two decimals: `"25.50"` (or an integer `amount_minor` in minor units; if you send both, or both `currency` and `asset`, they must agree or the intent is refused with `TEMPUS_INVALID_CONTRACT`) |
| A float in `input` (`{"price": 19.99}`) | `NON_EXACT_NUMBER ... $.input.price` (it used to produce a signed `BLOCKED`) | A string (`"19.99"`) or an integer in minor units (`1999`) |
| A decimal in agent `metadata`, a policy or an outcome `output` | `NON_EXACT_NUMBER` at its path | A string (`"0.5"`); policy limits such as `max_money_amount_minor` are already integers |
| `NaN`, `Infinity`, `1e400` or `-0` from the CLI | `NON_EXACT_NUMBER` | Send a string, or write `0` for `-0` |

Custom executors do not need to convert their results: the packaged runtime records floats,
huge integers, `Decimal` and `datetime` as strings, and a result it cannot represent in a
degraded form (with the adapter's own status) instead of recording `FAILED`. An exception
the adapter itself raises is still recorded as `FAILED` (or `UNKNOWN` for ambiguous
transport errors): the runtime cannot know whether the effect happened. Bundles signed by older
versions that contain a float verify as `INVALID` (`AUTHORIZATION_NON_EXACT_NUMBER` /
`EXECUTION_NON_EXACT_NUMBER`) even if untouched.

## Legacy ledger

The original `record`, `validate`, `list`, `count`, and `export` interfaces remain for
compatibility and migration. They are a voluntary flight recorder and do not enforce
the B2A toll. New autonomous integrations should use the signed action authorization
flow; local keyfile MCP tools are development compatibility only.

**The legacy ledger is not verifiable evidence.** It does not apply the exact-number rule
of the gate (floats and integers beyond 64 bits are accepted by `tempus record`), and its
hash is computed over the *parsed* payload, so `tempus verify` still reports a ledger as
valid after a number in a stored payload is edited to another spelling of the same f64
(`1e2` -> `100.0`, `...567890` -> `...567891` for a 30-digit integer). Do not present a
legacy ledger to an auditor as proof; use the signed flow (`verify-receipt`,
`export-bundle` / `verify-bundle`) for that.

## Security boundary

This implementation detects receipt, policy, evidence, and trace alteration; rejects
unregistered or revoked actors; prevents conflicting idempotent requests; and prevents
two outcomes from consuming one permit. It does not yet prevent deletion or rollback of
the entire local database, nor bypass by an agent that still possesses downstream
credentials. Read [THREAT_MODEL.md](THREAT_MODEL.md)
before using Tempus for high-impact production actions.

## Roadmap

The next release line focuses on large-ledger streaming, durable receipt events,
independent rollback detection, and operating procedures. See [ROADMAP.md](ROADMAP.md)
for milestones and explicit exit criteria.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, security reporting, and pull-request
requirements. The complete local verification set is:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
ruff check .
pytest -p no:cacheprovider
python -m maturin build
```

## License

MIT. See [LICENSE](LICENSE).
