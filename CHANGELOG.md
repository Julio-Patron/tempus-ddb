# Changelog

## [Unreleased]

### Documentation
- Legacy ledger (`tempus record` / `tempus verify`, `TEMPUS_LEGACY_TOOLS=1`) is documented
  as **not verifiable evidence**: it accepts floats and huge integers and hashes the parsed
  value, so an edited copy (`1e2` -> `100.0`, `...890` -> `...891`) still validates. Decision:
  document rather than apply the exact-number rule there (see README, "Legacy ledger"):
  it is a voluntary flight recorder, enforcing the rule in `verify` would invalidate
  existing ledgers, and enforcing it only in `record` would leave old records and `verify`
  unchanged. Evidence belongs in the signed B2A flow.
- README: a complete, runnable CLI walkthrough (policy, `request-action`, `commit-outcome`,
  `verify-receipt` / `verify-trace --strict`, `export-bundle` / `verify-bundle`), where the
  executors' `permit.json` comes from, what `VERIFIED` does and does not mean, and install
  from the clone until a release includes default-deny and independent verification (PyPI
  0.5.3 does not). Fixed the demo link that lacked `https://`.

### Security: verifier hardening (independent forge findings)
- **Duplicate JSON keys are INVALID.** `serde_json` kept the last value of a repeated key
  (`"amount":"9999.00","amount":"25.00"` verified), so a document could verify while a
  first-wins parser or a human read something else. `verify-receipt`, `verify-bundle`,
  `verify-trace` (stored documents) and `checkpoint verify` now reject a repeated object
  key at any depth: status `INVALID`, error / reason code `DUPLICATE_JSON_KEY`, exit 2.
- **Unknown fields are INVALID.** An unsigned extra field (`"note":"approved by CFO"`) at
  the top level of a bundle, in the `trace` wrapper or in the bundle's `checkpoint` wrapper
  verified; the other levels already rejected them. These wrappers now allow only their
  schema fields: anything else yields `INVALID` with `UNKNOWN_FIELD (<path>)`.
- **An empty `--gate-public-key` is a usage error.** `verify-trace --gate-public-key ""`
  and `checkpoint verify --gate-public-key ""` (typically an unset `$GATE_KEY`) silently
  fell back to the unpinned, non-independent mode and exited 0. An empty or whitespace-only
  `--gate-public-key` / `--executor-public-key` now exits 1 on every verifier; only
  omitting the option means "not pinned". In Python an empty string already raised;
  `verify_trace(id, None)` remains the documented unpinned mode.
- **Key files are parsed strictly.** A `--gate-public-key` / `--executor-public-key` FILE
  holding JSON used the last of any repeated key and fell through from an empty `public_key`
  to `gate_public_key` (`{"public_key":"","gate_public_key":ATTACKER}` pinned the attacker's
  key). A repeated key, a candidate field (`public_key`, `gate_public_key`) that is empty or
  not a string, a non-object document, or two candidate fields with different keys is now a
  usage error (exit 1). Files with one key, or both fields holding the same key, work as
  before, including a gate `keys.json` (only its public part is read).
- **Signed documents hold only exact numbers.** `serde_json` reads every float, and every
  integer outside i64/u64, as an f64. The gate rounded such numbers before signing (an
  outcome `output` of `123456789012345678901234567890` was signed as `1.2345678901234568e29`)
  and the verifier accepted any text with the same f64 (`...567891`, `...567000`, `...890.0`;
  `0.1` as `0.10` or `1e-1`). Now only integers in the i64/u64 range are allowed as numbers
  in anything the gate signs or verifies:
  - The gate refuses them when they arrive (`NON_EXACT_NUMBER: ... at $.path`, exit 1 on the
    CLI): outcomes (`commit-outcome`, executor `complete_execution`), intents, agent
    metadata and policies. Decimals and larger values must be strings (`"25.00"`,
    `"123456789012345678901234567890"` are unaffected).
  - `verify-receipt`, `verify-bundle`, `verify-trace` and `checkpoint verify` report such a
    document as `INVALID` (`AUTHORIZATION_NON_EXACT_NUMBER` / `EXECUTION_NON_EXACT_NUMBER
    (path)`, or reason code `NON_EXACT_NUMBER`), including bundles signed before this change.
  - Behaviour change: an intent whose `input` holds a float used to produce a signed `BLOCKED`
    (`POLICY_NON_DETERMINISTIC_INPUT`); it is now refused before anything is signed.
  - The packaged executors (`ExecutorRuntime`) keep working with downstream answers that
    contain floats or huge integers: the payload is converted (`0.1` -> `"0.1"`, a 30-digit
    integer -> its exact digits) before the outcome is signed. The conversion is applied to
    the value Python already parsed, so a float spelled `19.990` is recorded as `"19.99"`.
  - **A custom adapter never loses the effect to its own result type.** `Decimal` is
    recorded as its exact string (`Decimal("19.990")` -> `"19.990"`), `datetime`/`date`/`time`
    as ISO 8601, and bytes, sets or arbitrary objects as a bounded `repr` (512 characters).
    A result that cannot be converted at all (nesting beyond 64 levels, cycles) is recorded
    with the adapter's own status and the marker
    `{"_tempus_output_degraded": true, "reason": ..., "repr": <bounded>}`. Before, such a
    result made the runtime record `FAILED` (`EXECUTION_EXCEPTION`) although the external
    action had happened. Criterion: an adapter result is evidence about an effect that
    already occurred; degrading its representation is acceptable, recording a failure for a
    success is not.
- **VERIFIED now says what was decided and executed.** Results of `verify-receipt`,
  `verify-trace` and `verify-bundle` carry `decision` (`ALLOWED`/`BLOCKED`) and
  `execution_status` (`SUCCEEDED`/`FAILED`, `null` when there is no outcome); both are
  `null` unless the whole result verifies. New flags make the exit code mean more than
  "the signatures are fine": `--require-execution` (a verified outcome with status
  `SUCCEEDED`), `--require-decision ALLOWED|BLOCKED` and, on `verify-bundle`,
  `--require-checkpoint` (a checkpoint that verifies and includes the permit and outcome).
  An unmet requirement exits 2 with status `INVALID` and `REQUIREMENT_NOT_MET (...)`.
  Without the flags a BLOCKED bundle, a FAILED outcome or a bundle with no execution or
  checkpoint still verifies, as before.
- **Usage errors exit 1, INVALID exits 2.** `argparse` exits 2 on a missing or invalid
  argument, the same code as `INVALID`, so a script could not tell a typo from a forged
  receipt. Every `tempus` usage error (missing required argument, unknown option or
  command, bad `--require-decision` value) now exits 1; `--help` still exits 0. Breaking
  for callers that treated exit 2 from a missing argument as usage.

### Security: executors no longer follow redirects
- The HTTP, GitHub and Slack executor transports used `urllib.request.urlopen`, which
  follows 3xx responses and forwards the `Authorization` header to the new host. They now
  share one opener (`tempus_ddb._http`) that refuses every redirect: the request is not
  repeated, credentials are not forwarded, and the executor reports a failed outcome
  (`http_status` / `GITHUB_HTTP_<code>` / `error`) whose message names only the status code
  and the redirect target host (no `Location` path, query or credentials). Not covered by
  this change: DNS or IP based SSRF filtering (the allowlist is by host name) and the
  behaviour of custom transports passed in by an integrator.

### Security / Breaking
- **Default-deny.** The gate no longer seeds the allow-all `tempus.baseline.v1` (`"*"`)
  policy on `init`, first agent registration or first use, and tenants without their own
  policy no longer fall back to it. With no installed policy the gate issues a signed
  `BLOCKED` receipt with reason code `POLICY_NOT_INSTALLED` (verifiable by `verify-trace`;
  such a receipt can never verify as `ALLOWED`). A baseline already present in an older
  database is ignored.
- **Opt-in development mode.** `tempus init --allow-all-dev`, `tempus install-policy
  --allow-all-dev`, `TempusDDB.install_allow_all_dev_policy()` (Python, `UserWarning`) and
  `SqliteStorage::install_allow_all_dev_policy()` / `tempus-ddb-core install-allow-all-dev`
  (Rust) install a signed allow-all policy, versioned `tempus.dev-allow-all.v1.<ts>`. It is
  not exposed over MCP. `tempus doctor` fails `active_policy` while only it is active.
- Migration: install a real policy, or opt in with `--allow-all-dev` for development.

### Added: independent verification
- **Pinned gate key.** `tempus verify-trace --gate-public-key HEX|FILE [--executor-public-key ...]
  [--strict]` verifies a trace against a gate public key supplied by the verifier. A database
  signed by anyone else (a fully forged DB with the attacker's own gate, agent and executor
  keys) is `INVALID` (`GATE_KEY_NOT_PINNED`); before, it verified against its own root of trust.
- **`tempus verify-receipt`** verifies a standalone trace, permit or outcome JSON with no
  database. **`tempus checkpoint verify --gate-public-key`** needs only the public key (no
  keyfile, no database). Python: `verify_receipt`, `verify_checkpoint`,
  `TempusDDB.verify_trace(id, gate_public_key=None, executor_public_keys=None)`; Rust:
  `verify_receipt`, `verify_checkpoint`, `SqliteStorage::verify_trace_pinned`,
  `tempus-ddb-core verify-receipt`.
- **Evidence bundle** (`tempus.evidence-bundle.v1`): `tempus export-bundle --action-id ID --out
  FILE [--create-checkpoint] [--max-stream-events N] [--force]` writes one JSON file with the
  trace, signed policy and, if one covers the action, the latest signed checkpoint with its
  event stream; no private keys. `tempus verify-bundle --bundle FILE --gate-public-key HEX|FILE
  [--executor-public-key ...]` verifies it with no database (exit 0 VERIFIED, 2 INVALID, 1
  usage), including that the permit and outcome events are in the checkpointed ledger. Python:
  `TempusDDB.export_bundle`, `verify_bundle`; Rust: `SqliteStorage::export_bundle`,
  `verify_bundle`, `tempus-ddb-core export-bundle|verify-bundle`. Limits (completeness,
  global single use, gate-key compromise, privacy) are documented in the README.
- Trace verification now also rejects a trace whose unsigned `action_id` wrapper differs from
  the signed one (`TRACE_ACTION_ID_MISMATCH`).
- Verification results now carry a `kind` and a `trust` object (`PINNED_GATE_KEY`, independent,
  with `not_checked`; or `DATABASE_SELF_ATTESTED`, `"independent": false`). Without a pinned
  key the CLI prints a "NOT INDEPENDENT" warning; `--strict` refuses to run unpinned.

## [0.5.3] - 2026-09-26

First published build of the 0.5.2 security line. The `v0.5.2` release workflow
failed before building any artifact, so **0.5.2 was never published to PyPI or
crates.io**; 0.5.3 ships the same runtime code with a repaired release pipeline.

### Fixed
- **Release pipeline**: Four action pins in `release.yml` pointed to commit SHAs that do not exist upstream (`PyO3/maturin-action`, `actions/download-artifact`, `actions/attest-build-provenance`, `actions/attest-sbom`), which aborted the `v0.5.2` release at job setup. All pins now resolve to real tags (maturin-action v1.51.0, download-artifact v7.0.0, attest-build-provenance v2.4.0, attest-sbom v2.4.0).
- **Tag-exact builds**: Every release checkout now uses the release tag as `ref`, so manual re-runs build the tagged source instead of the dispatching branch.
- **Wheel test gate**: The pre-publish wheel tests imported the uncompiled `python/tempus_ddb` source (via pytest `pythonpath` and `tests/test_cli.py`) instead of the installed wheel, so they could never pass. The gate now removes the source package first and tests only the built wheel.
- **PyPI publishing**: Removed the unused `PYPI_API_TOKEN` password input; publication relies on Trusted Publishing (OIDC) only, as documented.
- **crates.io publishing**: The workflow read a `CRATES_IO_TOKEN` secret that was never configured, so the crate was silently skipped. It now uses `CARGO_API_TOKEN` in a separate job that cannot block the PyPI release.

### Changed
- Packaged sources no longer include the `launch/` marketing drafts removed after the `v0.5.2` tag.
- `python-dotenv` minimum raised to `>=1.2.3` (Dependabot #29).

## [0.5.2] - 2026-09-12 (not published)

### Security
- **Delegation Chain & Trusted Root Verification (Finding 1)**: Added `trusted_roots` table with single-root constraint; enforce recursive delegation chain checks ensuring all registered identities trace to an established root.
- **Signed Policy Activation & Strict Fallback (Finding 2)**: Added `active_policy_attestations` table storing cryptographic attestations over active policies; retired tenant policies fail closed instead of falling back to unconstrained wildcards; SSRF protection and destination domain allowlisting in `http_executor`.
- **Segregation of Duties & Role Enforcement (Finding 3)**: Prohibit proposing agents from executing their own permits (`executor_id != agent_id`); reject proposer roles from executor duty; enforce executor tenant scope matching.
- **Durability & Replay Defense Across Gate/Executor (Findings 4 & 6)**: Upgraded SQLite persistence to `PRAGMA synchronous = FULL;` across gate and executors; executors cross-verify revocation and consumption state against Gate DB before effectuating actions.
- **Financial Policy Beneficiary Validation (Finding 5)**: Enforce `allowed_beneficiaries` pattern matching in both policy evaluation and payment execution.
- **Untrusted Signer Rejection in Checkpoint Verification (Finding 7)**: Checkpoint stream verifier requires trusted public key and rejects checkpoints signed by arbitrary keys (`ERR_UNTRUSTED_SIGNER`).
- **Atomic State and Stream Mutations (Finding 8)**: Wrapped policy installations, authorizations, and outcome commits in immediate atomic SQLite transactions to eliminate race conditions between mutation and audit event logging.
- **Workflow Hardening (Finding 9)**: Pinned all GitHub Actions to immutable commit SHAs; added automated wheel testing and `cargo test` gates prior to release publication.
- **Windows CP1252 Compatibility**: Replaced all console and comment non-ASCII symbols with clean ASCII characters to prevent encoding crashes on Windows consoles.

## [0.5.0] - 2026-09-05

### Added
- **Append-Only Event Stream (`tempus.event-stream-event.v1`)**: Monotonically sequenced, hash-linked (`prev_event_hash` ➔ `event_digest`) event recording for all authorizations, outcomes, agent registrations, and policy installations.
- **Signed Monotonic Checkpoints (`tempus.checkpoint.v1`)**: Gate-signed external checkpoints binding cumulative SHA-256 stream root hashes and sequence windows (`first_sequence`..`last_sequence`).
- **Cryptographic Stream Verifier (`tempus.checkpoint-verification.v1`)**: Offline mathematical verification engine detecting rollback attacks (`ERR_ROLLBACK_DETECTED`), sequence gaps (`ERR_SEQUENCE_GAP`), broken chain linkage (`ERR_CHAIN_LINKAGE_BROKEN`), and single-byte tampering (`ERR_EVENT_TAMPERED`).
- **Unified Mediated Executor Runtime (`ExecutorRuntime`)**: Standardized base runtime with protocol `ActionAdapter` and conformance testing harness (`AdapterConformanceHarness` in `tempus_ddb.testing`).
- **CLI Checkpoint & DR Commands**: Added `tempus checkpoint create`, `tempus checkpoint export`, and `tempus checkpoint verify`.
- **Disaster Recovery Guide**: Published comprehensive procedures in `docs/BACKUP_AND_DISASTER_RECOVERY.md`.

## [0.4.2] - 2026-08-31

### Changed
- **Pluggable Financial Transport**: Clarified `tempus-payment-executor` and `PaymentExecutorAdapter` architecture as a pluggable reference adapter with `MockPaymentTransport` for CI/testing and `PaymentTransport` protocol for custom production payment gateways (Stripe, Wise, banking APIs).
- **Security Policy Badge**: Replaced unverified audit badge with `security-policy` badge linking to `SECURITY.md`.
- **Documentation & Install Synchronization**: Synchronized install guidance across README, PyPI metadata, and GitHub Pages emphasizing Sigstore provenance attestations and OIDC Trusted Publishing.

## [0.4.1] - 2026-08-31

### Added
- **Packaged Mediated Executors**: Added `tempus-http-executor` (generic HTTPS POST/PUT webhooks with isolated headers), `tempus-slack-executor` (isolated `SLACK_BOT_TOKEN`), and `tempus-payment-executor` (binding the universal `money` contract envelope and isolating payout secrets).
- **Cookbooks & Framework Integrations**: Added copy-paste recipes for **LangChain/LangGraph** tool guarding, **CrewAI** multi-agent financial delegation, and **Claude Desktop & Cursor MCP** autonomous setup.
- **Architectural Differentiation**: Added explicit technical comparison between Tempus DDB B2A zero-trust cryptographic toll and traditional RBAC/MCP proxies (Bifrost, Obot, MCPX, MintMCP).
- Exported `HttpExecutorAdapter`, `SlackExecutorAdapter`, and `PaymentExecutorAdapter` in the Python package root.

## [0.4.0] - 2026-08-27

### Fixed

- Kept the Rust quality gate compatible with current stable Clippy.
- Validate GitHub executor endpoints as absolute HTTPS URLs before an outbound request;
  malformed, credential-bearing, query-bearing, and plaintext endpoints fail closed.
- Restored standards-compliant Python package metadata by keeping `keywords` in the
  project metadata rather than treating it as an install extra.

### Changed

- Reused a bounded, configurable SQLite connection pool in the mediated executor instead
  of opening a new connection for every state transition.
- Added a recovery index and concurrent replay regression coverage proving that only one
  contender can consume a permit.
- Moved runnable demonstrations and the benchmark into `examples/` so the repository
  root contains only project configuration and public documentation.
- Updated repository, security, discussion, ownership, and SBOM links for
  `elbuilder77/tempus-ddb`.

### Phase 3

- A provider-neutral Rust signer boundary and verification-key resolver with compatible
  local Ed25519 and Vault Transit CLI backends. Signer URI, key version, and algorithm are
  bound into signed artifacts; unknown providers, algorithms, versions, and malformed
  responses fail closed.
- Signed deterministic policy bundles covering tenant, action type, resource, input size,
  optional money constraints, TTL, and allowed executors. Permits now bind the policy
  digest, reproducible evidence digest, executor constraints, and complete reason codes.
- Tenant-scoped identity delegation plus signed rotation and revocation events. Historical
  receipts resolve the key valid at signing time, while emergency revocation invalidates
  unconsumed permits.
- `tempus doctor`, policy and identity lifecycle commands, signer conformance checks, and
  a machine-readable adapter conformance fixture.
- SPDX 2.3 SBOM generation and GitHub artifact provenance/SBOM attestations in the release
  workflow, plus a compatibility policy and Vault Transit operating guide.
- Package maturity advances to design-partner beta (`0.4.0`). Existing v1 schema names
  remain compatible; the Phase 3 binding fields are additive and enforced by executors.

Live credentialed Vault and GitHub checks remain explicit opt-in tests; an integration
that was not run is never reported as passing.

### Added

- First complete local B2A authorization flow: signed action intent, gate permit,
  executor outcome, final receipt, trace reading, and end-to-end verification.
- Stable versioned JSON contracts and closed machine statuses for autonomous consumers.
- Signed, immutable agent registration events with a gate delegation root.
- Deterministic action idempotency, expiring permits, and single-consumption outcomes.
- Rust, Python, CLI, and MCP B2A surfaces plus replay/tamper/authorization tests.
- Public protocol boundary and production-oriented threat-model documentation.
- Signed MCP authorization and outcome tools for clients that keep agent and executor
  private keys outside the gate process.
- Signed executor observations for `STARTED`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`, plus
  restart recovery that never replays an ambiguous external effect.
- Packaged `tempus-github-executor` for exactly bound GitHub issue and pull-request
  creation with an executor-only credential.
- A public product roadmap with ordered Phase 3 trust and adoption milestones.
- Dependabot coverage for Cargo, Python, and GitHub Actions dependencies.

### Changed

- MCP defaults to the autonomous execution-gate surface. Administrative, legacy, and
  destructive tools now require explicit environment flags.
- Product positioning now treats money as optional action metadata and humans as
  read-only auditors rather than transaction approvers.
- Default MCP mode now exposes only signed B2A write tools. The compatibility tools
  that receive local keyfile paths require `TEMPUS_LOCAL_KEYFILE_TOOLS=1`.
- Phase 2 is complete for the single-instance GitHub adapter, including policy-version
  checks, exact argument binding, credential isolation, and crash recovery.
- Package metadata now reflects the actual Python 3.10+ MCP dependency and alpha status.
- The Python package exports its installed version and the GitHub executor derives its
  user-agent version from package metadata.
- Tests and runnable examples use self-cleaning temporary workspaces instead of leaving
  databases and generated keys in the repository root.

### Security

- Agent registrations can no longer be silently replaced.
- The gate signing key is server-controlled for MCP authorization requests.
- Unregistered agents are blocked before execution and conflicting permit reuse is
  rejected.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-06-26

### Changed
- Updated examples to the current free core API.
- Added smoke-test coverage for runnable example scripts.
- Stabilized release readiness for the free/open-core packaging and CI path.

## [0.2.0] - 2026-06-26

### Added
- Comprehensive CLI improvements: `tempus record`, `tempus status`, `tempus --version`
- Expanded test coverage with Python API tests and CLI integration tests
- Multiple end-to-end examples in `examples/`
- GitHub Actions CI workflow for multi-OS/Python testing
- Module docstrings and improved Python API documentation

### Changed
- Removed license gate entirely from Rust core and Python bindings for true free/open nature
- Simplified `TempusDDB` constructor to `TempusDDB(db_path, keyfile)`
- Updated positioning to emphasize "free, local-first, tamper-evident"
- Improved error handling and UX across CLI

### Fixed
- License generation to properly support direct CLI usage
- Constructor calls in tests and examples

## [0.1.0] - Previous

Initial public version with core Rust engine, MCP integration, and basic CLI.
