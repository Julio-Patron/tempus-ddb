# Migrating from 0.3.x to 0.4.0

Version `0.4.0` adds policy and identity lifecycle state through forward-only SQLite
migrations. Back up the gate and executor databases before upgrading, then rehearse the
upgrade on copies.

1. Upgrade the gate, every mediated executor, and the Python/MCP clients together.
   Phase 3 permits contain required policy bindings that a `0.3.x` executor does not
   enforce.
2. Start the gate once to apply the new tables and identity metadata columns. Existing
   signed registrations are backfilled with their public key as the stable identity ID.
3. Install a tenant policy based on `config/policy.github.example.json`. Without an
   installed policy the gate denies every action (`POLICY_NOT_INSTALLED`). Earlier
   0.4.x/0.5.x builds seeded an allow-all `tempus.baseline.v1` policy on first use; that
   baseline is no longer created and one left in an existing database is ignored. For
   local evaluation only, opt in explicitly with `tempus install-policy --allow-all-dev`.
4. Run `tempus doctor --json` and `tempus conformance --signer` before enabling effects.
5. Rotate development keyfiles or configure Vault Transit for production workloads, then
   verify an end-to-end trace in the target environment.

Historical `0.3.x` receipts using `tempus.identity-gate.v1` remain trace-verifiable with
their original Ed25519 signature. They are verification-only after the upgrade: an old,
unconsumed permit without an embedded signed policy bundle is rejected by a `0.4.x`
executor. This intentional tightening prevents execution under policy evidence that
cannot be reproduced.

The v1 schema names do not change; Phase 3 fields are additive. See `COMPATIBILITY.md`
for the support window and `CHANGELOG.md` for the full behavior delta.
