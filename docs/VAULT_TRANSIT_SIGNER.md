# Vault Transit signer

Tempus can use HashiCorp Vault Transit as an Ed25519 signer through the installed `vault`
CLI. Tempus never reads or receives the private key. The same provider boundary is used
by the gate and `TempusExecutor`, so either process may use this configuration.

## Prerequisites

1. Enable a Transit mount and create an `ed25519` key.
2. Give the workload only `update` permission on `transit/sign/<key>` and permission to
   discover its own authenticated state. Do not grant key export or delete rights.
3. Authenticate the workload with the platform's Vault mechanism (Kubernetes, OIDC,
   AppRole delivered by an agent, or another short-lived method). Do not put a Vault token
   or private key in the Tempus signer file.
4. Copy `config/vault-transit.signer.example.json`, set the signer URI, public key, and
   current key version, then restrict the file to the workload account.

The URI format is `vault-transit://<mount>/<key>`. The public key is 32-byte Ed25519 in
lowercase hexadecimal. `key_version` must match the `vN` returned by Vault; a mismatch is
rejected.

## Preflight and operation

```console
tempus --keyfile vault.signer.json --db tempus.db conformance --signer
tempus --keyfile vault.signer.json --db tempus.db doctor --json
```

Each signing call has a bounded timeout and one to three attempts. A timeout, CLI error,
unexpected key version, malformed response, or signature that does not verify against the
configured public key aborts the operation: no receipt is issued. Tempus passes only the non-secret message digest or
canonical receipt bytes to the CLI and does not print the Vault credential.

Vault's audit device should be enabled before production use. Correlate its signing path
and timestamp with the Tempus authorization or execution receipt. Test the integration
only when explicit Vault credentials are present; ordinary tests use offline local signer
fixtures.
