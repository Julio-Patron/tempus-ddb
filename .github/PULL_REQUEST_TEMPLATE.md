## Summary

Describe what changed and the user-visible outcome.

## Motivation

Explain the problem and link the issue with `Fixes #<number>` when applicable.

## Security and compatibility impact

- Trust boundary affected:
- Signed contract affected:
- Migration required:
- New failure mode or operational dependency:

Write `None` where appropriate. Security-sensitive changes must include an adversarial
regression test and any required threat-model update.

## Validation

List the exact commands and relevant manual checks performed.

## Checklist

- [ ] The change is focused and contains no generated artifacts or secrets.
- [ ] Rust format, Clippy, and tests pass where applicable.
- [ ] Ruff and pytest pass where applicable.
- [ ] New behavior has positive and negative test coverage.
- [ ] Unknown or unsupported states are still rejected or denied (never allowed).
- [ ] Public contracts and migration impact were reviewed.
- [ ] Documentation and `CHANGELOG.md` were updated when needed.
