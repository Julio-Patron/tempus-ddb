#!/usr/bin/env bash
# Build the browser verifier: the wasm32 build of this crate plus wasm-bindgen glue,
# written to site/assets/wasm/ (committed, so the site deploys without a Rust toolchain).
#
# Requires: rustup target add wasm32-unknown-unknown
#           cargo install wasm-bindgen-cli --version <same as Cargo.lock's wasm-bindgen>
set -euo pipefail
cd "$(dirname "$0")/.."

WANTED="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p')"
HAVE="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$WANTED" != "$HAVE" ]; then
  echo "wasm-bindgen-cli $HAVE does not match Cargo.lock ($WANTED): cargo install wasm-bindgen-cli --version $WANTED --force" >&2
  exit 1
fi

cargo build --release --lib --target wasm32-unknown-unknown
rm -rf site/assets/wasm
wasm-bindgen --target web --no-typescript \
  --out-dir site/assets/wasm --out-name tempus_verifier \
  target/wasm32-unknown-unknown/release/_tempus_ddb.wasm
ls -l site/assets/wasm
