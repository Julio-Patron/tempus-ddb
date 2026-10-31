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

# rustc embeds source paths (panic locations) in the binary, including the absolute
# path of this checkout and of the cargo registry under the builder's home directory.
# Remap them so the published artifact names no local user or machine. Both the POSIX
# and the native spelling are remapped: under Git Bash on Windows rustc sees the
# drive-letter form while the shell sees /c/Users/...
HOME_DIR="${HOME:-$(cd ~ && pwd)}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME_DIR/.cargo}"
REMAP="--remap-path-prefix=$PWD=/tempus-ddb --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$HOME_DIR=/home"
if command -v cygpath >/dev/null 2>&1; then
  REMAP="$REMAP --remap-path-prefix=$(cygpath -w "$PWD")=/tempus-ddb --remap-path-prefix=$(cygpath -w "$CARGO_HOME_DIR")=/cargo --remap-path-prefix=$(cygpath -w "$HOME_DIR")=/home"
fi
RUSTFLAGS="${RUSTFLAGS:-} $REMAP" cargo build --release --lib --target wasm32-unknown-unknown

# Refuse to publish a binary that still names the builder's home directory.
HOME_LEAF="$(basename "$HOME_DIR")"
if grep -a -q -F "$HOME_LEAF" target/wasm32-unknown-unknown/release/_tempus_ddb.wasm; then
  echo "the wasm binary still contains '$HOME_LEAF' (a local path); fix the remap before publishing" >&2
  exit 1
fi

rm -rf site/assets/wasm
wasm-bindgen --target web --no-typescript \
  --out-dir site/assets/wasm --out-name tempus_verifier \
  target/wasm32-unknown-unknown/release/_tempus_ddb.wasm
ls -l site/assets/wasm
