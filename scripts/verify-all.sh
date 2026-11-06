#!/usr/bin/env bash
# Run every automated check that does NOT need Windows or USB hardware.
# Read-only for the system: builds into ./target and the app's dist/ only.
#
# Passing this script proves nothing about Windows behaviour or USB enforcement.
# Native Windows and hardware tests are DEFERRED (docs/TEST-RESULTS.md).
set -uo pipefail
cd "$(dirname "$0")/.."

declare -a RESULTS=()
fail=0
run() {
  local name=$1; shift
  echo "== $name"
  if "$@"; then RESULTS+=("PASS     $name"); else RESULTS+=("FAIL     $name"); fail=1; fi
}
skip() { RESULTS+=("NOT RUN  $1 ($2)"); }

run "cargo fmt --check"                cargo fmt --all -- --check
run "cargo clippy (default features)"  cargo clippy --workspace --all-targets --locked -- -D warnings
run "cargo clippy (all features)"      cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run "cargo test (all features)"        cargo test --workspace --all-features --locked
run "cargo test ui-bridge (release)"   cargo test -p rustward-ui-bridge --release --features dev-backend --locked

if [ -d apps/rustward-desktop/node_modules ]; then
  run "tsc typecheck"   bash -c "cd apps/rustward-desktop && npx tsc -b --noEmit"
  run "vitest"          bash -c "cd apps/rustward-desktop && npx vitest run"
  run "vite build"      bash -c "cd apps/rustward-desktop && npx vite build"
  run "offline assets (no runtime network)" node scripts/check-offline-assets.mjs
  run "build real-backend harness" cargo build -p rustward-ui-bridge --features dev-backend --example stdio_backend --locked
  run "tsc typecheck (integration tests)" bash -c "cd apps/rustward-desktop && npx tsc -p tsconfig.integration.json --noEmit"
  run "vitest integration (real backend + SQLite)" bash -c "cd apps/rustward-desktop && RUSTWARD_STDIO_BACKEND=\$PWD/../../target/debug/examples/stdio_backend npx vitest run --config vitest.integration.config.ts"
else
  skip "frontend checks" "run npm ci in apps/rustward-desktop first"
fi

if pkg-config --exists webkit2gtk-4.1 2>/dev/null && [ -d apps/rustward-desktop/dist ]; then
  run "src-tauri fmt"    bash -c "cd apps/rustward-desktop/src-tauri && cargo fmt -- --check"
  run "src-tauri clippy" bash -c "cd apps/rustward-desktop/src-tauri && cargo clippy --all-targets --locked -- -D warnings"
  run "src-tauri tests (mock runtime IPC)" bash -c "cd apps/rustward-desktop/src-tauri && cargo test --locked"
else
  skip "src-tauri checks" "needs webkit2gtk-4.1 dev libraries and a built dist/"
fi

if command -v cargo-deny >/dev/null 2>&1; then
  run "cargo deny (workspace, windows target)"   cargo deny check
  run "cargo deny (src-tauri, windows target)"   cargo deny --manifest-path apps/rustward-desktop/src-tauri/Cargo.toml check
else
  skip "cargo deny" "cargo install cargo-deny --locked"
fi

skip "Windows build / MSI bundling"      "requires Windows 10 Pro x64 acceptance VM"
skip "named-pipe + service runtime tests" "requires Windows"
skip "native SetupAPI inventory"          "requires Windows"
skip "physical USB tests"                 "requires hardware on the acceptance VM"

echo
printf '%s\n' "${RESULTS[@]}"
exit $fail
