#!/usr/bin/env bash
# Prepare every build input for an OFFLINE build machine.
# Run on a CONNECTED machine from the repository root. Changes nothing outside
# the repository: writes ./vendor (Rust crates), ./.npm-offline-cache (npm
# tarballs) and ./.cargo-offline/config.toml (source replacement).
#
# Then copy the whole repository to the offline build machine and build with:
#   cargo build --release --locked --offline --config .cargo-offline/config.toml -p rustward-service
#   (cd apps/rustward-desktop && npm ci --offline --cache ../../.npm-offline-cache)
#   (cd apps/rustward-desktop/src-tauri && cargo build --release --locked --offline --config ../../../.cargo-offline/config.toml)
set -euo pipefail
cd "$(dirname "$0")/.."
PWD_ROOT=$(pwd)

echo "== Rust: vendoring workspace + Tauri shell (locked versions) =="
mkdir -p .cargo-offline
cargo vendor --locked --versioned-dirs \
  --sync apps/rustward-desktop/src-tauri/Cargo.toml \
  vendor > .cargo-offline/config.toml.tmp
# Relative paths in a --config file resolve against the parent of the
# directory holding it (here: the repository root), so "vendor" is correct.
cp .cargo-offline/config.toml.tmp .cargo-offline/config.toml
rm .cargo-offline/config.toml.tmp

echo "== npm: populating offline cache from package-lock.json =="
# Native helper packages (esbuild, rollup, Tailwind oxide, lightningcss) are
# per-platform optional dependencies, so the cache must also contain the
# win32-x64 variants used on the Windows build machine. Install into a scratch
# prefix so the developer's node_modules is untouched.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
for target in "" "--os=win32 --cpu=x64"; do
  rm -rf "$scratch"/*
  cp apps/rustward-desktop/package.json apps/rustward-desktop/package-lock.json "$scratch"/
  # shellcheck disable=SC2086
  (cd "$scratch" && npm ci --ignore-scripts --cache "$PWD_ROOT/.npm-offline-cache" --prefer-online $target >/dev/null)
done

echo "== Inventory =="
crates=$(find vendor -mindepth 1 -maxdepth 1 -type d | wc -l)
echo "vendored crates: ${crates}"
du -sh vendor .npm-offline-cache | sed 's/^/size: /'
echo "Done. Nothing was installed or registered."
