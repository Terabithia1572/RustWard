#!/usr/bin/env bash
# Phase 11: compile RustWard for the Windows target ON LINUX.
#
# THIS IS NOT A NATIVE WINDOWS BUILD. It compiles every cfg(windows) code path
# (SetupAPI, policy reader, named pipes, SCM host, Event Log, native tests)
# against the real windows-sys bindings for x86_64-pc-windows-gnu with MinGW,
# links the executables and test binaries, and checks their import tables.
# Nothing is executed. MSVC, rc.exe, WebView2, the MSI and every runtime
# behaviour still need Stage A on Windows.
#
# Requirements: rustc with matching library sources (rust-src, or
#   RUSTWARD_RUST_SRC=/path/to/rust checkout at `rustc -vV` commit-hash),
#   x86_64-w64-mingw32-gcc, RUSTC_BOOTSTRAP for -Zbuild-std (the target's
#   prebuilt std is not needed).
#
# The service's build.rs deliberately refuses to cross-compile (the release
# exe must embed the Event Log MESSAGETABLE with rc.exe). This script copies
# the working tree to a temporary directory and disables only that embedding
# step IN THE COPY. The repository is never modified, and the resulting
# executables are check artifacts: never ship them.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
TARGET=x86_64-pc-windows-gnu
WORK=${RUSTWARD_WINDOWS_CHECK_DIR:-$(mktemp -d)}
OUT=${CARGO_TARGET_DIR_WINDOWS:-$WORK/target}

command -v x86_64-w64-mingw32-gcc >/dev/null || { echo "missing x86_64-w64-mingw32-gcc (apt install mingw-w64)"; exit 2; }
SYSROOT=$(rustc --print sysroot)
if [ ! -d "$SYSROOT/lib/rustlib/src/rust/library/std" ]; then
  echo "missing rust-src for $(rustc -V); set it up from a rust checkout at commit $(rustc -vV | sed -n 's/commit-hash: //p')"
  exit 2
fi

echo "== copying working tree to $WORK/src (repository untouched)"
rm -rf "$WORK/src" && mkdir -p "$WORK/src"
tar -C "$REPO" --exclude=target --exclude=node_modules --exclude=.git -cf - . | tar -C "$WORK/src" -xf -
BUILD_RS="$WORK/src/crates/rustward-service/build.rs"
grep -q '^        embed(&rc)?;$' "$BUILD_RS" || { echo "build.rs changed; update this script"; exit 2; }
sed -i 's|^        embed(&rc)?;$|        let _ = embed; // windows-target-check copy only: no rc.exe on Linux|' "$BUILD_RS"

export RUSTC_BOOTSTRAP=1
export CARGO_TARGET_DIR=$OUT
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
BS="-Zbuild-std=std,panic_abort,panic_unwind"
cd "$WORK/src"

echo "== clippy (Windows target, default features)"
cargo clippy $BS --target $TARGET --workspace --all-targets --locked -- -D warnings
echo "== clippy (Windows target, all features)"
cargo clippy $BS --target $TARGET --workspace --all-targets --all-features --locked -- -D warnings
echo "== clippy (Windows target, release, libraries and binaries)"
cargo clippy -Zbuild-std=std,panic_abort --target $TARGET --release --workspace --lib --bins --locked -- -D warnings
echo "== link all test binaries (not run)"
cargo test $BS --target $TARGET --workspace --no-run --locked
echo "== release executables"
cargo build -Zbuild-std=std,panic_abort --target $TARGET --release --locked -p rustward-service -p rustward-inventory

if [ "${RUSTWARD_WINDOWS_CHECK_TAURI:-0}" = "1" ]; then
  # Needs apps/rustward-desktop/dist (vite build) for tauri::generate_context!.
  echo "== Tauri shell clippy (Windows target; WebView2 code compiled, not run)"
  [ -d "$REPO/apps/rustward-desktop/dist" ] && cp -r "$REPO/apps/rustward-desktop/dist" apps/rustward-desktop/
  (cd apps/rustward-desktop/src-tauri && cargo clippy $BS --target $TARGET --all-targets --locked -- -D warnings)
fi

echo "== import tables: no registry writes, device/driver changes or service configuration"
fail=0
for exe in rustward-service.exe rustward-inventory.exe; do
  imports=$(x86_64-w64-mingw32-objdump -p "$OUT/$TARGET/release/$exe" |
    awk '/DLL Name:/{dll=tolower($3)} /^\t[0-9a-f]+\t +[0-9]+ +[A-Za-z_]/{print dll" "$NF}' | sort -u)
  bad=$(grep -E ' (Reg(Set|Create|Delete|Save|Restore|Load|Replace|Flush|Copy|Rename)[A-Za-z]*|CM_(Disable|Uninstall|Set_|Reenumerate|Query_And_Remove|Setup)[A-Za-z_]*|SetupDi(Remove|Uninstall|SetDevice|CallClass|ChangeState|SetClassInstall|InstallDevice|RegisterDevice)[A-Za-z]*|DeviceIoControl|CreateService[AW]|ChangeServiceConfig[A-Za-z0-9]*|DeleteService|ControlService[A-Za-z]*|OpenSCManager[AW]|DefineDosDevice[AW]|SetVolumeMountPoint[AW]|DeleteVolumeMountPoint[AW])$' <<<"$imports" || true)
  reg=$(grep -E ' Reg[A-Z]' <<<"$imports" | awk '{print $2}' | tr '\n' ' ')
  echo "$exe: $(wc -l <<<"$imports") imports; registry functions: ${reg:-none}"
  if [ -n "$bad" ]; then echo "FORBIDDEN IMPORTS in $exe:"; echo "$bad"; fail=1; fi
done
[ $fail -eq 0 ] && echo "import check OK"
echo "NOT A NATIVE WINDOWS BUILD: nothing above was executed on Windows."
exit $fail
