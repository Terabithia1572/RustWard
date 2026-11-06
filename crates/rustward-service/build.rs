//! Embeds the Event Log message table into `rustward-service.exe`.
//!
//! The table is generated from `rustward_windows::eventlog_map` (single
//! source of truth for event IDs) and compiled with `embed-resource` when the
//! target is Windows. The installer registers the executable as the
//! `EventMessageFile` of the `RustWard` source so Event Viewer can format
//! entries. On other hosts the table is still generated (so the generator is
//! exercised) but nothing is linked. **NOT VERIFIED ON WINDOWS.**

use std::path::PathBuf;

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../rustward-windows/src/eventlog_map.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR not set")?);
    let bin = out.join("rustward-messages.bin");
    std::fs::write(
        &bin,
        rustward_windows::eventlog_map::message_table_resource(),
    )
    .map_err(|e| format!("write {}: {e}", bin.display()))?;
    // rc string literal: absolute path with escaped backslashes.
    let escaped = bin.display().to_string().replace('\\', "\\\\");
    let rc = out.join("rustward-messages.rc");
    std::fs::write(
        &rc,
        rustward_windows::eventlog_map::message_table_rc(&escaped),
    )
    .map_err(|e| format!("write {}: {e}", rc.display()))?;
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed(&rc)?;
    }
    Ok(())
}

#[cfg(windows)]
fn embed(rc: &std::path::Path) -> Result<(), String> {
    embed_resource::compile(rc, embed_resource::NONE)
        .manifest_optional()
        .map_err(|e| format!("embedding the Event Log message table failed: {e}"))
}

#[cfg(not(windows))]
fn embed(_rc: &std::path::Path) -> Result<(), String> {
    Err(
        "cross-compiling rustward-service for Windows from a non-Windows host is not supported: \
         build it natively so the Event Log message table is embedded"
            .into(),
    )
}
