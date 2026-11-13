//! Captures build-time version metadata for `AboutInfoView` offline without network access.

use std::process::Command;

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTWARD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=RUSTWARD_BUILD_TIMESTAMP");

    if let Ok(head_path) = std::fs::canonicalize("../../.git/HEAD") {
        println!("cargo:rerun-if-changed={}", head_path.display());
    }

    let sha = std::env::var("RUSTWARD_GIT_SHA")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| git_output(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned());

    let timestamp = std::env::var("RUSTWARD_BUILD_TIMESTAMP")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| git_output(&["show", "-s", "--format=%cI", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=RUSTWARD_GIT_SHA={sha}");
    println!("cargo:rustc-env=RUSTWARD_BUILD_TIMESTAMP={timestamp}");
}
