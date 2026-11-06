//! Phase 11: static guarantees for the Windows acceptance scripts.
//!
//! The PowerShell scripts under `scripts/` are run by the project owner on
//! the disposable VM; the developers never executed them. This test keeps
//! them within the Phase 11 boundary: no script may write the registry,
//! change policy, devices, drivers, ACLs or services, and only the MSI
//! script (behind a typed confirmation on a detected VM) may run msiexec.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn scripts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts")
}

fn powershell_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![scripts_dir()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read scripts dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "ps1" || e == "psm1") {
                let text = std::fs::read_to_string(&path).expect("read script");
                let name = path
                    .strip_prefix(scripts_dir())
                    .expect("under scripts")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((name, text));
            }
        }
    }
    out.sort();
    out
}

/// Commands that change Windows. Matched case-insensitively.
const FORBIDDEN: &[&str] = &[
    "reg add",
    "reg delete",
    "reg import",
    "reg load",
    "reg unload",
    "reg restore",
    "reg copy",
    "set-itemproperty",
    "new-itemproperty",
    "remove-itemproperty",
    "rename-itemproperty",
    "hklm:\\software\\policies\\microsoft\\windows\\deviceinstall\\restrictions\" -force",
    "set-acl",
    "icacls",
    "takeown",
    "pnputil",
    "devcon",
    "disable-pnpdevice",
    "enable-pnpdevice",
    "gpupdate",
    "secedit",
    "lgpo",
    "bcdedit",
    "sc.exe create",
    "sc.exe config",
    "sc.exe delete",
    "sc.exe failure",
    "sc.exe sdset",
    "sc.exe start",
    "sc.exe stop",
    "start-service",
    "stop-service",
    "restart-service",
    "set-service",
    "new-service",
    "remove-service",
    "new-eventlog",
    "remove-eventlog",
    "wevtutil im",
    "wevtutil um",
    "wevtutil cl",
    "diskpart",
    "format-volume",
    "clear-disk",
    "set-disk",
    "initialize-disk",
    "mountvol",
    "dismount-",
    "manage-bde",
    "rundll32",
];

#[test]
fn scripts_exist_and_are_scanned() {
    let names: Vec<String> = powershell_files().into_iter().map(|(n, _)| n).collect();
    for expected in [
        "run-native-validation.ps1",
        "check-prereqs.ps1",
        "build-release.ps1",
        "windows/RustWardAcceptance.psm1",
        "windows/Invoke-StageB-DeviceInspection.ps1",
        "windows/Invoke-StageC-ServiceInspection.ps1",
        "windows/Invoke-StageE-PolicyInspection.ps1",
        "windows/Invoke-AcceptanceMsi.ps1",
        "windows/Build-RustWard.ps1",
    ] {
        assert!(names.iter().any(|n| n == expected), "missing {expected}");
    }
}

#[test]
fn no_script_changes_windows_configuration() {
    for (name, text) in powershell_files() {
        let lower = text.to_lowercase();
        for f in FORBIDDEN {
            assert!(
                !lower.contains(f),
                "{name} contains forbidden command `{f}`"
            );
        }
    }
}

#[test]
fn only_the_msi_script_runs_msiexec_and_it_requires_confirmation() {
    for (name, text) in powershell_files() {
        let runs_msiexec = text.to_lowercase().contains("msiexec.exe");
        if name == "windows/Invoke-AcceptanceMsi.ps1" {
            assert!(runs_msiexec);
            assert!(
                text.contains("Assert-RwTestMachine -DisposableVm:$DisposableVm -SystemChange")
            );
            // The guard runs before the evidence folder or msiexec.
            let guard = text.find("-SystemChange").expect("guard");
            assert!(guard < text.find("Initialize-RwEvidence").expect("evidence"));
            assert!(guard < text.find("Start-Process").expect("msiexec"));
            assert!(text.contains("SHA256SUMS.txt"), "D1 hash check");
        } else {
            assert!(!runs_msiexec, "{name} must not run msiexec");
        }
    }
}

#[test]
fn stage_scripts_require_an_authorized_test_machine() {
    for (name, text) in powershell_files() {
        if name.starts_with("windows/Invoke-") {
            assert!(
                text.contains("Assert-RwTestMachine"),
                "{name} has no machine guard"
            );
            assert!(
                text.contains("NOT YET EXECUTED on Windows"),
                "{name} must state that it was never executed"
            );
        }
    }
    let module = powershell_files()
        .into_iter()
        .find(|(n, _)| n == "windows/RustWardAcceptance.psm1")
        .expect("module")
        .1;
    // System changes only on a detected VM, with the computer name typed.
    assert!(module.contains("if ($SystemChange) {"));
    assert!(module.contains("-not $kind.IsVirtual"));
    assert!(module.contains("$typed -cne $env:COMPUTERNAME"));
}

#[test]
fn stage_e_compares_the_policy_key_before_and_after() {
    let (_, text) = powershell_files()
        .into_iter()
        .find(|(n, _)| n == "windows/Invoke-StageE-PolicyInspection.ps1")
        .expect("stage E");
    let before = text
        .find("Export-RwPolicy 'deviceinstall-before'")
        .expect("before");
    let capture = text.find("policy-capture --out").expect("capture");
    let after = text
        .find("Export-RwPolicy 'deviceinstall-after'")
        .expect("after");
    assert!(before < capture && capture < after);
    assert!(text.contains("E10 RESULT: PASS"));
    assert!(text.contains("E10 RESULT: FAIL"));
}

#[test]
fn build_script_builds_without_installing_or_elevating() {
    let (_, text) = powershell_files()
        .into_iter()
        .find(|(n, _)| n == "windows/Build-RustWard.ps1")
        .expect("build script");
    // UTF-8 BOM: Windows PowerShell 5.1 reads the Turkish messages correctly.
    assert!(
        text.starts_with('\u{feff}'),
        "Build-RustWard.ps1 needs a UTF-8 BOM"
    );
    let lower = text.to_lowercase();
    for f in [
        "runas",
        "-verb runas",
        "winget",
        "choco ",
        "msiexec",
        "rustup-init.exe -y",
        "invoke-webrequest",
        "start-bitstransfer",
    ] {
        assert!(
            !lower.contains(f),
            "build script must not install or elevate: `{f}`"
        );
    }
    assert!(text.contains("npx tauri build --no-bundle"));
    assert!(text.contains("npx tauri build --debug --no-bundle --features gui-subsystem"));
    assert!(
        text.contains("Test-PeX64"),
        "outputs are verified before copying"
    );
    assert!(
        text.contains("Test-MessageTable"),
        "the service must carry its Event Log message table"
    );
    assert!(
        text.contains("tauri.acceptance.conf.json"),
        "the MSI includes the service fragment"
    );
    // The MSI is only read (Windows Installer database, mode 0), never installed.
    assert!(text.contains("@($MsiPath, 0)"));
    let launcher =
        std::fs::read_to_string(scripts_dir().join("../BUILD-RUSTWARD.cmd")).expect("launcher");
    assert!(launcher.contains("scripts\\windows\\Build-RustWard.ps1"));
    assert!(launcher.is_ascii(), "cmd launcher stays ASCII");
    assert!(
        launcher.contains("exit /b %RW_EXIT%"),
        "nonzero exit code is passed on"
    );
}
