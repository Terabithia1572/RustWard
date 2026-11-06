//! `rustward-inventory` — read-only diagnostics.
//!
//! Nothing in this tool changes device, driver, registry or policy state.
//! The only files it writes are the ones named by `--out` / `--out-dir`.
//! Every decision it prints is labelled SIMULATED and every report states
//! "ENFORCEMENT: NOT ACTIVE"; the output types offer no way to say "blocked".

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use rustward_core::catalog::{CatalogError, ValidatedCatalog};
use rustward_core::device::DeviceSnapshot;
use rustward_core::plan::compile_plan;
use rustward_core::policy::{PolicyError, ValidatedPolicy};
use rustward_core::report::{build_report, render_markdown};
use rustward_enforcement::policy_inspect::{CapturedPolicy, PolicyInspection, inspect};
use rustward_enforcement::{
    DeviceInstallRestrictionProvider, EnforcementProvider, EnvironmentFacts, PlanInputs,
    SimulationOnlyProvider,
};
use rustward_windows::{EnumerationScope, collect_inventory};

const DEFAULT_CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const DEFAULT_POLICY: &str = include_str!("../../../config/policy.example.json");

const BANNER: &str = "RustWard inventory - ENFORCEMENT: NOT ACTIVE. Read-only; nothing on this system is changed or blocked.";

const USAGE: &str = "\
Usage:
  rustward-inventory scan     [--include-non-present] [--sanitize] [--json] [--catalog FILE] [--policy FILE]
  rustward-inventory evaluate --snapshot FILE [--sanitize] [--json] [--catalog FILE] [--policy FILE]
  rustward-inventory capture  --out FILE [--include-non-present]
  rustward-inventory report   (--snapshot FILE | --live [--include-non-present]) --out-dir DIR
                              [--catalog FILE] [--policy FILE]
  rustward-inventory plan     (--snapshot FILE | --live) [--catalog FILE] [--policy FILE]
  rustward-inventory policy-capture --out FILE
  rustward-inventory policy-inspect (--policy-capture FILE | --live) [--snapshot FILE] [--json]
                              [--catalog FILE] [--policy FILE]

All commands are read-only. Live commands require Windows.
'policy-capture' reads HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions
(KEY_READ only) and OS version facts into FILE. 'policy-inspect' interprets a capture: documented,
unresolved and unrecognised values, OS compatibility and, with a device snapshot, conflicts with the
RustWard plan. Nothing is ever written.
'report' writes diagnostic-raw.{md,json} (keep local) and diagnostic-sanitized.{md,json}
(serials pseudonymized, computer name removed) into DIR.
Without --catalog/--policy the built-in Phase 1 catalog and the PC-01 example policy are used.";

#[derive(Debug, Default)]
struct Args {
    command: String,
    include_non_present: bool,
    json: bool,
    live: bool,
    sanitize: bool,
    catalog: Option<String>,
    policy: Option<String>,
    snapshot: Option<String>,
    out: Option<String>,
    policy_capture: Option<String>,
    out_dir: Option<String>,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        command: it.next().ok_or("missing command")?,
        ..Args::default()
    };
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--include-non-present" => a.include_non_present = true,
            "--json" => a.json = true,
            "--live" => a.live = true,
            "--sanitize" => a.sanitize = true,
            "--catalog" => a.catalog = Some(value("--catalog")?),
            "--policy" => a.policy = Some(value("--policy")?),
            "--snapshot" => a.snapshot = Some(value("--snapshot")?),
            "--out" => a.out = Some(value("--out")?),
            "--out-dir" => a.out_dir = Some(value("--out-dir")?),
            "--policy-capture" => a.policy_capture = Some(value("--policy-capture")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(a)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn write(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn load_rules(a: &Args) -> Result<(ValidatedCatalog, ValidatedPolicy), String> {
    let catalog_json = a.catalog.as_deref().map(read).transpose()?;
    let policy_json = a.policy.as_deref().map(read).transpose()?;
    let catalog = ValidatedCatalog::from_json(catalog_json.as_deref().unwrap_or(DEFAULT_CATALOG))
        .map_err(|e| match e {
        CatalogError::Invalid(issues) => format!(
            "catalog rejected: {}",
            serde_json::to_string_pretty(&issues).unwrap_or_default()
        ),
        other => other.to_string(),
    })?;
    let policy =
        ValidatedPolicy::from_json(policy_json.as_deref().unwrap_or(DEFAULT_POLICY), &catalog)
            .map_err(|e| match e {
                PolicyError::Invalid(issues) => format!(
                    "policy rejected: {}",
                    serde_json::to_string_pretty(&issues).unwrap_or_default()
                ),
                other => other.to_string(),
            })?;
    Ok((catalog, policy))
}

fn scope(a: &Args) -> EnumerationScope {
    if a.include_non_present {
        EnumerationScope::IncludeNonPresent
    } else {
        EnumerationScope::PresentOnly
    }
}

fn live_snapshot(a: &Args) -> Result<(DeviceSnapshot, Vec<String>), String> {
    let inv = collect_inventory(scope(a)).map_err(|e| e.to_string())?;
    Ok((inv.snapshot, inv.warnings))
}

fn snapshot_from_args(a: &Args) -> Result<(DeviceSnapshot, Vec<String>), String> {
    match (&a.snapshot, a.live) {
        (Some(p), false) => Ok((
            DeviceSnapshot::from_json(&read(p)?).map_err(|e| e.to_string())?,
            Vec::new(),
        )),
        (None, true) => live_snapshot(a),
        _ => Err("exactly one of --snapshot FILE or --live is required".into()),
    }
}

fn print_report(snapshot: &DeviceSnapshot, warnings: &[String], a: &Args) -> Result<(), String> {
    let (catalog, policy) = load_rules(a)?;
    let report = build_report(snapshot, warnings, &policy, &catalog, a.sanitize);
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("{BANNER}");
        println!(
            "Protection state: {}\n",
            SimulationOnlyProvider.status().label_tr()
        );
        print!("{}", render_markdown(&report));
    }
    Ok(())
}

fn write_reports(a: &Args) -> Result<(), String> {
    let dir = Path::new(a.out_dir.as_deref().ok_or("report needs --out-dir DIR")?);
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let (catalog, policy) = load_rules(a)?;
    let (snapshot, warnings) = snapshot_from_args(a)?;
    if a.live {
        write(
            &dir.join("snapshot-raw.json"),
            &serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?,
        )?;
    }
    for (sanitize, stem) in [(false, "diagnostic-raw"), (true, "diagnostic-sanitized")] {
        let r = build_report(&snapshot, &warnings, &policy, &catalog, sanitize);
        write(&dir.join(format!("{stem}.md")), &render_markdown(&r))?;
        write(
            &dir.join(format!("{stem}.json")),
            &serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?,
        )?;
    }
    eprintln!(
        "wrote diagnostic-raw.* (KEEP LOCAL) and diagnostic-sanitized.* to {}",
        dir.display()
    );
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn load_capture(a: &Args) -> Result<CapturedPolicy, String> {
    match (&a.policy_capture, a.live) {
        (Some(p), false) => serde_json::from_str(&read(p)?).map_err(|e| format!("{p}: {e}")),
        (None, true) => rustward_windows::capture_device_install_policy(now_ms()),
        _ => Err("exactly one of --policy-capture FILE or --live is required".into()),
    }
}

fn policy_inspect(a: &Args) -> Result<(), String> {
    let captured = load_capture(a)?;
    let plan = match &a.snapshot {
        Some(p) => {
            let (catalog, policy) = load_rules(a)?;
            let snap = DeviceSnapshot::from_json(&read(p)?).map_err(|e| e.to_string())?;
            let env = EnvironmentFacts::default();
            Some(DeviceInstallRestrictionProvider.plan(PlanInputs {
                policy: &policy,
                catalog: &catalog,
                snapshot: &snap,
                env: &env,
            }))
        }
        None => None,
    };
    let inspection = inspect(&captured, plan.as_ref());
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection).map_err(|e| e.to_string())?
        );
    } else {
        println!("{BANNER}");
        print!("{}", render_inspection(&inspection));
    }
    Ok(())
}

/// Human-readable inspection summary.
fn render_inspection(i: &PolicyInspection) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let flag = |f: &rustward_enforcement::policy_inspect::FlagView| {
        f.value
            .map_or_else(|| "not set".to_owned(), |v| v.to_string())
    };
    let _ = writeln!(
        o,
        "# Device Installation Restrictions (read-only inspection)\n"
    );
    let _ = writeln!(o, "Key present: {}", i.key_present);
    let _ = writeln!(
        o,
        "OS: build {:?}, UBR {:?} (undocumented source), product type {:?}, edition supported: {:?}",
        i.os.build, i.os.ubr, i.os.product_type, i.edition_supported
    );
    let _ = writeln!(o, "Layered evaluation support: {:?}", i.layering);
    let _ = writeln!(o, "AllowDenyLayered: {} (documented)", flag(&i.layered));
    let _ = writeln!(
        o,
        "DenyUnspecified: {} (documented)\n",
        flag(&i.deny_unspecified)
    );
    let _ = writeln!(
        o,
        "| List | Kind | Layer | Enabled | Entries | Entry layout |"
    );
    let _ = writeln!(o, "|---|---|---|---|---|---|");
    for l in &i.lists {
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} | {} | {:?} |",
            l.name,
            if l.allow { "allow" } else { "prevent" },
            l.layer,
            l.enabled.map_or_else(|| "-".into(), |v| v.to_string()),
            l.entries.len(),
            l.layout_status
        );
    }
    let _ = writeln!(o);
    for f in &i.retroactive {
        let _ = writeln!(o, "{}: {} (name unresolved)", f.name, flag(f));
    }
    let _ = writeln!(
        o,
        "\nUnrecognised values (not interpreted): {}",
        i.unrecognised.len()
    );
    for (r, d) in &i.unrecognised {
        let _ = writeln!(o, "  {}\\{} = {:?}", r.key, r.name, d);
    }
    if let Some(p) = &i.plan_presence {
        let _ = writeln!(
            o,
            "\nRustWard plan values on this machine: {p:?} (policy state only, NOT verified protection)"
        );
    }
    let _ = writeln!(o, "Conflicts with the RustWard plan: {}", i.conflicts.len());
    for c in &i.conflicts {
        let _ = writeln!(o, "  - {c:?}");
    }
    for e in &i.read_errors {
        let _ = writeln!(o, "  ! {e}");
    }
    o
}

fn run(a: &Args) -> Result<(), String> {
    match a.command.as_str() {
        "scan" => {
            let (snap, warnings) = live_snapshot(a)?;
            print_report(&snap, &warnings, a)
        }
        "evaluate" => {
            let path = a
                .snapshot
                .as_deref()
                .ok_or("evaluate needs --snapshot FILE")?;
            let snap = DeviceSnapshot::from_json(&read(path)?).map_err(|e| e.to_string())?;
            print_report(&snap, &[], a)
        }
        "capture" => {
            let out = a.out.as_deref().ok_or("capture needs --out FILE")?;
            let (snap, warnings) = live_snapshot(a)?;
            let s = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
            write(Path::new(out), &s)?;
            eprintln!(
                "wrote {} device records to {out} (raw: contains serial numbers, keep local)",
                snap.devices.len()
            );
            for w in warnings {
                eprintln!("  ! {w}");
            }
            Ok(())
        }
        "report" => write_reports(a),
        "plan" => {
            let (catalog, policy) = load_rules(a)?;
            let (snap, _) = snapshot_from_args(a)?;
            println!("{BANNER}");
            println!("PLAN PREVIEW - status NOT APPLIED. RustWard Phase 1 cannot apply it.");
            let plan = compile_plan(&policy, &catalog, Some(&snap));
            println!(
                "{}",
                serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "policy-capture" => {
            let out = a.out.as_deref().ok_or("policy-capture needs --out FILE")?;
            let captured = rustward_windows::capture_device_install_policy(now_ms())?;
            write(
                Path::new(out),
                &serde_json::to_string_pretty(&captured).map_err(|e| e.to_string())?,
            )?;
            eprintln!(
                "wrote {} policy value(s) to {out} (key present: {}; read problems: {})",
                captured.values.values.len(),
                captured.key_present,
                captured.read_errors.len()
            );
            Ok(())
        }
        "policy-inspect" => policy_inspect(a),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn parses_flags_and_rejects_unknown() {
        let a = args(&[
            "report",
            "--snapshot",
            "x.json",
            "--out-dir",
            "d",
            "--sanitize",
        ])
        .unwrap();
        assert_eq!(a.command, "report");
        assert_eq!(a.snapshot.as_deref(), Some("x.json"));
        assert_eq!(a.out_dir.as_deref(), Some("d"));
        assert!(a.sanitize);
        assert!(args(&["scan", "--force"]).is_err());
        assert!(args(&["scan", "--catalog"]).is_err());
        assert!(args(&[]).is_err());
    }

    #[test]
    fn built_in_rules_load() {
        assert!(load_rules(&args(&["scan"]).unwrap()).is_ok());
    }

    #[test]
    fn snapshot_source_must_be_unambiguous() {
        assert!(snapshot_from_args(&args(&["plan"]).unwrap()).is_err());
        assert!(
            snapshot_from_args(&args(&["plan", "--live", "--snapshot", "x"]).unwrap()).is_err()
        );
    }

    #[test]
    fn report_command_writes_raw_and_sanitized_files() {
        let dir = std::env::temp_dir().join(format!("rustward-report-test-{}", std::process::id()));
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/synthetic-lab-snapshot.json"
        );
        let a = args(&[
            "report",
            "--snapshot",
            fixture,
            "--out-dir",
            dir.to_str().unwrap(),
        ])
        .unwrap();
        write_reports(&a).unwrap();
        for f in [
            "diagnostic-raw.md",
            "diagnostic-raw.json",
            "diagnostic-sanitized.md",
            "diagnostic-sanitized.json",
        ] {
            let text = std::fs::read_to_string(dir.join(f)).unwrap();
            assert!(text.contains("NOT ACTIVE"), "{f}");
        }
        assert!(
            !dir.join("snapshot-raw.json").exists(),
            "only live reports copy the snapshot"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_inspect_reads_a_capture_file_and_reports_without_writing() {
        use rustward_enforcement::device_install::RESTRICTIONS_KEY;
        use rustward_enforcement::policy_state::{PolicySnapshot, RegData};
        let dir = std::env::temp_dir().join(format!("rw-inv-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let capture = CapturedPolicy {
            captured_ms: 1,
            key_present: true,
            values: PolicySnapshot::default()
                .with(RESTRICTIONS_KEY, "DenyUnspecified", RegData::Dword(1))
                .with(RESTRICTIONS_KEY, "VendorExtra", RegData::Sz("x".into())),
            ..CapturedPolicy::default()
        };
        let file = dir.join("capture.json");
        std::fs::write(&file, serde_json::to_string(&capture).unwrap()).unwrap();
        let a = Args {
            command: "policy-inspect".into(),
            policy_capture: Some(file.display().to_string()),
            snapshot: Some(format!(
                "{}/../../tests/fixtures/synthetic-lab-snapshot.json",
                env!("CARGO_MANIFEST_DIR")
            )),
            ..Args::default()
        };
        let loaded = load_capture(&a).unwrap();
        assert_eq!(loaded, capture);
        let text = render_inspection(&inspect(&loaded, None));
        assert!(text.contains("DenyUnspecified: 1 (documented)"));
        assert!(text.contains("Unrecognised values (not interpreted): 1"));
        assert!(policy_inspect(&a).is_ok());
        // Both sources at once is refused.
        let both = Args { live: true, ..a };
        assert!(load_capture(&both).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
