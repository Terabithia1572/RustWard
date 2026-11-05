//! `rustward-inventory` — read-only diagnostics.
//!
//! Nothing in this tool changes device, driver, registry or policy state.
//! The only file it writes is the one passed to `--out`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use rustward_core::catalog::ValidatedCatalog;
use rustward_core::classify::{DeviceCategory, StorageScope};
use rustward_core::device::{DeviceSnapshot, SnapshotSource};
use rustward_core::evaluate::{Decision, Verdict, evaluate_snapshot};
use rustward_core::plan::{ConsistencyFinding, DeviceInstallPlan, check_consistency, compile_plan};
use rustward_core::policy::ValidatedPolicy;
use rustward_enforcement::{EnforcementProvider, ProtectionState, SimulationOnlyProvider};
use rustward_windows::{EnumerationScope, collect_inventory};
use serde::Serialize;

const DEFAULT_CATALOG: &str = include_str!("../../../config/manufacturer-catalog.json");
const DEFAULT_POLICY: &str = include_str!("../../../config/policy.example.json");

const BANNER: &str = "RustWard inventory - SIMULATION ONLY. No enforcement is active and nothing on this system is changed.";

const USAGE: &str = "\
Usage:
  rustward-inventory scan     [--include-non-present] [--catalog FILE] [--policy FILE] [--json]
  rustward-inventory capture  --out FILE [--include-non-present]
  rustward-inventory evaluate --snapshot FILE [--catalog FILE] [--policy FILE] [--json]
  rustward-inventory plan     (--snapshot FILE | --live) [--catalog FILE] [--policy FILE]

All commands are read-only. 'scan' and 'capture --live' require Windows.
Without --catalog/--policy the built-in Phase 1 catalog and the PC-01 example policy are used.";

#[derive(Debug, Default)]
struct Args {
    command: String,
    include_non_present: bool,
    json: bool,
    live: bool,
    catalog: Option<String>,
    policy: Option<String>,
    snapshot: Option<String>,
    out: Option<String>,
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
            "--catalog" => a.catalog = Some(value("--catalog")?),
            "--policy" => a.policy = Some(value("--policy")?),
            "--snapshot" => a.snapshot = Some(value("--snapshot")?),
            "--out" => a.out = Some(value("--out")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(a)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn load_rules(a: &Args) -> Result<(ValidatedCatalog, ValidatedPolicy), String> {
    let catalog_json = a.catalog.as_deref().map(read).transpose()?;
    let policy_json = a.policy.as_deref().map(read).transpose()?;
    let catalog = ValidatedCatalog::from_json(catalog_json.as_deref().unwrap_or(DEFAULT_CATALOG))
        .map_err(|e| match e {
        rustward_core::catalog::CatalogError::Invalid(issues) => {
            format!(
                "catalog rejected: {}",
                serde_json::to_string_pretty(&issues).unwrap_or_default()
            )
        }
        other => other.to_string(),
    })?;
    let policy =
        ValidatedPolicy::from_json(policy_json.as_deref().unwrap_or(DEFAULT_POLICY), &catalog)
            .map_err(|e| match e {
                rustward_core::policy::PolicyError::Invalid(issues) => {
                    format!(
                        "policy rejected: {}",
                        serde_json::to_string_pretty(&issues).unwrap_or_default()
                    )
                }
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

#[derive(Serialize)]
struct Report<'a> {
    notice: &'static str,
    protection_state: ProtectionState,
    source: &'a SnapshotSource,
    workstation_id: &'a str,
    policy_version: u64,
    catalog_version: &'a str,
    catalog_warnings: Vec<String>,
    policy_warnings: Vec<String>,
    read_warnings: &'a [String],
    decisions: Vec<&'a Decision>,
    already_installed_denied: Vec<&'a str>,
    plan_consistency: &'a [ConsistencyFinding],
}

fn build_and_print(
    snapshot: &DeviceSnapshot,
    read_warnings: &[String],
    catalog: &ValidatedCatalog,
    policy: &ValidatedPolicy,
    json: bool,
) -> Result<(), String> {
    let decisions = evaluate_snapshot(snapshot, policy, catalog);
    let plan = compile_plan(policy, catalog, Some(snapshot));
    let consistency = check_consistency(&plan, snapshot, &decisions);
    let provider = SimulationOnlyProvider;
    let interesting: Vec<&Decision> = decisions
        .iter()
        .filter(|d| {
            d.classification.category.scope() != StorageScope::NotInScope
                || matches!(
                    d.classification.category,
                    DeviceCategory::Peripheral { .. } | DeviceCategory::SystemOrNonUsbStorage
                )
        })
        .collect();
    // Every device in a snapshot is already installed, so an install-time
    // restriction would not block it without a baseline cleanup.
    let already_installed_denied: Vec<&str> = decisions
        .iter()
        .filter(|d| d.verdict == Verdict::Deny)
        .map(|d| d.instance_id.as_str())
        .collect();

    let report = Report {
        notice: BANNER,
        protection_state: provider.protection_state(),
        source: &snapshot.source,
        workstation_id: &policy.policy().workstation_id,
        policy_version: policy.policy().policy_version,
        catalog_version: &catalog.catalog().catalog_version,
        catalog_warnings: catalog
            .warnings()
            .iter()
            .map(|w| w.detail.clone())
            .collect(),
        policy_warnings: policy.warnings().iter().map(|w| w.detail.clone()).collect(),
        read_warnings,
        decisions: interesting,
        already_installed_denied,
        plan_consistency: &consistency,
    };
    if json {
        let s = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        println!("{s}");
    } else {
        print_text(&report);
    }
    Ok(())
}

fn label(d: &Decision) -> String {
    d.classification
        .inquiry
        .as_ref()
        .map(|i| {
            format!(
                "{} {}",
                i.vendor_display(),
                i.product_display().unwrap_or_default()
            )
        })
        .unwrap_or_else(|| d.instance_id.clone())
}

fn print_text(r: &Report<'_>) {
    println!("{}", r.notice);
    println!("Protection state: {}", r.protection_state.label_tr());
    match r.source {
        SnapshotSource::Live {
            computer_name,
            includes_non_present,
            ..
        } => println!(
            "Snapshot: live, computer {}, {}",
            computer_name.as_deref().unwrap_or("?"),
            if *includes_non_present {
                "present + previously installed devices"
            } else {
                "present devices only"
            }
        ),
        SnapshotSource::Synthetic { description } => {
            println!("Snapshot: SYNTHETIC - {description}")
        }
    }
    println!(
        "Policy: {} v{} | catalog {}",
        r.workstation_id, r.policy_version, r.catalog_version
    );
    for w in r
        .catalog_warnings
        .iter()
        .chain(&r.policy_warnings)
        .chain(r.read_warnings)
    {
        println!("  ! {w}");
    }

    let section = |title: &str, pred: &dyn Fn(&Decision) -> bool| {
        let items: Vec<_> = r.decisions.iter().filter(|d| pred(d)).collect();
        println!("\n{title} ({})", items.len());
        for d in items {
            let verdict = match d.verdict {
                Verdict::Allow => "ALLOW (simulated)",
                Verdict::Deny => "DENY  (simulated)",
                Verdict::NotApplicable => "n/a",
            };
            println!("  [{verdict}] {}", label(d));
            println!("      instance: {}", d.instance_id);
            if let Some(u) = &d.classification.usb_ancestor {
                println!("      usb: VID {:04X} PID {:04X}", u.ids.vid, u.ids.pid);
            }
            if let Some(i) = &d.classification.inquiry {
                println!("      vendor-level ID: {}", i.vendor_level_id);
            }
            println!(
                "      category: {}",
                serde_json::to_string(&d.classification.category).unwrap_or_default()
            );
            println!(
                "      reason: {}",
                serde_json::to_string(&d.reason).unwrap_or_default()
            );
            for e in &d.evidence {
                println!("      {:?}: [{}] {}", e.kind, e.source, e.detail);
            }
        }
    };
    section("USB storage in policy scope", &|d| {
        d.classification.category.scope() == StorageScope::InScope
    });
    section("USB storage with pending scope decision", &|d| {
        d.classification.category.scope() == StorageScope::ScopeDecisionPending
    });
    section("Peripherals (never targeted)", &|d| {
        matches!(d.classification.category, DeviceCategory::Peripheral { .. })
    });
    section("System / non-USB storage (never touched)", &|d| {
        d.classification.category == DeviceCategory::SystemOrNonUsbStorage
    });

    println!(
        "\nAlready-installed devices the policy would deny ({}):",
        r.already_installed_denied.len()
    );
    println!(
        "  Device-installation restrictions do NOT re-evaluate installed devices; these need a reviewed baseline cleanup in Phase 2."
    );
    for id in &r.already_installed_denied {
        println!("  - {id}");
    }
    println!(
        "\nDecision engine vs. modelled Device Installation plan ({} finding(s)):",
        r.plan_consistency.len()
    );
    for f in r.plan_consistency {
        println!(
            "  - {}: {} (verdict {:?}, model {:?})",
            f.kind, f.instance_id, f.verdict, f.model
        );
    }
}

fn print_plan(plan: &DeviceInstallPlan) -> Result<(), String> {
    println!("{BANNER}");
    println!("PLAN PREVIEW - status NOT APPLIED. RustWard Phase 1 cannot apply it.");
    println!(
        "{}",
        serde_json::to_string_pretty(plan).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run(a: &Args) -> Result<(), String> {
    match a.command.as_str() {
        "scan" => {
            let (catalog, policy) = load_rules(a)?;
            let (snap, warnings) = live_snapshot(a)?;
            build_and_print(&snap, &warnings, &catalog, &policy, a.json)
        }
        "capture" => {
            let out = a.out.as_deref().ok_or("capture needs --out FILE")?;
            let (snap, warnings) = live_snapshot(a)?;
            let s = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
            std::fs::write(out, s).map_err(|e| format!("cannot write {out}: {e}"))?;
            eprintln!("wrote {} device records to {out}", snap.devices.len());
            for w in warnings {
                eprintln!("  ! {w}");
            }
            Ok(())
        }
        "evaluate" => {
            let (catalog, policy) = load_rules(a)?;
            let path = a
                .snapshot
                .as_deref()
                .ok_or("evaluate needs --snapshot FILE")?;
            let snap = DeviceSnapshot::from_json(&read(path)?).map_err(|e| e.to_string())?;
            build_and_print(&snap, &[], &catalog, &policy, a.json)
        }
        "plan" => {
            let (catalog, policy) = load_rules(a)?;
            let snap = match (&a.snapshot, a.live) {
                (Some(p), false) => {
                    DeviceSnapshot::from_json(&read(p)?).map_err(|e| e.to_string())?
                }
                (None, true) => live_snapshot(a)?.0,
                _ => return Err("plan needs exactly one of --snapshot FILE or --live".into()),
            };
            print_plan(&compile_plan(&policy, &catalog, Some(&snap)))
        }
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
        let a = args(&["evaluate", "--snapshot", "x.json", "--json"]).unwrap();
        assert_eq!(a.command, "evaluate");
        assert_eq!(a.snapshot.as_deref(), Some("x.json"));
        assert!(a.json);
        assert!(args(&["scan", "--force"]).is_err());
        assert!(args(&["scan", "--catalog"]).is_err());
        assert!(args(&[]).is_err());
    }

    #[test]
    fn built_in_rules_load() {
        let a = args(&["scan"]).unwrap();
        assert!(load_rules(&a).is_ok());
    }
}
