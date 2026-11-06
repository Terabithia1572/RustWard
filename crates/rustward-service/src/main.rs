//! `rustward-service` — RustWard background service host.
//!
//! Commands:
//! - `console [--db PATH] [--synthetic] [--iterations N] [--interval-secs S]`
//!   runs the service loop in the foreground (development; default database
//!   in the temp directory, never ProgramData).
//! - `service` — entry point used by the Windows SCM (Windows only,
//!   NOT VERIFIED). The service is never installed by this program.
//! - `install-plan` — prints the planned deployment commands (not executed).
//!
//! Detection is separate from enforcement: this host refreshes the
//! inventory and records simulated decisions; it never blocks devices.

#![forbid(unsafe_code)]

// Some items are only used by the Windows SCM host.
#[cfg_attr(not(windows), allow(dead_code))]
mod paths;
#[cfg_attr(not(windows), allow(dead_code))]
mod runtime;

// Used by the Windows SCM host; tested on every OS.
#[cfg_attr(not(windows), allow(dead_code))]
mod event_mirror;
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
mod ipc_server;
#[cfg(any(windows, feature = "host-typecheck"))]
#[cfg_attr(not(windows), allow(dead_code))]
mod scm;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rustward_app::{
    AppConfig, AppService, BackendKind, FixtureInventory, InventorySource, LiveInventory,
    default_policy_state,
};
use rustward_storage::{Clock, Store, SystemClock};

use crate::paths::{INSTALL_PLAN, ServicePaths};
use crate::runtime::ServiceRuntime;

const USAGE: &str = "\
Usage:
  rustward-service console [--db PATH] [--synthetic] [--iterations N] [--interval-secs S]
  rustward-service service        (Windows SCM entry point; NOT VERIFIED)
  rustward-service install-plan   (prints planned deployment commands; executes nothing)";

/// Build the runtime and application service for a data layout.
pub(crate) fn build_runtime(
    paths: &ServicePaths,
    synthetic: bool,
    backend: BackendKind,
    location: &str,
) -> Result<(ServiceRuntime, Arc<AppService>), String> {
    std::fs::create_dir_all(&paths.data_dir)
        .map_err(|e| format!("cannot create {}: {e}", paths.data_dir.display()))?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = Store::open(&paths.database, Arc::clone(&clock)).map_err(|e| e.to_string())?;
    let inventory: Box<dyn InventorySource> = if synthetic {
        Box::new(FixtureInventory::bundled()?)
    } else {
        Box::new(LiveInventory)
    };
    let app = Arc::new(
        AppService::new(
            store,
            Arc::clone(&clock),
            inventory,
            AppConfig {
                backend,
                allow_synthetic: synthetic,
                backup_dir: Some(paths.backups.clone()),
                database_location: location.into(),
                app_version: env!("CARGO_PKG_VERSION").into(),
            },
            &default_policy_state()?,
        )
        .map_err(|e| e.to_string())?,
    );
    Ok((ServiceRuntime::new(Arc::clone(&app), clock), app))
}

#[derive(Debug, Default)]
struct ConsoleArgs {
    db: Option<PathBuf>,
    synthetic: bool,
    iterations: Option<u64>,
    interval: Option<Duration>,
}

fn parse_console(mut it: impl Iterator<Item = String>) -> Result<ConsoleArgs, String> {
    let mut a = ConsoleArgs::default();
    while let Some(flag) = it.next() {
        let mut value = |n: &str| it.next().ok_or(format!("{n} needs a value"));
        match flag.as_str() {
            "--db" => a.db = Some(PathBuf::from(value("--db")?)),
            "--synthetic" => a.synthetic = true,
            "--iterations" => {
                a.iterations = Some(
                    value("--iterations")?
                        .parse()
                        .map_err(|_| "invalid --iterations")?,
                )
            }
            "--interval-secs" => {
                let s: u64 = value("--interval-secs")?
                    .parse()
                    .map_err(|_| "invalid --interval-secs")?;
                a.interval = Some(Duration::from_secs(s.clamp(1, 3600)));
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(a)
}

fn console(a: &ConsoleArgs) -> Result<(), String> {
    let paths = match &a.db {
        Some(db) => {
            let dir = db
                .parent()
                .map_or_else(|| PathBuf::from("."), PathBuf::from);
            ServicePaths {
                database: db.clone(),
                backups: dir.join("backups"),
                data_dir: dir,
            }
        }
        None => ServicePaths::development(),
    };
    let (mut runtime, _app) =
        build_runtime(&paths, a.synthetic, BackendKind::WindowsService, "dev_temp")?;
    eprintln!(
        "RustWard service (console mode). ENFORCEMENT: NOT ACTIVE. database: {} inventory: {}",
        paths.database.display(),
        if a.synthetic {
            "SYNTHETIC fixture"
        } else {
            "live (Windows only)"
        }
    );
    let n = runtime.run(a.iterations, a.interval);
    eprintln!("stopped after {n} iteration(s)");
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("console") => parse_console(args).and_then(|a| console(&a)),
        Some("service") => {
            #[cfg(windows)]
            {
                scm::run_dispatcher()
            }
            #[cfg(not(windows))]
            {
                Err("the service entry point is only available on Windows".to_owned())
            }
        }
        Some("install-plan") => {
            println!("{INSTALL_PLAN}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
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

    #[test]
    fn console_args() {
        let a = parse_console(
            ["--synthetic", "--iterations", "2", "--interval-secs", "0"]
                .iter()
                .map(|s| (*s).to_owned()),
        )
        .unwrap();
        assert!(a.synthetic);
        assert_eq!(a.iterations, Some(2));
        assert_eq!(a.interval, Some(Duration::from_secs(1)), "clamped");
        assert!(parse_console(["--bogus"].iter().map(|s| (*s).to_owned())).is_err());
    }

    #[test]
    fn console_mode_runs_against_a_temp_database_with_synthetic_inventory() {
        let dir = std::env::temp_dir().join(format!("rustward-svc-test-{}", std::process::id()));
        let a = ConsoleArgs {
            db: Some(dir.join("svc.db")),
            synthetic: true,
            iterations: Some(2),
            interval: Some(Duration::from_secs(1)),
        };
        console(&a).unwrap();
        assert!(dir.join("svc.db").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
