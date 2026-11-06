//! Platform-neutral service runtime: periodic inventory refresh, health
//! tracking, daily retention and cooperative shutdown. The Windows SCM host
//! and the console host both drive this type.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use rustward_app::AppService;
use rustward_storage::{Clock, Severity};

/// Retention runs at most once per this interval.
pub const RETENTION_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;
/// Consecutive failures before the health state becomes `Degraded`.
pub const DEGRADED_AFTER_FAILURES: u32 = 3;

/// After a device-change wake-up, wait this long for the device stack to
/// settle (a USB disk produces several devnodes in quick succession).
pub const WAKE_SETTLE: Duration = Duration::from_millis(750);
/// Minimum spacing between wake-triggered refreshes (protects against
/// notification storms, e.g. during driver reinstallation).
pub const MIN_WAKE_SPACING: Duration = Duration::from_secs(2);

/// Something that can wake the runtime early (device-change telemetry).
/// Waking only schedules an inventory refresh; it never enforces anything.
pub trait WakeSource: Send {
    /// Block up to `timeout`; `true` if a wake-up signal arrived.
    fn wait(&mut self, timeout: Duration) -> bool;
    /// Discard queued signals; returns how many were dropped.
    fn drain(&mut self) -> usize;
}

impl<T: Send> WakeSource for Receiver<T> {
    fn wait(&mut self, timeout: Duration) -> bool {
        match self.recv_timeout(timeout) {
            Ok(_) => true,
            Err(RecvTimeoutError::Timeout) => false,
            // A dead sender must not turn the loop into a busy spin.
            Err(RecvTimeoutError::Disconnected) => {
                std::thread::sleep(timeout);
                false
            }
        }
    }
    fn drain(&mut self) -> usize {
        self.try_iter().count()
    }
}

/// Service health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Refreshes succeed.
    Running,
    /// Repeated refresh failures; enforcement state unaffected (detection
    /// is separate from enforcement), operators are warned.
    Degraded,
}

/// Outcome of one iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutcome {
    /// Refresh succeeded.
    pub refreshed: bool,
    /// Retention executed in this tick.
    pub retention_ran: bool,
    /// Health after the tick.
    pub health: HealthState,
}

/// The runtime.
pub struct ServiceRuntime {
    app: Arc<AppService>,
    clock: Arc<dyn Clock>,
    stop: Arc<AtomicBool>,
    last_retention_ms: Option<i64>,
    failures: u32,
    wake: Option<Box<dyn WakeSource>>,
    wake_refreshes: u64,
}

impl std::fmt::Debug for ServiceRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceRuntime")
            .field("failures", &self.failures)
            .finish_non_exhaustive()
    }
}

impl ServiceRuntime {
    /// New runtime.
    pub fn new(app: Arc<AppService>, clock: Arc<dyn Clock>) -> Self {
        Self {
            app,
            clock,
            stop: Arc::new(AtomicBool::new(false)),
            last_retention_ms: None,
            failures: 0,
            wake: None,
            wake_refreshes: 0,
        }
    }

    /// Use an externally owned stop flag (e.g. the SCM control handler's).
    #[must_use]
    pub fn with_stop_handle(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = stop;
        self
    }

    /// Refresh early when `wake` signals a device change.
    #[must_use]
    pub fn with_wake_source(mut self, wake: Box<dyn WakeSource>) -> Self {
        self.wake = Some(wake);
        self
    }

    /// Refreshes triggered by wake-ups so far.
    #[must_use]
    pub fn wake_refreshes(&self) -> u64 {
        self.wake_refreshes
    }

    /// Sleep up to `interval` in short slices. Returns early (after the
    /// settle delay) when a wake-up arrives and `MIN_WAKE_SPACING` has
    /// passed since the previous wake-triggered refresh.
    fn idle(&mut self, interval: Duration, last_wake_refresh: &mut Option<Instant>) -> bool {
        let start = Instant::now();
        let slice = Duration::from_millis(100);
        while !self.stop.load(Ordering::SeqCst) {
            let elapsed = start.elapsed();
            if elapsed >= interval {
                return false;
            }
            let step = slice.min(interval - elapsed);
            let woke = match self.wake.as_mut() {
                Some(w) => w.wait(step),
                None => {
                    std::thread::sleep(step);
                    false
                }
            };
            let spaced = last_wake_refresh.is_none_or(|t| t.elapsed() >= MIN_WAKE_SPACING);
            if woke && spaced {
                let settle_until = Instant::now() + WAKE_SETTLE;
                while Instant::now() < settle_until && !self.stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if let Some(w) = self.wake.as_mut() {
                    w.drain();
                }
                *last_wake_refresh = Some(Instant::now());
                self.wake_refreshes += 1;
                return true;
            }
        }
        false
    }

    /// Handle used by the SCM control handler / Ctrl+C to request a stop.
    #[must_use]
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// The application service.
    #[must_use]
    pub fn app(&self) -> Arc<AppService> {
        Arc::clone(&self.app)
    }

    /// One iteration: refresh, then retention if due. Never panics; errors
    /// are recorded as events and reflected in health.
    pub fn tick(&mut self) -> TickOutcome {
        let refreshed = match self.app.refresh_inventory() {
            Ok(_) => {
                if self.failures >= DEGRADED_AFTER_FAILURES {
                    let _ = self.app.record_event(
                        Severity::Info,
                        "service_recovered",
                        "inventory refresh recovered",
                    );
                }
                self.failures = 0;
                true
            }
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                if self.failures == DEGRADED_AFTER_FAILURES {
                    let _ = self.app.record_event(
                        Severity::Critical,
                        "service_degraded",
                        "inventory refresh failed repeatedly; detection degraded (enforcement state unchanged, still not verified)",
                    );
                }
                false
            }
        };
        let now = self.clock.now_ms();
        let due = self
            .last_retention_ms
            .is_none_or(|t| now.saturating_sub(t) >= RETENTION_INTERVAL_MS);
        let retention_ran = due && self.app.apply_retention().is_ok();
        if retention_ran {
            self.last_retention_ms = Some(now);
        }
        TickOutcome {
            refreshed,
            retention_ran,
            health: if self.failures >= DEGRADED_AFTER_FAILURES {
                HealthState::Degraded
            } else {
                HealthState::Running
            },
        }
    }

    /// Run until stopped (or `max_iterations`). Sleeps in short slices so a
    /// stop request is honoured within ~100 ms.
    pub fn run(&mut self, max_iterations: Option<u64>, interval_override: Option<Duration>) -> u64 {
        let _ = self.app.record_event(
            Severity::Info,
            "service_started",
            "RustWard service loop started",
        );
        let mut iterations = 0u64;
        let mut last_wake_refresh: Option<Instant> = None;
        while !self.stop.load(Ordering::SeqCst) {
            self.tick();
            iterations += 1;
            if max_iterations.is_some_and(|m| iterations >= m) {
                break;
            }
            let interval = interval_override.unwrap_or_else(|| {
                Duration::from_secs(u64::from(self.app.refresh_interval_seconds()))
            });
            self.idle(interval, &mut last_wake_refresh);
        }
        let _ = self.app.record_event(
            Severity::Info,
            "service_stopping",
            "RustWard service loop stopping",
        );
        iterations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustward_app::{
        AppConfig, BackendKind, FixtureInventory, InventorySource, default_policy_state,
    };
    use rustward_core::device::DeviceSnapshot;
    use rustward_ipc::messages::{AccessLevel, EventQuery, Request, ResponseBody};
    use rustward_ipc::rpc::Handler;
    use rustward_ipc::{ClientIdentity, IdentitySource};
    use rustward_storage::{ManualClock, Store};

    struct Flaky {
        fail_first: u32,
        calls: u32,
    }
    impl InventorySource for Flaky {
        fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
            self.calls += 1;
            if self.calls <= self.fail_first {
                Err("simulated failure".into())
            } else {
                FixtureInventory::bundled()?.collect()
            }
        }
        fn kind(&self) -> &'static str {
            "synthetic"
        }
    }

    fn runtime(inv: Box<dyn InventorySource>) -> (ServiceRuntime, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(1_793_836_800_000));
        let app = AppService::new(
            Store::open_in_memory(clock.clone()).unwrap(),
            clock.clone(),
            inv,
            AppConfig {
                backend: BackendKind::WindowsService,
                allow_synthetic: false,
                backup_dir: None,
                database_location: "memory".into(),
                app_version: "test".into(),
            },
            &default_policy_state().unwrap(),
        )
        .unwrap();
        (ServiceRuntime::new(Arc::new(app), clock.clone()), clock)
    }

    fn kinds(rt: &ServiceRuntime) -> Vec<String> {
        let id = ClientIdentity {
            account: "SYSTEM".into(),
            sid: None,
            is_administrator: true,
            elevated: true,
            source: IdentitySource::Test,
            channel_max_access: AccessLevel::Administrator,
        };
        match rt
            .app()
            .handle(
                &Request::ListEvents {
                    query: EventQuery::default(),
                },
                &id,
            )
            .unwrap()
        {
            ResponseBody::Events(e) => e.into_iter().map(|e| e.kind).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn degrades_after_repeated_failures_and_recovers() {
        let (mut rt, _) = runtime(Box::new(Flaky {
            fail_first: 3,
            calls: 0,
        }));
        assert_eq!(rt.tick().health, HealthState::Running);
        assert_eq!(rt.tick().health, HealthState::Running);
        let t = rt.tick();
        assert!(!t.refreshed);
        assert_eq!(t.health, HealthState::Degraded);
        let t = rt.tick();
        assert!(t.refreshed);
        assert_eq!(t.health, HealthState::Running);
        let k = kinds(&rt);
        assert!(k.contains(&"service_degraded".to_owned()));
        assert!(k.contains(&"service_recovered".to_owned()));
    }

    #[test]
    fn retention_runs_once_per_day() {
        let (mut rt, clock) = runtime(Box::new(FixtureInventory::bundled().unwrap()));
        assert!(rt.tick().retention_ran);
        assert!(!rt.tick().retention_ran);
        clock.advance(RETENTION_INTERVAL_MS);
        assert!(rt.tick().retention_ran);
    }

    #[test]
    fn run_stops_on_request_and_records_lifecycle() {
        let (mut rt, _) = runtime(Box::new(FixtureInventory::bundled().unwrap()));
        let stop = rt.stop_handle();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            stop.store(true, Ordering::SeqCst);
        });
        let n = rt.run(None, Some(Duration::from_millis(50)));
        t.join().unwrap();
        assert!(n >= 1);
        let k = kinds(&rt);
        assert!(k.contains(&"service_started".to_owned()));
        assert!(k.contains(&"service_stopping".to_owned()));
    }

    #[test]
    fn device_change_wakes_the_loop_early_and_storms_are_coalesced() {
        let (rt, _) = runtime(Box::new(FixtureInventory::bundled().unwrap()));
        let (tx, rx) = std::sync::mpsc::channel::<u8>();
        let mut rt = rt.with_wake_source(Box::new(rx));
        let stop = rt.stop_handle();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // A burst of 50 notifications (one USB disk = several devnodes).
            for i in 0..50u8 {
                let _ = tx.send(i);
            }
            std::thread::sleep(Duration::from_millis(1500));
            stop.store(true, Ordering::SeqCst);
            tx
        });
        let started = Instant::now();
        // Without a wake-up the first sleep would last a full hour.
        let n = rt.run(None, Some(Duration::from_secs(3600)));
        let _tx = sender.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(n, 2, "initial refresh + exactly one wake-triggered refresh");
        assert_eq!(rt.wake_refreshes(), 1, "the burst is coalesced");
    }

    #[test]
    fn disconnected_wake_source_does_not_spin() {
        let (rt, _) = runtime(Box::new(FixtureInventory::bundled().unwrap()));
        let (tx, rx) = std::sync::mpsc::channel::<u8>();
        drop(tx);
        let mut rt = rt.with_wake_source(Box::new(rx));
        let started = Instant::now();
        assert_eq!(rt.run(Some(2), Some(Duration::from_millis(300))), 2);
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert_eq!(rt.wake_refreshes(), 0);
    }

    #[test]
    fn external_stop_handle_is_honoured() {
        let (rt, _) = runtime(Box::new(FixtureInventory::bundled().unwrap()));
        let stop = Arc::new(AtomicBool::new(true));
        let mut rt = rt.with_stop_handle(Arc::clone(&stop));
        assert_eq!(rt.run(None, Some(Duration::from_secs(3600))), 0);
    }

    #[test]
    fn bounded_run_for_console_mode() {
        let (mut rt, _) = runtime(Box::new(FixtureInventory::bundled().unwrap()));
        assert_eq!(rt.run(Some(3), Some(Duration::from_millis(1))), 3);
    }
}
