//! Reproducible performance and concurrency benchmarks for ARGON Phase 4 (Bug B).
//!
//! Measures:
//! 1. Live Windows SetupAPI enumeration (`IncludeNonPresent` and `PresentOnly`).
//! 2. `apply_inventory` scaling when removing a 15-node composite USB device from a 1,500-device tree.
//! 3. Concurrent IPC read/observation latency while `PolicySource::capture` is slow (25 ms).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustward_app::{
    AppConfig, AppService, BackendKind, InventorySource, PolicySource, default_policy_state,
};
use rustward_core::device::{
    DeviceRecord, DeviceSnapshot, SNAPSHOT_SCHEMA_VERSION, SnapshotSource,
};
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_ipc::messages::AccessLevel;
use rustward_ipc::rpc::Handler;
use rustward_ipc::{ClientIdentity, IdentitySource, Request};
use rustward_storage::{ManualClock, Store};

fn admin() -> ClientIdentity {
    ClientIdentity {
        account: "PC-PERF\\admin".into(),
        sid: Some("S-1-5-21-1000-1000-1000-500".into()),
        is_administrator: true,
        elevated: true,
        source: IdentitySource::Test,
        channel_max_access: AccessLevel::Administrator,
    }
}

fn build_large_snapshot(total_filler: usize, with_composite_usb: bool) -> DeviceSnapshot {
    let mut devices = Vec::with_capacity(total_filler + 20);
    devices.push(DeviceRecord {
        instance_id: "HTREE\\ROOT\\0".into(),
        present: Some(true),
        ..DeviceRecord::default()
    });
    devices.push(DeviceRecord {
        instance_id: "PCI\\VEN_15AD&DEV_07F0\\3&111111&0&00".into(),
        parent_instance_id: Some("HTREE\\ROOT\\0".into()),
        class_name: Some("SCSIAdapter".into()),
        class_guid: Some("{4d36e97b-e325-11ce-bfc1-08002be10318}".into()),
        present: Some(true),
        ..DeviceRecord::default()
    });
    devices.push(DeviceRecord {
        instance_id: "SCSI\\DISK&VEN_NVME&PROD_VMWARE_VIRTUAL_N\\5&25A13950&0&000000".into(),
        parent_instance_id: Some("PCI\\VEN_15AD&DEV_07F0\\3&111111&0&00".into()),
        class_name: Some("DiskDrive".into()),
        class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
        hardware_ids: vec!["SCSI\\DiskNVMe____VMware_Virtual_N1.0_".into()],
        service: Some("disk".into()),
        present: Some(true),
        ..DeviceRecord::default()
    });
    for i in 0..total_filler {
        devices.push(DeviceRecord {
            instance_id: format!("ACPI\\PNP0C02\\{i:04}"),
            parent_instance_id: Some("HTREE\\ROOT\\0".into()),
            class_name: Some("System".into()),
            class_guid: Some("{4d36e97d-e325-11ce-bfc1-08002be10318}".into()),
            friendly_name: Some(format!("Motherboard resource {i}")),
            present: Some(i % 3 != 0),
            ..DeviceRecord::default()
        });
    }
    if with_composite_usb {
        let root_usb = "USB\\VID_0951&PID_1666\\PERF0001".to_owned();
        devices.push(DeviceRecord {
            instance_id: root_usb.clone(),
            parent_instance_id: Some("HTREE\\ROOT\\0".into()),
            class_name: Some("USB".into()),
            class_guid: Some("{36fc9e60-c465-11cf-8056-444553540000}".into()),
            hardware_ids: vec!["USB\\VID_0951&PID_1666".into()],
            service: Some("USBSTOR".into()),
            present: Some(true),
            ..DeviceRecord::default()
        });
        for lun in 0..14 {
            devices.push(DeviceRecord {
                instance_id: format!(
                    "USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\\PERF0001&{lun}"
                ),
                parent_instance_id: Some(root_usb.clone()),
                class_name: Some("DiskDrive".into()),
                class_guid: Some("{4d36e967-e325-11ce-bfc1-08002be10318}".into()),
                hardware_ids: vec![
                    "USBSTOR\\DiskKingstonDataTraveler_3.0PMAP".into(),
                    "USBSTOR\\DiskKingstonDataTraveler_3.0".into(),
                ],
                friendly_name: Some(format!("Kingston DataTraveler LUN {lun}")),
                service: Some("disk".into()),
                present: Some(true),
                ..DeviceRecord::default()
            });
        }
    }
    DeviceSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Synthetic {
            description: "perf-benchmark".into(),
        },
        devices,
    }
}

struct ToggleInventory {
    snapshots: Mutex<Vec<DeviceSnapshot>>,
    delay: Duration,
    calls: Arc<AtomicUsize>,
}

impl InventorySource for ToggleInventory {
    fn kind(&self) -> &'static str {
        "perf_toggle"
    }
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        let mut guard = self.snapshots.lock().unwrap();
        let snap = if guard.len() > 1 {
            guard.remove(0)
        } else {
            guard[0].clone()
        };
        Ok((snap, Vec::new()))
    }
}

struct SlowPolicySource {
    delay: Duration,
}

impl PolicySource for SlowPolicySource {
    fn name(&self) -> &'static str {
        "windows_registry_read_only"
    }
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String> {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        Ok(CapturedPolicy {
            captured_ms: now_ms,
            key_present: false,
            ..CapturedPolicy::default()
        })
    }
}

#[test]
fn measure_composite_removal_and_concurrent_ipc_timings() {
    // 1. Composite removal on 1,500-device tree (15 nodes removed at once).
    let with_usb = build_large_snapshot(1500, true);
    let without_usb = build_large_snapshot(1500, false);
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(ManualClock::new(1_793_836_800_000));
    let svc = Arc::new(
        AppService::new(
            Store::open_in_memory(clock.clone()).unwrap(),
            clock.clone(),
            Box::new(ToggleInventory {
                snapshots: Mutex::new(vec![with_usb, without_usb]),
                delay: Duration::ZERO,
                calls: calls.clone(),
            }),
            AppConfig {
                backend: BackendKind::WindowsService,
                allow_synthetic: false,
                backup_dir: None,
                database_location: "memory".into(),
                app_version: "perf".into(),
            },
            &default_policy_state().unwrap(),
        )
        .unwrap()
        .with_policy_source(Box::new(SlowPolicySource {
            delay: Duration::ZERO,
        })),
    );
    svc.refresh_inventory().unwrap();
    let t0 = Instant::now();
    let summary = svc.refresh_inventory().unwrap();
    let removal_us = t0.elapsed().as_micros();
    println!(
        "PERF_COMPOSITE_REMOVAL_1500: removed={} elapsed_us={} ({:.2} ms)",
        summary.removed,
        removal_us,
        removal_us as f64 / 1000.0
    );
    assert_eq!(summary.removed, 14);

    // 2. 4 concurrent IPC calls (GetDashboard, GetEnforcementObservation,
    // GetEnforcementReadiness, ListDevices) when policy capture takes 25 ms.
    let snap = build_large_snapshot(1500, true);
    let svc_conc = Arc::new(
        AppService::new(
            Store::open_in_memory(clock.clone()).unwrap(),
            clock,
            Box::new(ToggleInventory {
                snapshots: Mutex::new(vec![snap]),
                delay: Duration::ZERO,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            AppConfig {
                backend: BackendKind::WindowsService,
                allow_synthetic: false,
                backup_dir: None,
                database_location: "memory".into(),
                app_version: "perf".into(),
            },
            &default_policy_state().unwrap(),
        )
        .unwrap()
        .with_policy_source(Box::new(SlowPolicySource {
            delay: Duration::from_millis(25),
        })),
    );
    svc_conc.refresh_inventory().unwrap();

    let t_conc = Instant::now();
    std::thread::scope(|s| {
        let a = admin();
        let s1 = &svc_conc;
        let h1 = s.spawn({
            let a = a.clone();
            move || {
                let t = Instant::now();
                s1.handle(&Request::GetDashboard, &a).unwrap();
                t.elapsed()
            }
        });
        let h2 = s.spawn({
            let a = a.clone();
            move || {
                let t = Instant::now();
                s1.handle(&Request::GetEnforcementObservation, &a).unwrap();
                t.elapsed()
            }
        });
        let h3 = s.spawn({
            let a = a.clone();
            move || {
                let t = Instant::now();
                s1.handle(&Request::GetEnforcementReadiness, &a).unwrap();
                t.elapsed()
            }
        });
        let h4 = s.spawn({
            move || {
                std::thread::sleep(Duration::from_millis(2));
                let t = Instant::now();
                s1.handle(
                    &Request::ListDevices {
                        include_absent: false,
                    },
                    &a,
                )
                .unwrap();
                t.elapsed()
            }
        });
        let (d1, d2, d3, d4) = (
            h1.join().unwrap(),
            h2.join().unwrap(),
            h3.join().unwrap(),
            h4.join().unwrap(),
        );
        let wall = t_conc.elapsed();
        println!(
            "PERF_CONCURRENT_IPC: wall={:.2}ms dashboard={:.2}ms obs={:.2}ms readiness={:.2}ms list_devices={:.2}ms",
            wall.as_secs_f64() * 1000.0,
            d1.as_secs_f64() * 1000.0,
            d2.as_secs_f64() * 1000.0,
            d3.as_secs_f64() * 1000.0,
            d4.as_secs_f64() * 1000.0,
        );
    });
}

#[cfg(windows)]
#[test]
fn measure_live_windows_setupapi_enumeration() {
    use rustward_windows::{EnumerationScope, collect_inventory};

    let warm = collect_inventory(EnumerationScope::IncludeNonPresent).unwrap();
    let count_all = warm.snapshot.devices.len();
    let mut all_ms = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let inv = collect_inventory(EnumerationScope::IncludeNonPresent).unwrap();
        assert!(!inv.snapshot.devices.is_empty());
        all_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    all_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mut present_ms = Vec::new();
    let mut count_present = 0;
    for _ in 0..5 {
        let t = Instant::now();
        let inv = collect_inventory(EnumerationScope::PresentOnly).unwrap();
        count_present = inv.snapshot.devices.len();
        present_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    present_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!(
        "PERF_LIVE_SETUPAPI: all_devices={} all_median={:.2}ms all_min={:.2}ms | present_devices={} present_median={:.2}ms present_min={:.2}ms",
        count_all, all_ms[2], all_ms[0], count_present, present_ms[2], present_ms[0],
    );
}
