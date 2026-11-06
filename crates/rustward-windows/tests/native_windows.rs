//! Native Windows integration tests. They run ONLY on Windows, perform
//! read-only enumeration of the real device tree, and change nothing.
//! Run with `cargo test -p rustward-windows --test native_windows -- --nocapture`
//! to see the summary lines.

#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use rustward_core::class_guids;
use rustward_core::classify::{DeviceCategory, classify};
use rustward_core::device::SnapshotSource;
use rustward_windows::{EnumerationScope, collect_inventory};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

fn handle_count() -> u32 {
    let mut count = 0u32;
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; `count` is a valid out-pointer for the duration of the call.
    let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
    assert_ne!(ok, 0, "GetProcessHandleCount failed");
    count
}

#[test]
fn native_backend_enumerates_the_live_device_tree() {
    let inv = collect_inventory(EnumerationScope::PresentOnly).expect("live enumeration");
    let devices = &inv.snapshot.devices;
    println!(
        "native: present devices = {}, read warnings = {}",
        devices.len(),
        inv.warnings.len()
    );
    assert!(
        devices.len() > 10,
        "a real Windows PC has more than 10 devnodes"
    );
    assert!(devices.iter().all(|d| !d.instance_id.is_empty()));
    assert!(
        devices
            .iter()
            .any(|d| d.instance_id.eq_ignore_ascii_case("HTREE\\ROOT\\0")),
        "the PnP root devnode must be enumerated"
    );
    assert!(matches!(
        inv.snapshot.source,
        SnapshotSource::Live {
            includes_non_present: false,
            ..
        }
    ));
    let with_parent = devices
        .iter()
        .filter(|d| d.parent_instance_id.is_some())
        .count();
    println!("native: present devices with a readable parent = {with_parent}");
    assert!(
        with_parent * 5 >= devices.len() * 4,
        "parent property should resolve for at least 80% of present devices"
    );
}

#[test]
fn non_present_enumeration_is_a_superset_of_present() {
    let present = collect_inventory(EnumerationScope::PresentOnly).unwrap();
    let all = collect_inventory(EnumerationScope::IncludeNonPresent).unwrap();
    let all_ids: HashSet<String> = all
        .snapshot
        .devices
        .iter()
        .map(|d| d.instance_id.to_ascii_uppercase())
        .collect();
    let missing: Vec<_> = present
        .snapshot
        .devices
        .iter()
        .filter(|d| !all_ids.contains(&d.instance_id.to_ascii_uppercase()))
        .map(|d| d.instance_id.clone())
        .collect();
    let non_present = all
        .snapshot
        .devices
        .iter()
        .filter(|d| d.present == Some(false))
        .count();
    println!(
        "native: all devices = {}, marked non-present = {non_present}, present-only = {}",
        all.snapshot.devices.len(),
        present.snapshot.devices.len()
    );
    // A device may legitimately arrive between the two calls; allow a tiny slack.
    assert!(
        missing.len() <= 2,
        "present devices missing from full scan: {missing:?}"
    );
    assert!(all.snapshot.devices.len() >= present.snapshot.devices.len());
}

#[test]
fn repeated_enumeration_does_not_leak_handles() {
    for _ in 0..2 {
        collect_inventory(EnumerationScope::PresentOnly).unwrap();
    }
    let before = handle_count();
    for _ in 0..25 {
        collect_inventory(EnumerationScope::PresentOnly).unwrap();
    }
    let after = handle_count();
    println!("native: process handles before = {before}, after 25 scans = {after}");
    assert!(
        after <= before + 16,
        "handle count grew from {before} to {after}; device info sets may be leaking"
    );
}

#[test]
fn internal_disks_are_classified_as_system_storage_on_this_machine() {
    let inv = collect_inventory(EnumerationScope::PresentOnly).unwrap();
    let index = inv.snapshot.index();
    let mut internal = 0;
    for d in &inv.snapshot.devices {
        if !d.class_is(class_guids::DISK_DRIVE) {
            continue;
        }
        let c = classify(&index, d);
        let below_usb = c.usb_ancestor.is_some();
        println!(
            "native: disk {} -> {:?} (usb ancestor: {below_usb})",
            d.enumerator_name(),
            c.category
        );
        if !below_usb {
            internal += 1;
            assert_eq!(
                c.category,
                DeviceCategory::SystemOrNonUsbStorage,
                "non-USB disk must be excluded: {}",
                d.instance_id
            );
        }
    }
    assert!(internal >= 1, "the boot disk must be found and excluded");
}

#[test]
fn device_install_policy_capture_is_read_only_and_repeatable() {
    // Phase 10: reads the Restrictions key with KEY_READ only. Two captures
    // in a row must agree (nothing was written between them), and the OS
    // facts must come from RtlGetVersion on a real Windows 10/11 machine.
    let first = rustward_windows::capture_device_install_policy(1).expect("policy capture");
    let second = rustward_windows::capture_device_install_policy(2).expect("policy capture");
    println!(
        "native: restrictions key present = {}, values = {}, read errors = {}, os = {:?}",
        first.key_present,
        first.values.values.len(),
        first.read_errors.len(),
        first.os
    );
    assert!(first.os.is_windows);
    assert_eq!(
        first.os.major,
        Some(10),
        "Windows 10 and 11 report major 10"
    );
    assert!(first.os.build.is_some_and(|b| b >= 10240));
    assert_eq!(first.key_present, second.key_present);
    assert_eq!(first.values, second.values);
    if !first.key_present {
        assert!(first.values.values.is_empty());
    }
}
