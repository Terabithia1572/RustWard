//! Inventory sources: live SetupAPI (Windows), synthetic fixture, or empty.

use rustward_core::device::{DeviceSnapshot, SNAPSHOT_SCHEMA_VERSION, SnapshotSource};
use rustward_windows::{EnumerationScope, collect_inventory};

/// The bundled SYNTHETIC lab fixture (not real hardware).
pub const SYNTHETIC_FIXTURE: &str =
    include_str!("../../../tests/fixtures/synthetic-lab-snapshot.json");

/// A source of device snapshots.
pub trait InventorySource: Send {
    /// Collect a snapshot (+ read warnings).
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String>;
    /// `live`, `synthetic` or `empty`.
    fn kind(&self) -> &'static str;
}

/// Live read-only SetupAPI enumeration (Windows only; errors elsewhere).
#[derive(Debug, Default)]
pub struct LiveInventory;

impl InventorySource for LiveInventory {
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
        collect_inventory(EnumerationScope::IncludeNonPresent)
            .map(|i| (i.snapshot, i.warnings))
            .map_err(|e| e.to_string())
    }
    fn kind(&self) -> &'static str {
        "live"
    }
}

/// A fixed snapshot (synthetic fixtures, tests).
#[derive(Debug, Clone)]
pub struct FixtureInventory {
    snapshot: DeviceSnapshot,
}

impl FixtureInventory {
    /// From a snapshot.
    #[must_use]
    pub fn new(snapshot: DeviceSnapshot) -> Self {
        Self { snapshot }
    }

    /// The bundled synthetic lab fixture.
    pub fn bundled() -> Result<Self, String> {
        DeviceSnapshot::from_json(SYNTHETIC_FIXTURE)
            .map(Self::new)
            .map_err(|e| e.to_string())
    }

    /// Replace the snapshot (tests simulate arrivals/removals).
    pub fn set(&mut self, snapshot: DeviceSnapshot) {
        self.snapshot = snapshot;
    }
}

impl InventorySource for FixtureInventory {
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
        Ok((self.snapshot.clone(), Vec::new()))
    }
    fn kind(&self) -> &'static str {
        match self.snapshot.source {
            SnapshotSource::Synthetic { .. } => "synthetic",
            SnapshotSource::Live { .. } => "replayed",
        }
    }
}

/// No devices (development backend on non-Windows before a fixture is loaded).
#[derive(Debug, Default)]
pub struct EmptyInventory;

impl InventorySource for EmptyInventory {
    fn collect(&mut self) -> Result<(DeviceSnapshot, Vec<String>), String> {
        Ok((
            DeviceSnapshot {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: SnapshotSource::Synthetic {
                    description: "empty development inventory".into(),
                },
                devices: Vec::new(),
            },
            Vec::new(),
        ))
    }
    fn kind(&self) -> &'static str {
        "empty"
    }
}
