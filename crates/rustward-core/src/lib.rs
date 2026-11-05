//! RustWard core: pure, platform-independent domain logic.
//!
//! This crate contains no Windows API calls and no I/O besides parsing
//! in-memory JSON. Everything here is unit-testable on any OS.
//!
//! Module map:
//! - [`ids`]: parsing/encoding of Windows Plug and Play identifier strings.
//! - [`device`]: raw device facts collected by a platform adapter (snapshot).
//! - [`catalog`]: local, versioned manufacturer catalog and its validation.
//! - [`policy`]: per-workstation brand allowlist policy and its validation.
//! - [`classify`]: device classification (USB storage vs. peripherals vs. system storage).
//! - [`evaluate`]: default-deny policy decisions with evidence.
//! - [`plan`]: compilation of the policy into a *preview* of a Windows
//!   Device Installation Restriction configuration, and a model of how
//!   Windows would evaluate it. Nothing in this crate applies anything.
//!
//! IMPORTANT: decisions produced here are *simulations*. They are not
//! enforcement and must never be presented to an operator as protection.

#![forbid(unsafe_code)]

pub mod catalog;
pub mod classify;
pub mod device;
pub mod evaluate;
pub mod ids;
pub mod plan;
pub mod policy;

/// Well-known Windows device setup class GUIDs (lower-case, with braces).
pub mod class_guids {
    /// Disk drives (`DiskDrive`).
    pub const DISK_DRIVE: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";
    /// CD/DVD drives (`CDROM`).
    pub const CDROM: &str = "{4d36e965-e325-11ce-bfc1-08002be10318}";
    /// USB controllers, hubs, composite parents and mass-storage function nodes (`USB`).
    pub const USB: &str = "{36fc9e60-c465-11cf-8056-444553540000}";
    /// USB devices with vendor-specific drivers (`USBDevice`).
    pub const USB_DEVICE: &str = "{88bae032-5a81-49f0-bc3d-a4ff138216d6}";
    /// Human interface devices (`HIDClass`).
    pub const HID: &str = "{745a17a0-74d3-11d0-b6fe-00a0c91efb8b}";
    /// Keyboards.
    pub const KEYBOARD: &str = "{4d36e96b-e325-11ce-bfc1-08002be10318}";
    /// Mice and other pointing devices.
    pub const MOUSE: &str = "{4d36e96f-e325-11ce-bfc1-08002be10318}";
    /// Printers.
    pub const PRINTER: &str = "{4d36e979-e325-11ce-bfc1-08002be10318}";
    /// Windows Portable Devices (MTP/PTP, and WPD views of removable volumes).
    pub const WPD: &str = "{eec5ad98-8080-425f-922a-dabf3de3f69a}";
    /// Storage volumes.
    pub const VOLUME: &str = "{71a27cdd-812a-11d0-bec7-08002be10318}";
    /// Storage controllers (includes UASP adapters).
    pub const SCSI_ADAPTER: &str = "{4d36e97b-e325-11ce-bfc1-08002be10318}";
}

/// Case-insensitive ASCII equality, the comparison Windows uses for PnP IDs.
#[must_use]
pub fn pnp_id_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
