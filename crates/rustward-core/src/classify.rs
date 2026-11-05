//! Device classification.
//!
//! Classification looks at the enumerator, service, setup class, hardware
//! and compatible IDs, and the parent chain — never at the top-level USB
//! class alone. Composite devices are handled per function: a keyboard
//! interface and a storage interface on the same physical device are
//! classified independently.

use serde::{Deserialize, Serialize};

use crate::class_guids;
use crate::device::{DeviceRecord, SnapshotIndex};
use crate::ids::{InquiryIdentity, UsbVidPid, parse_inquiry_identity, parse_usb_vid_pid};

/// USB storage transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbStorageTransport {
    /// Bulk-Only Transport via `USBSTOR`.
    BulkOnly,
    /// USB Attached SCSI via `UASPStor` (enumerated as `SCSI\...`).
    Uasp,
    /// A disk below a USB device through some other driver stack.
    Unknown,
}

/// Non-storage peripheral kinds that must keep working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeripheralKind {
    /// Keyboard.
    Keyboard,
    /// Mouse / pointing device.
    Mouse,
    /// Other HID (or HID collection parent).
    Hid,
    /// Printer.
    Printer,
    /// USB hub or host controller.
    Hub,
    /// USB composite parent (`usbccgp`).
    CompositeParent,
    /// Any other USB function.
    Other,
}

/// Classification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceCategory {
    /// A disk exposed by a USB-attached device. **In scope** of the brand policy.
    UsbStorageDisk {
        /// Transport.
        transport: UsbStorageTransport,
    },
    /// USB storage of another SCSI type (CD-ROM, tape, changer…). Scope
    /// decision pending.
    UsbStorageOtherType {
        /// SCSI type string.
        device_type: String,
    },
    /// USB function node bound to a mass-storage driver (USBSTOR/UASPStor).
    /// The policy decision is made on its child disk.
    UsbStorageInterface,
    /// MTP/PTP/WPD device on USB (phones, cameras). Scope decision pending.
    UsbPortableDevice,
    /// A disk not below any USB device (internal SATA/NVMe, virtual
    /// disks), with a fully resolved parent chain. Out of scope; must never
    /// be touched.
    SystemOrNonUsbStorage,
    /// A disk whose parent chain is broken or unreadable, so neither USB
    /// nor internal attachment can be proven. **In scope** (fail-closed).
    StorageAttachmentUnknown,
    /// A non-storage peripheral or USB infrastructure.
    Peripheral {
        /// Kind.
        peripheral: PeripheralKind,
    },
    /// Anything else.
    Other,
}

/// How a category relates to the storage policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageScope {
    /// Brand policy applies.
    InScope,
    /// Storage-like, but whether/how to control it is an open scope
    /// decision (documented in DEVICE-CLASSIFICATION.md).
    ScopeDecisionPending,
    /// Not subject to the policy.
    NotInScope,
}

impl DeviceCategory {
    /// Scope of this category.
    #[must_use]
    pub fn scope(&self) -> StorageScope {
        match self {
            Self::UsbStorageDisk { .. } | Self::StorageAttachmentUnknown => StorageScope::InScope,
            Self::UsbStorageOtherType { .. } | Self::UsbPortableDevice => {
                StorageScope::ScopeDecisionPending
            }
            Self::UsbStorageInterface
            | Self::SystemOrNonUsbStorage
            | Self::Peripheral { .. }
            | Self::Other => StorageScope::NotInScope,
        }
    }
}

/// The nearest USB device (with a VID) above or at a device node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbAncestor {
    /// Instance ID of that USB node.
    pub instance_id: String,
    /// Parsed VID/PID.
    pub ids: UsbVidPid,
    /// Its function driver service.
    pub service: Option<String>,
}

/// Full classification of one device node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    /// Category.
    pub category: DeviceCategory,
    /// Nearest USB ancestor (or self).
    pub usb_ancestor: Option<UsbAncestor>,
    /// INQUIRY identity, for storage nodes.
    pub inquiry: Option<InquiryIdentity>,
}

fn find_usb_ancestor(index: &SnapshotIndex<'_>, device: &DeviceRecord) -> Option<UsbAncestor> {
    std::iter::once(device)
        .chain(index.ancestors(device))
        .find_map(|d| {
            if d.enumerator_name() != "USB" {
                return None;
            }
            parse_usb_vid_pid(&d.instance_id)
                .or_else(|| d.hardware_ids.iter().find_map(|h| parse_usb_vid_pid(h)))
                .map(|ids| UsbAncestor {
                    instance_id: d.instance_id.clone(),
                    ids,
                    service: d.service.clone(),
                })
        })
}

fn is_disk_like(device_type: &str) -> bool {
    crate::ids::is_block_storage_type(device_type)
}

/// Classify one device within its snapshot.
#[must_use]
pub fn classify(index: &SnapshotIndex<'_>, device: &DeviceRecord) -> Classification {
    let usb_ancestor = find_usb_ancestor(index, device);
    let attachment_proven = device.parent_instance_id.is_some() && index.ancestry_complete(device);
    let non_usb_storage = || {
        if attachment_proven {
            DeviceCategory::SystemOrNonUsbStorage
        } else {
            DeviceCategory::StorageAttachmentUnknown
        }
    };
    let enumerator = device.enumerator_name();
    let inquiry = match enumerator.as_str() {
        "USBSTOR" | "SCSI" => parse_inquiry_identity(&device.hardware_ids),
        _ => None,
    };

    let category = match enumerator.as_str() {
        "USBSTOR" => {
            let ty = inquiry.as_ref().map(|i| i.device_type.clone()).or_else(|| {
                device
                    .compatible_ids
                    .iter()
                    .find_map(|c| {
                        c.get(8..)
                            .filter(|_| c.to_ascii_uppercase().starts_with("USBSTOR\\"))
                    })
                    .filter(|t| !t.eq_ignore_ascii_case("RAW"))
                    .map(str::to_owned)
            });
            match ty {
                Some(t) if !is_disk_like(&t) => {
                    DeviceCategory::UsbStorageOtherType { device_type: t }
                }
                // Unknown type under USBSTOR is treated as a disk: fail closed.
                _ => DeviceCategory::UsbStorageDisk {
                    transport: UsbStorageTransport::BulkOnly,
                },
            }
        }
        "SCSI" if usb_ancestor.is_some() => {
            let ty = inquiry.as_ref().map(|i| i.device_type.clone());
            let uasp = usb_ancestor
                .as_ref()
                .and_then(|a| a.service.as_deref())
                .is_some_and(|s| s.eq_ignore_ascii_case("UASPStor"));
            match ty {
                Some(t) if !is_disk_like(&t) => {
                    DeviceCategory::UsbStorageOtherType { device_type: t }
                }
                _ => DeviceCategory::UsbStorageDisk {
                    transport: if uasp {
                        UsbStorageTransport::Uasp
                    } else {
                        UsbStorageTransport::Unknown
                    },
                },
            }
        }
        _ if device.class_is(class_guids::DISK_DRIVE) => {
            if usb_ancestor.is_some() {
                DeviceCategory::UsbStorageDisk {
                    transport: UsbStorageTransport::Unknown,
                }
            } else {
                non_usb_storage()
            }
        }
        "SCSI" => non_usb_storage(),
        "USB" => {
            if device.service_is("USBSTOR") || device.service_is("UASPStor") {
                DeviceCategory::UsbStorageInterface
            } else if device.class_is(class_guids::WPD) {
                DeviceCategory::UsbPortableDevice
            } else if device.service_is("usbccgp") {
                DeviceCategory::Peripheral {
                    peripheral: PeripheralKind::CompositeParent,
                }
            } else if device.instance_id.to_ascii_uppercase().contains("ROOT_HUB")
                || device.service_is("USBHUB3")
                || device.service_is("usbhub")
            {
                DeviceCategory::Peripheral {
                    peripheral: PeripheralKind::Hub,
                }
            } else if device.class_is(class_guids::HID) {
                DeviceCategory::Peripheral {
                    peripheral: PeripheralKind::Hid,
                }
            } else if device.class_is(class_guids::PRINTER) || device.service_is("usbprint") {
                DeviceCategory::Peripheral {
                    peripheral: PeripheralKind::Printer,
                }
            } else {
                DeviceCategory::Peripheral {
                    peripheral: PeripheralKind::Other,
                }
            }
        }
        _ if device.class_is(class_guids::KEYBOARD) => DeviceCategory::Peripheral {
            peripheral: PeripheralKind::Keyboard,
        },
        _ if device.class_is(class_guids::MOUSE) => DeviceCategory::Peripheral {
            peripheral: PeripheralKind::Mouse,
        },
        "HID" => DeviceCategory::Peripheral {
            peripheral: PeripheralKind::Hid,
        },
        _ if device.class_is(class_guids::PRINTER) || enumerator == "USBPRINT" => {
            DeviceCategory::Peripheral {
                peripheral: PeripheralKind::Printer,
            }
        }
        _ if device.class_is(class_guids::CDROM) && usb_ancestor.is_some() => {
            DeviceCategory::UsbStorageOtherType {
                device_type: "CdRom".into(),
            }
        }
        _ => DeviceCategory::Other,
    };

    Classification {
        category,
        usb_ancestor,
        inquiry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceSnapshot, SnapshotSource};

    fn rec(id: &str, parent: Option<&str>) -> DeviceRecord {
        DeviceRecord {
            instance_id: id.into(),
            parent_instance_id: parent.map(Into::into),
            ..DeviceRecord::default()
        }
    }

    fn snapshot(devices: Vec<DeviceRecord>) -> DeviceSnapshot {
        DeviceSnapshot {
            schema_version: 1,
            source: SnapshotSource::Synthetic {
                description: "unit".into(),
            },
            devices,
        }
    }

    #[test]
    fn usbstor_disk_without_identity_is_still_in_scope() {
        let mut usb = rec("USB\\VID_0781&PID_5581\\SER", None);
        usb.service = Some("USBSTOR".into());
        let disk = rec(
            "USBSTOR\\Disk&Ven_&Prod_\\SER&0",
            Some("USB\\VID_0781&PID_5581\\SER"),
        );
        let s = snapshot(vec![usb, disk]);
        let idx = s.index();
        let c = classify(&idx, idx.get("USBSTOR\\Disk&Ven_&Prod_\\SER&0").unwrap());
        assert_eq!(c.category.scope(), StorageScope::InScope);
        assert!(c.inquiry.is_none());
        assert_eq!(c.usb_ancestor.unwrap().ids.vid, 0x0781);
        let i = classify(&idx, idx.get("USB\\VID_0781&PID_5581\\SER").unwrap());
        assert_eq!(i.category, DeviceCategory::UsbStorageInterface);
    }

    #[test]
    fn scsi_disk_without_usb_parent_is_system_storage() {
        let mut d = rec(
            "SCSI\\Disk&Ven_Samsung&Prod_SSD\\4&1&0&000000",
            Some("PCI\\VEN_8086&DEV_A352\\3&1"),
        );
        d.class_guid = Some(class_guids::DISK_DRIVE.into());
        let s = snapshot(vec![d, rec("PCI\\VEN_8086&DEV_A352\\3&1", None)]);
        let idx = s.index();
        let c = classify(
            &idx,
            idx.get("SCSI\\Disk&Ven_Samsung&Prod_SSD\\4&1&0&000000")
                .unwrap(),
        );
        assert_eq!(c.category, DeviceCategory::SystemOrNonUsbStorage);
        assert_eq!(c.category.scope(), StorageScope::NotInScope);
    }

    #[test]
    fn storage_with_broken_parent_chain_fails_closed() {
        let mut orphan = rec(
            "SCSI\\Disk&Ven_Samsung&Prod_X\\9&1&0&000000",
            Some("USB\\VID_0BC2&PID_2344\\GONE"),
        );
        orphan.class_guid = Some(class_guids::DISK_DRIVE.into());
        let mut parentless = rec("SCSI\\Disk&Ven_Seagate&Prod_Y\\9&2&0&000000", None);
        parentless.class_guid = Some(class_guids::DISK_DRIVE.into());
        let s = snapshot(vec![orphan, parentless]);
        let idx = s.index();
        for d in &s.devices {
            let c = classify(&idx, d);
            assert_eq!(
                c.category,
                DeviceCategory::StorageAttachmentUnknown,
                "{}",
                d.instance_id
            );
            assert_eq!(c.category.scope(), StorageScope::InScope);
        }
    }

    #[test]
    fn enumerator_beats_misleading_class_metadata() {
        // A USBSTOR devnode that claims the Keyboard class is still storage.
        let mut fake_kbd = rec("USBSTOR\\Disk&Ven_ACME\\1&0", None);
        fake_kbd.class_guid = Some(class_guids::KEYBOARD.into());
        // A HID-enumerated node that claims DiskDrive under USB fails closed.
        let usb = rec("USB\\VID_1234&PID_0001\\X", None);
        let mut fake_disk = rec(
            "HID\\VID_1234&PID_0001\\1",
            Some("USB\\VID_1234&PID_0001\\X"),
        );
        fake_disk.class_guid = Some(class_guids::DISK_DRIVE.into());
        // A plain keyboard is never storage.
        let mut kbd = rec(
            "HID\\VID_046D&PID_C31C\\2",
            Some("USB\\VID_1234&PID_0001\\X"),
        );
        kbd.class_guid = Some(class_guids::KEYBOARD.into());
        let s = snapshot(vec![fake_kbd, usb, fake_disk, kbd]);
        let idx = s.index();
        let cat = |id: &str| classify(&idx, idx.get(id).unwrap()).category;
        assert!(matches!(
            cat("USBSTOR\\Disk&Ven_ACME\\1&0"),
            DeviceCategory::UsbStorageDisk { .. }
        ));
        assert!(matches!(
            cat("HID\\VID_1234&PID_0001\\1"),
            DeviceCategory::UsbStorageDisk { .. }
        ));
        assert_eq!(
            cat("HID\\VID_046D&PID_C31C\\2"),
            DeviceCategory::Peripheral {
                peripheral: PeripheralKind::Keyboard
            }
        );
    }

    #[test]
    fn disk_class_below_usb_with_unknown_stack_fails_closed_into_scope() {
        let usb = rec("USB\\VID_1234&PID_0001\\X", None);
        let mut d = rec("VENDORBUS\\DISK\\1", Some("USB\\VID_1234&PID_0001\\X"));
        d.class_guid = Some(class_guids::DISK_DRIVE.into());
        let s = snapshot(vec![usb, d]);
        let idx = s.index();
        let c = classify(&idx, idx.get("VENDORBUS\\DISK\\1").unwrap());
        assert_eq!(
            c.category,
            DeviceCategory::UsbStorageDisk {
                transport: UsbStorageTransport::Unknown
            }
        );
    }
}
