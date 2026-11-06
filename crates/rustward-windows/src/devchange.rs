//! Platform-neutral device-change notification types.
//!
//! Device-change notifications are **telemetry**: they make the service
//! refresh its inventory sooner. They are not, and must never be used as,
//! an enforcement mechanism (a user-mode reaction always races the storage
//! stack).

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_NOTIFY_ACTION, CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED,
    CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED, CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED,
};

use crate::wide::utf16_until_nul;

/// Maximum device instance ID length in characters (`MAX_DEVICE_ID_LEN`).
pub const MAX_DEVICE_ID_LEN: usize = 200;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceChangeKind {
    /// A new devnode was enumerated.
    Enumerated,
    /// A devnode started (driver loaded).
    Started,
    /// A devnode was removed.
    Removed,
}

/// One device-change notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceChange {
    /// Kind.
    pub kind: DeviceChangeKind,
    /// Device instance ID as reported by Configuration Manager.
    pub instance_id: String,
}

/// Map a `CM_NOTIFY_ACTION` for a device-instance filter.
#[must_use]
pub fn kind_from_action(action: CM_NOTIFY_ACTION) -> Option<DeviceChangeKind> {
    match action {
        CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED => Some(DeviceChangeKind::Enumerated),
        CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED => Some(DeviceChangeKind::Started),
        CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED => Some(DeviceChangeKind::Removed),
        _ => None,
    }
}

/// Decode a notification from its action and the UTF-16 instance-ID
/// buffer that follows the event-data header. Returns `None` for actions
/// RustWard ignores and for empty or over-long IDs (fail-safe: the periodic
/// refresh still runs).
#[must_use]
pub fn decode_device_instance_event(
    action: CM_NOTIFY_ACTION,
    units: &[u16],
) -> Option<DeviceChange> {
    let kind = kind_from_action(action)?;
    let bounded = &units[..units.len().min(MAX_DEVICE_ID_LEN + 1)];
    let instance_id = utf16_until_nul(bounded);
    if instance_id.is_empty() || instance_id.chars().count() > MAX_DEVICE_ID_LEN {
        return None;
    }
    Some(DeviceChange { kind, instance_id })
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL, CM_NOTIFY_ACTION_DEVICEQUERYREMOVE,
    };

    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn decodes_instance_events() {
        let e = decode_device_instance_event(
            CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED,
            &w("USBSTOR\\Disk&Ven_SanDisk\\1&0"),
        )
        .unwrap();
        assert_eq!(e.kind, DeviceChangeKind::Enumerated);
        assert_eq!(e.instance_id, "USBSTOR\\Disk&Ven_SanDisk\\1&0");
        assert_eq!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED, &w("X"))
                .unwrap()
                .kind,
            DeviceChangeKind::Removed
        );
        assert_eq!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED, &w("X"))
                .unwrap()
                .kind,
            DeviceChangeKind::Started
        );
    }

    #[test]
    fn ignores_other_actions_and_bad_ids() {
        assert!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL, &w("X"))
                .is_none()
        );
        assert!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEQUERYREMOVE, &w("X")).is_none()
        );
        assert!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED, &[0]).is_none()
        );
        assert!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED, &[]).is_none()
        );
        let long: Vec<u16> = std::iter::repeat_n(u16::from(b'A'), 500).collect();
        assert!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED, &long)
                .is_none(),
            "IDs longer than MAX_DEVICE_ID_LEN are rejected"
        );
        let exact: Vec<u16> = std::iter::repeat_n(u16::from(b'A'), MAX_DEVICE_ID_LEN)
            .chain([0])
            .collect();
        assert!(
            decode_device_instance_event(CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED, &exact)
                .is_some()
        );
    }
}
