//! Platform-neutral enumeration engine.
//!
//! The SetupAPI backend implements [`DeviceSource`]; all buffer-growth,
//! error-mapping and per-device fault-isolation logic lives here so it can be
//! tested with synthetic failure scenarios on any host.

use rustward_core::device::DeviceRecord;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
};

use crate::InventoryError;
use crate::wide::{PropValue, decode_property};

/// Maximum attempts when a property grows between the size query and the read.
pub const PROPERTY_READ_ATTEMPTS: usize = 3;

/// Upper bound for a single property buffer (1 MiB). Real PnP properties are
/// a few KiB; anything larger is treated as corrupt.
pub const MAX_PROPERTY_BYTES: usize = 1 << 20;

/// Device properties RustWard reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropKey {
    /// `DEVPKEY_Device_InstanceId`
    InstanceId,
    /// `DEVPKEY_Device_HardwareIds`
    HardwareIds,
    /// `DEVPKEY_Device_CompatibleIds`
    CompatibleIds,
    /// `DEVPKEY_Device_ClassGuid`
    ClassGuid,
    /// `DEVPKEY_Device_Class`
    Class,
    /// `DEVPKEY_Device_EnumeratorName`
    EnumeratorName,
    /// `DEVPKEY_Device_Service`
    Service,
    /// `DEVPKEY_Device_Manufacturer`
    Manufacturer,
    /// `DEVPKEY_Device_FriendlyName`
    FriendlyName,
    /// `DEVPKEY_Device_DeviceDesc`
    DeviceDesc,
    /// `DEVPKEY_Device_BusReportedDeviceDesc`
    BusReportedDeviceDesc,
    /// `DEVPKEY_Device_Parent`
    Parent,
    /// `DEVPKEY_Device_IsPresent`
    IsPresent,
    /// `DEVPKEY_Device_ProblemCode`
    ProblemCode,
}

impl PropKey {
    /// Name used in warnings.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InstanceId => "InstanceId",
            Self::HardwareIds => "HardwareIds",
            Self::CompatibleIds => "CompatibleIds",
            Self::ClassGuid => "ClassGuid",
            Self::Class => "Class",
            Self::EnumeratorName => "EnumeratorName",
            Self::Service => "Service",
            Self::Manufacturer => "Manufacturer",
            Self::FriendlyName => "FriendlyName",
            Self::DeviceDesc => "DeviceDesc",
            Self::BusReportedDeviceDesc => "BusReportedDeviceDesc",
            Self::Parent => "Parent",
            Self::IsPresent => "IsPresent",
            Self::ProblemCode => "ProblemCode",
        }
    }
}

/// Result of one raw property read attempt (mirrors the Win32 contract of
/// `SetupDiGetDevicePropertyW`: on failure `required` may be set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawRead {
    /// Success; `len` bytes of `buf` were written.
    Ok {
        /// `DEVPROPTYPE`.
        prop_type: u32,
        /// Bytes written.
        len: u32,
    },
    /// Failure with a Win32 error code.
    Err {
        /// `GetLastError()`.
        code: u32,
        /// Required size reported by the API (0 if none).
        required: u32,
    },
}

/// A source of device nodes (SetupAPI in production, mocks in tests).
pub trait DeviceSource {
    /// Opaque per-device handle.
    type Device;
    /// Device at `index`; `Ok(None)` when there are no more; `Err(code)` on failure.
    fn device_at(&mut self, index: u32) -> Result<Option<Self::Device>, u32>;
    /// One raw property read attempt into `buf` (may be empty).
    fn read_property(&self, device: &Self::Device, key: PropKey, buf: &mut [u8]) -> RawRead;
}

/// Read one property with buffer growth. `Ok(None)` = property absent.
pub fn get_property<S: DeviceSource>(
    source: &S,
    device: &S::Device,
    key: PropKey,
) -> Result<Option<PropValue>, InventoryError> {
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..PROPERTY_READ_ATTEMPTS {
        match source.read_property(device, key, &mut buf) {
            RawRead::Ok { prop_type, len } => {
                let used = usize::try_from(len).unwrap_or(usize::MAX).min(buf.len());
                return Ok(Some(decode_property(prop_type, &buf[..used])));
            }
            RawRead::Err { code, .. } if code == ERROR_NOT_FOUND || code == ERROR_INVALID_DATA => {
                return Ok(None);
            }
            RawRead::Err {
                code: ERROR_INSUFFICIENT_BUFFER,
                required,
            } => {
                let needed =
                    usize::try_from(required).map_err(|_| InventoryError::BufferTooLarge)?;
                if needed > MAX_PROPERTY_BYTES {
                    return Err(InventoryError::BufferTooLarge);
                }
                if needed == 0 || needed <= buf.len() {
                    return Err(InventoryError::PropertySizeInconsistent);
                }
                buf = vec![0u8; needed];
            }
            RawRead::Err { code, .. } => {
                return Err(InventoryError::Win32 {
                    api: "SetupDiGetDevicePropertyW",
                    code,
                });
            }
        }
    }
    Err(InventoryError::PropertyUnstable)
}

/// Read a full device record. Only the instance ID is mandatory; every other
/// property failure becomes a warning and `None`, so one unreadable field
/// (common on non-present devices) never drops the device.
pub fn read_device<S: DeviceSource>(
    source: &S,
    device: &S::Device,
    warnings: &mut Vec<String>,
) -> Result<DeviceRecord, InventoryError> {
    let instance_id = get_property(source, device, PropKey::InstanceId)?
        .and_then(PropValue::into_string)
        .ok_or(InventoryError::MissingInstanceId)?;
    let mut prop = |key: PropKey| match get_property(source, device, key) {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!(
                "{instance_id}: property {} unreadable: {e}",
                key.name()
            ));
            None
        }
    };
    let hardware_ids = prop(PropKey::HardwareIds)
        .map(PropValue::into_string_list)
        .unwrap_or_default();
    let compatible_ids = prop(PropKey::CompatibleIds)
        .map(PropValue::into_string_list)
        .unwrap_or_default();
    let class_guid = prop(PropKey::ClassGuid).and_then(PropValue::into_guid);
    let class_name = prop(PropKey::Class).and_then(PropValue::into_string);
    let enumerator = prop(PropKey::EnumeratorName).and_then(PropValue::into_string);
    let service = prop(PropKey::Service).and_then(PropValue::into_string);
    let inf_manufacturer = prop(PropKey::Manufacturer).and_then(PropValue::into_string);
    let friendly_name = prop(PropKey::FriendlyName).and_then(PropValue::into_string);
    let description = prop(PropKey::DeviceDesc).and_then(PropValue::into_string);
    let bus_reported_description =
        prop(PropKey::BusReportedDeviceDesc).and_then(PropValue::into_string);
    let parent_instance_id = prop(PropKey::Parent).and_then(PropValue::into_string);
    let present = prop(PropKey::IsPresent).and_then(PropValue::into_bool);
    let problem_code = prop(PropKey::ProblemCode).and_then(PropValue::into_u32);
    Ok(DeviceRecord {
        instance_id,
        hardware_ids,
        compatible_ids,
        class_guid,
        class_name,
        enumerator,
        service,
        inf_manufacturer,
        friendly_name,
        description,
        bus_reported_description,
        parent_instance_id,
        present,
        problem_code,
    })
}

/// Hard cap on enumerated devices (guards against a runaway source).
pub const MAX_DEVICES: u32 = 100_000;

/// Enumerate every device. An enumeration-level failure aborts with an
/// error; a per-device failure skips that device with a warning.
pub fn enumerate_all<S: DeviceSource>(
    source: &mut S,
) -> Result<(Vec<DeviceRecord>, Vec<String>), InventoryError> {
    let mut devices = Vec::new();
    let mut warnings = Vec::new();
    for index in 0..MAX_DEVICES {
        let device = match source.device_at(index) {
            Ok(Some(d)) => d,
            Ok(None) => return Ok((devices, warnings)),
            Err(code) if code == ERROR_NO_MORE_ITEMS => return Ok((devices, warnings)),
            Err(code) => {
                return Err(InventoryError::Win32 {
                    api: "SetupDiEnumDeviceInfo",
                    code,
                });
            }
        };
        match read_device(source, &device, &mut warnings) {
            Ok(d) => devices.push(d),
            Err(e) => warnings.push(format!("device index {index} skipped: {e}")),
        }
    }
    Err(InventoryError::TooManyDevices)
}

/// Owns a handle and closes it exactly once when dropped, including during
/// unwinding. `close` must be safe to call with the stored handle.
#[derive(Debug)]
pub struct HandleGuard<T: Copy> {
    handle: T,
    close: fn(T),
}

impl<T: Copy> HandleGuard<T> {
    /// Take ownership of `handle`.
    pub fn new(handle: T, close: fn(T)) -> Self {
        Self { handle, close }
    }

    /// The raw handle (still owned by the guard).
    #[must_use]
    pub fn get(&self) -> T {
        self.handle
    }
}

impl<T: Copy> Drop for HandleGuard<T> {
    fn drop(&mut self) {
        (self.close)(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows_sys::Win32::Devices::Properties::{
        DEVPROP_TYPE_BOOLEAN, DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING_LIST,
    };
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    use super::*;

    /// Scripted property behaviour.
    #[derive(Clone)]
    enum Prop {
        Value(u32, Vec<u8>),
        Fail(u32),
        /// Reports a larger size on every attempt.
        AlwaysGrowing,
    }

    #[derive(Default)]
    struct Mock {
        devices: Vec<HashMap<PropKey, Prop>>,
        enum_error_at: Option<(u32, u32)>,
    }

    fn wide(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn multi(v: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = v.iter().flat_map(|s| wide(s)).collect();
        out.extend([0, 0]);
        out
    }

    impl DeviceSource for Mock {
        type Device = usize;
        fn device_at(&mut self, index: u32) -> Result<Option<usize>, u32> {
            if let Some((at, code)) = self.enum_error_at
                && at == index
            {
                return Err(code);
            }
            let i = index as usize;
            Ok((i < self.devices.len()).then_some(i))
        }
        fn read_property(&self, device: &usize, key: PropKey, buf: &mut [u8]) -> RawRead {
            match self.devices[*device].get(&key) {
                None => RawRead::Err {
                    code: ERROR_NOT_FOUND,
                    required: 0,
                },
                Some(Prop::Fail(code)) => RawRead::Err {
                    code: *code,
                    required: 0,
                },
                Some(Prop::AlwaysGrowing) => RawRead::Err {
                    code: ERROR_INSUFFICIENT_BUFFER,
                    required: u32::try_from(buf.len()).unwrap() + 16,
                },
                Some(Prop::Value(ty, bytes)) => {
                    if buf.len() < bytes.len() {
                        RawRead::Err {
                            code: ERROR_INSUFFICIENT_BUFFER,
                            required: u32::try_from(bytes.len()).unwrap(),
                        }
                    } else {
                        buf[..bytes.len()].copy_from_slice(bytes);
                        RawRead::Ok {
                            prop_type: *ty,
                            len: u32::try_from(bytes.len()).unwrap(),
                        }
                    }
                }
            }
        }
    }

    fn device(id: &str) -> HashMap<PropKey, Prop> {
        HashMap::from([(
            PropKey::InstanceId,
            Prop::Value(DEVPROP_TYPE_STRING, wide(id)),
        )])
    }

    #[test]
    fn reads_full_record_with_buffer_growth() {
        let mut d = device("USBSTOR\\Disk&Ven_SanDisk\\1&0");
        d.insert(
            PropKey::HardwareIds,
            Prop::Value(
                DEVPROP_TYPE_STRING_LIST,
                multi(&["USBSTOR\\DiskSanDisk_", "GenDisk"]),
            ),
        );
        d.insert(
            PropKey::IsPresent,
            Prop::Value(DEVPROP_TYPE_BOOLEAN, vec![0]),
        );
        let mut m = Mock {
            devices: vec![d],
            ..Mock::default()
        };
        let (devs, warnings) = enumerate_all(&mut m).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(devs[0].hardware_ids, ["USBSTOR\\DiskSanDisk_", "GenDisk"]);
        assert_eq!(devs[0].present, Some(false));
        assert_eq!(
            devs[0].parent_instance_id, None,
            "absent property is None, not an error"
        );
    }

    #[test]
    fn missing_instance_id_skips_only_that_device() {
        let mut m = Mock {
            devices: vec![HashMap::new(), device("A")],
            ..Mock::default()
        };
        let (devs, warnings) = enumerate_all(&mut m).unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].instance_id, "A");
        assert!(warnings[0].contains("index 0 skipped"));
    }

    #[test]
    fn property_errors_become_field_warnings() {
        let mut d = device("X");
        d.insert(PropKey::Parent, Prop::Fail(ERROR_ACCESS_DENIED));
        d.insert(PropKey::HardwareIds, Prop::AlwaysGrowing);
        let mut m = Mock {
            devices: vec![d],
            ..Mock::default()
        };
        let (devs, warnings) = enumerate_all(&mut m).unwrap();
        assert_eq!(devs.len(), 1, "device kept despite unreadable fields");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Parent") && w.contains("error 5"))
        );
        assert!(warnings.iter().any(|w| w.contains("HardwareIds")));
    }

    #[test]
    fn invalid_data_and_not_found_mean_absent() {
        let mut d = device("X");
        d.insert(PropKey::Service, Prop::Fail(ERROR_INVALID_DATA));
        let m = Mock {
            devices: vec![d],
            ..Mock::default()
        };
        assert_eq!(get_property(&m, &0, PropKey::Service).unwrap(), None);
        assert_eq!(get_property(&m, &0, PropKey::Class).unwrap(), None);
    }

    #[test]
    fn unstable_and_oversized_properties_are_errors() {
        let mut d = device("X");
        d.insert(PropKey::FriendlyName, Prop::AlwaysGrowing);
        d.insert(
            PropKey::DeviceDesc,
            Prop::Value(DEVPROP_TYPE_STRING, vec![0; MAX_PROPERTY_BYTES + 2]),
        );
        let m = Mock {
            devices: vec![d],
            ..Mock::default()
        };
        assert!(matches!(
            get_property(&m, &0, PropKey::FriendlyName),
            Err(InventoryError::PropertyUnstable)
        ));
        assert!(matches!(
            get_property(&m, &0, PropKey::DeviceDesc),
            Err(InventoryError::BufferTooLarge)
        ));
    }

    #[test]
    fn enumeration_failure_propagates_win32_error() {
        let mut m = Mock {
            devices: vec![device("A"), device("B")],
            enum_error_at: Some((1, ERROR_ACCESS_DENIED)),
        };
        match enumerate_all(&mut m) {
            Err(InventoryError::Win32 { api, code }) => {
                assert_eq!(api, "SetupDiEnumDeviceInfo");
                assert_eq!(code, ERROR_ACCESS_DENIED);
            }
            other => panic!("expected Win32 error, got {other:?}"),
        }
    }

    #[test]
    fn no_more_items_ends_enumeration_cleanly() {
        let mut m = Mock {
            devices: vec![device("A"), device("B")],
            enum_error_at: Some((1, ERROR_NO_MORE_ITEMS)),
        };
        let (devs, _) = enumerate_all(&mut m).unwrap();
        assert_eq!(devs.len(), 1);
    }

    static CLOSED: AtomicUsize = AtomicUsize::new(0);
    fn count_close(_: isize) {
        CLOSED.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn handle_guard_closes_exactly_once_including_on_panic() {
        CLOSED.store(0, Ordering::SeqCst);
        {
            let g = HandleGuard::new(7isize, count_close);
            assert_eq!(g.get(), 7);
        }
        assert_eq!(CLOSED.load(Ordering::SeqCst), 1);
        let r = std::panic::catch_unwind(|| {
            let _g = HandleGuard::new(8isize, count_close);
            panic!("simulated failure while the handle is open");
        });
        assert!(r.is_err());
        assert_eq!(CLOSED.load(Ordering::SeqCst), 2);
    }
}
