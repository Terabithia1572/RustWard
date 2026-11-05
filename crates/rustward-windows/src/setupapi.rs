//! SetupAPI backend. READ-ONLY.
//!
//! Only the functions listed in [`crate::WIN32_API_ALLOWLIST`] may be
//! imported here; a unit test enforces this. No function in this module
//! changes device state, driver state, the registry, or policy. All
//! enumeration logic lives in [`crate::engine`]; this file is only the thin
//! FFI layer.

use std::ptr;

use rustward_core::device::DeviceRecord;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDevicePropertyW,
};
use windows_sys::Win32::Devices::Properties::{
    DEVPKEY_Device_BusReportedDeviceDesc, DEVPKEY_Device_Class, DEVPKEY_Device_ClassGuid,
    DEVPKEY_Device_CompatibleIds, DEVPKEY_Device_DeviceDesc, DEVPKEY_Device_EnumeratorName,
    DEVPKEY_Device_FriendlyName, DEVPKEY_Device_HardwareIds, DEVPKEY_Device_InstanceId,
    DEVPKEY_Device_IsPresent, DEVPKEY_Device_Manufacturer, DEVPKEY_Device_Parent,
    DEVPKEY_Device_ProblemCode, DEVPKEY_Device_Service, DEVPROPTYPE,
};
use windows_sys::Win32::Foundation::{DEVPROPKEY, ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows_sys::core::GUID;

use crate::engine::{DeviceSource, HandleGuard, PropKey, RawRead, enumerate_all};
use crate::{EnumerationScope, InventoryError};

/// `INVALID_HANDLE_VALUE` as an `HDEVINFO`.
const INVALID_HDEVINFO: HDEVINFO = -1;

fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

/// Close function for [`HandleGuard`]. Only ever called by a guard that was
/// constructed from a handle already checked against `INVALID_HDEVINFO`.
fn destroy_list(handle: HDEVINFO) {
    // SAFETY: `handle` comes from a successful SetupDiGetClassDevsW call and
    // the owning HandleGuard calls this exactly once.
    unsafe {
        SetupDiDestroyDeviceInfoList(handle);
    }
}

fn devpkey(key: PropKey) -> &'static DEVPROPKEY {
    match key {
        PropKey::InstanceId => &DEVPKEY_Device_InstanceId,
        PropKey::HardwareIds => &DEVPKEY_Device_HardwareIds,
        PropKey::CompatibleIds => &DEVPKEY_Device_CompatibleIds,
        PropKey::ClassGuid => &DEVPKEY_Device_ClassGuid,
        PropKey::Class => &DEVPKEY_Device_Class,
        PropKey::EnumeratorName => &DEVPKEY_Device_EnumeratorName,
        PropKey::Service => &DEVPKEY_Device_Service,
        PropKey::Manufacturer => &DEVPKEY_Device_Manufacturer,
        PropKey::FriendlyName => &DEVPKEY_Device_FriendlyName,
        PropKey::DeviceDesc => &DEVPKEY_Device_DeviceDesc,
        PropKey::BusReportedDeviceDesc => &DEVPKEY_Device_BusReportedDeviceDesc,
        PropKey::Parent => &DEVPKEY_Device_Parent,
        PropKey::IsPresent => &DEVPKEY_Device_IsPresent,
        PropKey::ProblemCode => &DEVPKEY_Device_ProblemCode,
    }
}

/// A device information set as a [`DeviceSource`].
struct SetupApiSource {
    list: HandleGuard<HDEVINFO>,
}

impl SetupApiSource {
    fn open(scope: EnumerationScope) -> Result<Self, InventoryError> {
        let flags = match scope {
            EnumerationScope::PresentOnly => DIGCF_ALLCLASSES | DIGCF_PRESENT,
            EnumerationScope::IncludeNonPresent => DIGCF_ALLCLASSES,
        };
        // SAFETY: a null class GUID and null enumerator are permitted with
        // DIGCF_ALLCLASSES; a null parent window is permitted. No pointer is
        // retained by the callee.
        let handle =
            unsafe { SetupDiGetClassDevsW(ptr::null(), ptr::null(), ptr::null_mut(), flags) };
        if handle == INVALID_HDEVINFO {
            return Err(InventoryError::Win32 {
                api: "SetupDiGetClassDevsW",
                code: last_error(),
            });
        }
        Ok(Self {
            list: HandleGuard::new(handle, destroy_list),
        })
    }
}

impl DeviceSource for SetupApiSource {
    type Device = SP_DEVINFO_DATA;

    fn device_at(&mut self, index: u32) -> Result<Option<SP_DEVINFO_DATA>, u32> {
        let mut data = SP_DEVINFO_DATA {
            // The struct is a few dozen bytes; the conversion cannot fail.
            cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>()).unwrap_or(u32::MAX),
            ClassGuid: GUID::from_u128(0),
            DevInst: 0,
            Reserved: 0,
        };
        // SAFETY: the list handle is live (owned by the guard); `data` is a
        // properly sized, writable SP_DEVINFO_DATA with cbSize set.
        let ok = unsafe { SetupDiEnumDeviceInfo(self.list.get(), index, &mut data) };
        if ok == 0 {
            Err(last_error())
        } else {
            Ok(Some(data))
        }
    }

    fn read_property(&self, device: &SP_DEVINFO_DATA, key: PropKey, buf: &mut [u8]) -> RawRead {
        let mut prop_type: DEVPROPTYPE = 0;
        let mut required: u32 = 0;
        let Ok(buf_len) = u32::try_from(buf.len()) else {
            return RawRead::Err {
                code: ERROR_INSUFFICIENT_BUFFER,
                required: 0,
            };
        };
        let buf_ptr = if buf.is_empty() {
            ptr::null_mut()
        } else {
            buf.as_mut_ptr()
        };
        // SAFETY: the list handle is live and `device` was filled by
        // SetupDiEnumDeviceInfo for that list. The key, `prop_type` and
        // `required` pointers are valid for the call. `buf_ptr` is null with
        // size 0, or points to `buf_len` writable bytes borrowed from `buf`.
        let ok = unsafe {
            SetupDiGetDevicePropertyW(
                self.list.get(),
                device,
                devpkey(key),
                &mut prop_type,
                buf_ptr,
                buf_len,
                &mut required,
                0,
            )
        };
        if ok == 0 {
            RawRead::Err {
                code: last_error(),
                required,
            }
        } else {
            RawRead::Ok {
                prop_type,
                len: required.min(buf_len),
            }
        }
    }
}

/// Enumerate all device nodes (read-only).
pub(crate) fn enumerate(
    scope: EnumerationScope,
) -> Result<(Vec<DeviceRecord>, Vec<String>), InventoryError> {
    let mut source = SetupApiSource::open(scope)?;
    enumerate_all(&mut source)
}
