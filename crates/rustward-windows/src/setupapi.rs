//! SetupAPI backend. READ-ONLY.
//!
//! Only the functions listed in [`crate::WIN32_API_ALLOWLIST`] may be
//! imported here; a unit test enforces this. No function in this module
//! changes device state, driver state, the registry, or policy.

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
use windows_sys::Win32::Foundation::{
    DEVPROPKEY, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_NOT_FOUND, GetLastError,
};
use windows_sys::core::GUID;

use crate::wide::{PropValue, decode_property};
use crate::{EnumerationScope, InventoryError};

/// `INVALID_HANDLE_VALUE` as an `HDEVINFO`.
const INVALID_HDEVINFO: HDEVINFO = -1;

/// Maximum attempts when a property grows between the size query and the read.
const PROPERTY_READ_ATTEMPTS: usize = 3;

/// Owned device information set; destroyed exactly once on drop.
struct DevInfoList(HDEVINFO);

impl Drop for DevInfoList {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by a successful SetupDiGetClassDevsW
        // call (checked against INVALID_HDEVINFO before construction) and is
        // owned exclusively by this value, so it is destroyed exactly once.
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

fn empty_devinfo_data() -> SP_DEVINFO_DATA {
    SP_DEVINFO_DATA {
        // The struct is a few dozen bytes; the cast cannot truncate.
        cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>()).unwrap_or(u32::MAX),
        ClassGuid: GUID::from_u128(0),
        DevInst: 0,
        Reserved: 0,
    }
}

/// Read one device property. `Ok(None)` when the device has no such property.
fn get_property(
    list: &DevInfoList,
    data: &SP_DEVINFO_DATA,
    key: &DEVPROPKEY,
) -> Result<Option<PropValue>, InventoryError> {
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..PROPERTY_READ_ATTEMPTS {
        let mut prop_type: DEVPROPTYPE = 0;
        let mut required: u32 = 0;
        let buf_len = u32::try_from(buf.len()).map_err(|_| InventoryError::BufferTooLarge)?;
        let buf_ptr = if buf.is_empty() {
            ptr::null_mut()
        } else {
            buf.as_mut_ptr()
        };
        // SAFETY: `list.0` is a live device information set and `data` was
        // filled by SetupDiEnumDeviceInfo for that set. `key`, `prop_type`
        // and `required` are valid for the duration of the call. `buf_ptr`
        // is either null with size 0 or points to `buf_len` writable bytes
        // owned by `buf`, which outlives the call.
        let ok = unsafe {
            SetupDiGetDevicePropertyW(
                list.0,
                data,
                key,
                &mut prop_type,
                buf_ptr,
                buf_len,
                &mut required,
                0,
            )
        };
        if ok != 0 {
            let used = usize::try_from(required)
                .unwrap_or(buf.len())
                .min(buf.len());
            return Ok(Some(decode_property(prop_type, &buf[..used])));
        }
        match last_error() {
            ERROR_NOT_FOUND | ERROR_INVALID_DATA => return Ok(None),
            ERROR_INSUFFICIENT_BUFFER => {
                let needed =
                    usize::try_from(required).map_err(|_| InventoryError::BufferTooLarge)?;
                buf = vec![0u8; needed];
            }
            code => {
                return Err(InventoryError::Win32 {
                    api: "SetupDiGetDevicePropertyW",
                    code,
                });
            }
        }
    }
    Err(InventoryError::PropertyUnstable)
}

/// Read one optional property; a read error becomes `None` plus a warning so
/// that one unreadable field (common on non-present devices) never drops
/// the whole device from the inventory.
fn optional_property(
    list: &DevInfoList,
    data: &SP_DEVINFO_DATA,
    key: &DEVPROPKEY,
    name: &str,
    instance_id: &str,
    warnings: &mut Vec<String>,
) -> Option<PropValue> {
    match get_property(list, data, key) {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("{instance_id}: property {name} unreadable: {e}"));
            None
        }
    }
}

fn read_device(
    list: &DevInfoList,
    data: &SP_DEVINFO_DATA,
    warnings: &mut Vec<String>,
) -> Result<DeviceRecord, InventoryError> {
    let instance_id = get_property(list, data, &DEVPKEY_Device_InstanceId)?
        .and_then(PropValue::into_string)
        .ok_or(InventoryError::MissingInstanceId)?;
    let mut prop = |key: &DEVPROPKEY, name: &str| {
        optional_property(list, data, key, name, &instance_id, warnings)
    };
    let hardware_ids = prop(&DEVPKEY_Device_HardwareIds, "HardwareIds")
        .map(PropValue::into_string_list)
        .unwrap_or_default();
    let compatible_ids = prop(&DEVPKEY_Device_CompatibleIds, "CompatibleIds")
        .map(PropValue::into_string_list)
        .unwrap_or_default();
    let class_guid = prop(&DEVPKEY_Device_ClassGuid, "ClassGuid").and_then(PropValue::into_guid);
    let class_name = prop(&DEVPKEY_Device_Class, "Class").and_then(PropValue::into_string);
    let enumerator =
        prop(&DEVPKEY_Device_EnumeratorName, "EnumeratorName").and_then(PropValue::into_string);
    let service = prop(&DEVPKEY_Device_Service, "Service").and_then(PropValue::into_string);
    let inf_manufacturer =
        prop(&DEVPKEY_Device_Manufacturer, "Manufacturer").and_then(PropValue::into_string);
    let friendly_name =
        prop(&DEVPKEY_Device_FriendlyName, "FriendlyName").and_then(PropValue::into_string);
    let description =
        prop(&DEVPKEY_Device_DeviceDesc, "DeviceDesc").and_then(PropValue::into_string);
    let bus_reported_description = prop(
        &DEVPKEY_Device_BusReportedDeviceDesc,
        "BusReportedDeviceDesc",
    )
    .and_then(PropValue::into_string);
    let parent_instance_id =
        prop(&DEVPKEY_Device_Parent, "Parent").and_then(PropValue::into_string);
    let present = prop(&DEVPKEY_Device_IsPresent, "IsPresent").and_then(PropValue::into_bool);
    let problem_code =
        prop(&DEVPKEY_Device_ProblemCode, "ProblemCode").and_then(PropValue::into_u32);
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

/// Enumerate all device nodes. A device without a readable instance ID is
/// skipped with a warning; other property failures become per-field
/// warnings. Neither aborts the inventory.
pub(crate) fn enumerate(
    scope: EnumerationScope,
) -> Result<(Vec<DeviceRecord>, Vec<String>), InventoryError> {
    let flags = match scope {
        EnumerationScope::PresentOnly => DIGCF_ALLCLASSES | DIGCF_PRESENT,
        EnumerationScope::IncludeNonPresent => DIGCF_ALLCLASSES,
    };
    // SAFETY: a null class GUID and null enumerator are permitted with
    // DIGCF_ALLCLASSES; a null parent window is permitted. No pointer is
    // retained by the callee.
    let handle = unsafe { SetupDiGetClassDevsW(ptr::null(), ptr::null(), ptr::null_mut(), flags) };
    if handle == INVALID_HDEVINFO {
        return Err(InventoryError::Win32 {
            api: "SetupDiGetClassDevsW",
            code: last_error(),
        });
    }
    let list = DevInfoList(handle);

    let mut devices = Vec::new();
    let mut warnings = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut data = empty_devinfo_data();
        // SAFETY: `list.0` is a live device information set; `data` is a
        // properly sized, writable SP_DEVINFO_DATA with cbSize set.
        let ok = unsafe { SetupDiEnumDeviceInfo(list.0, index, &mut data) };
        if ok == 0 {
            let code = last_error();
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(InventoryError::Win32 {
                api: "SetupDiEnumDeviceInfo",
                code,
            });
        }
        match read_device(&list, &data, &mut warnings) {
            Ok(d) => devices.push(d),
            Err(e) => warnings.push(format!("device index {index} skipped: {e}")),
        }
        index = index.checked_add(1).ok_or(InventoryError::TooManyDevices)?;
    }
    Ok((devices, warnings))
}
