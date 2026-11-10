//! Official Windows Local Group Policy COM API (`IGroupPolicyObject`) adapter.
//!
//! Provides transactional application and removal of Windows Device Installation
//! Restrictions for authorized USB storage devices.
//!
//! COM Interface: `IGroupPolicyObject` (gpedit.dll)
//! Section: `GPO_SECTION_MACHINE`
//! CSE Extension: `REGISTRY_EXTENSION_GUID` ({35378EAC-683A-11D2-A89A-00C04FBBCFA2})
//! Snap-in: `CLSID_GPESnapIn` ({0F6B957E-509E-11D1-A7CC-0000F87571E3})

use std::ffi::c_void;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, KEY_WOW64_64KEY, REG_DWORD,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW,
    RegDeleteValueW, RegOpenKeyExW, RegSetValueExW,
};

#[allow(clippy::upper_case_acronyms)]
type BOOL = i32;
#[allow(clippy::upper_case_acronyms)]
type HRESULT = i32;
const S_OK: HRESULT = 0;
const S_FALSE: HRESULT = 1;

use crate::regdecode::to_wide;

// CLSID_GroupPolicyObject = {EA502722-A23D-11D1-A7D3-0000F87571E3} (Microsoft GPEdit.h)
pub const CLSID_GROUP_POLICY_OBJECT: GUID = GUID {
    data1: 0xEA502722,
    data2: 0xA23D,
    data3: 0x11D1,
    data4: [0xA7, 0xD3, 0x00, 0x00, 0xF8, 0x75, 0x71, 0xE3],
};

// IID_IGroupPolicyObject = {EA502723-A23D-11D1-A7D3-0000F87571E3} (Microsoft GPEdit.h)
pub const IID_IGROUP_POLICY_OBJECT: GUID = GUID {
    data1: 0xEA502723,
    data2: 0xA23D,
    data3: 0x11D1,
    data4: [0xA7, 0xD3, 0x00, 0x00, 0xF8, 0x75, 0x71, 0xE3],
};

// REGISTRY_EXTENSION_GUID = {35378EAC-683F-11D2-A89A-00C04FBBCFA2} (Microsoft GPEdit.h / UserEnv.h)
pub const REGISTRY_EXTENSION_GUID: GUID = GUID {
    data1: 0x35378EAC,
    data2: 0x683F,
    data3: 0x11D2,
    data4: [0xA8, 0x9A, 0x00, 0xC0, 0x4F, 0xBB, 0xCF, 0xA2],
};

// CLSID_GPESnapIn = {8FC0B734-A0E1-11D1-A7D3-0000F87571E3} (Microsoft GPEdit.h)
pub const CLSID_GPE_SNAPIN: GUID = GUID {
    data1: 0x8FC0B734,
    data2: 0xA0E1,
    data3: 0x11D1,
    data4: [0xA7, 0xD3, 0x00, 0x00, 0xF8, 0x75, 0x71, 0xE3],
};

pub const GPO_OPEN_LOAD_REGISTRY: u32 = 0x00000001;
pub const GPO_SECTION_MACHINE: u32 = 2;

const GPO_RESTRICTIONS_SUBKEY: &str =
    "Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions";
const HKLM_RESTRICTIONS_PATH: &str =
    "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions";

#[repr(C)]
#[allow(non_snake_case)]
pub struct IGroupPolicyObjectVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppvObject: *mut *mut c_void,
    ) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub New: unsafe extern "system" fn(
        this: *mut c_void,
        pszDomainName: *const u16,
        pszDisplayName: *const u16,
        dwFlags: u32,
    ) -> HRESULT,
    pub OpenDSGPO: unsafe extern "system" fn(
        this: *mut c_void,
        pszPath: *const u16,
        dwFlags: u32,
    ) -> HRESULT,
    pub OpenLocalMachineGPO: unsafe extern "system" fn(
        this: *mut c_void,
        dwFlags: u32,
    ) -> HRESULT,
    pub OpenRemoteMachineGPO: unsafe extern "system" fn(
        this: *mut c_void,
        pszComputerName: *const u16,
        dwFlags: u32,
    ) -> HRESULT,
    pub Save: unsafe extern "system" fn(
        this: *mut c_void,
        bMachine: BOOL,
        bAdd: BOOL,
        pGuidExtension: *const GUID,
        pGuid: *const GUID,
    ) -> HRESULT,
    pub Delete: unsafe extern "system" fn(this: *mut c_void) -> HRESULT,
    pub GetName: unsafe extern "system" fn(
        this: *mut c_void,
        pszName: *mut u16,
        cchMaxLength: i32,
    ) -> HRESULT,
    pub GetDisplayName: unsafe extern "system" fn(
        this: *mut c_void,
        pszDisplayName: *mut u16,
        cchMaxLength: i32,
    ) -> HRESULT,
    pub SetDisplayName: unsafe extern "system" fn(
        this: *mut c_void,
        pszDisplayName: *const u16,
    ) -> HRESULT,
    pub GetPath: unsafe extern "system" fn(
        this: *mut c_void,
        pszPath: *mut u16,
        cchMaxPath: i32,
    ) -> HRESULT,
    pub GetDSPath: unsafe extern "system" fn(
        this: *mut c_void,
        dwSection: u32,
        pszPath: *mut u16,
        cchMaxPath: i32,
    ) -> HRESULT,
    pub GetFileSysPath: unsafe extern "system" fn(
        this: *mut c_void,
        dwSection: u32,
        pszPath: *mut u16,
        cchMaxPath: i32,
    ) -> HRESULT,
    pub GetRegistryKey: unsafe extern "system" fn(
        this: *mut c_void,
        dwSection: u32,
        hKey: *mut HKEY,
    ) -> HRESULT,
    pub GetOptions: unsafe extern "system" fn(
        this: *mut c_void,
        pdwOptions: *mut u32,
    ) -> HRESULT,
    pub SetOptions: unsafe extern "system" fn(
        this: *mut c_void,
        dwOptions: u32,
        dwMask: u32,
    ) -> HRESULT,
    pub GetType: unsafe extern "system" fn(
        this: *mut c_void,
        pGPOType: *mut u32,
    ) -> HRESULT,
    pub GetMachineName: unsafe extern "system" fn(
        this: *mut c_void,
        pszMachineName: *mut u16,
        cchMaxLength: i32,
    ) -> HRESULT,
    pub GetPropertySheetPages: unsafe extern "system" fn(
        this: *mut c_void,
        hPages: *mut *mut c_void,
        uPageCount: *mut u32,
    ) -> HRESULT,
}

struct ComGuard(bool);

impl ComGuard {
    fn init() -> Self {
        // SAFETY: standard COM apartment initialization.
        let hr = unsafe { CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED as u32) };
        Self(hr == S_OK || hr == S_FALSE)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: matched uninitialization for successful CoInitializeEx.
            unsafe { CoUninitialize() };
        }
    }
}

struct GpoObject(*mut *mut IGroupPolicyObjectVtbl);

impl Drop for GpoObject {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Release COM interface on drop.
            unsafe {
                let vtbl = *self.0;
                ((*vtbl).Release)(self.0.cast::<c_void>());
            }
        }
    }
}

struct KeyGuard(HKEY);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Close valid open registry key handle.
            unsafe { RegCloseKey(self.0) };
        }
    }
}

/// GPO policy writer adapter for Windows Device Installation Restrictions.
#[derive(Debug, Default, Clone, Copy)]
pub struct GpoPolicyWriter;

impl GpoPolicyWriter {
    /// Ensures `C:\Windows\System32\GroupPolicy\Machine\Registry.pol` has a valid PReg header.
    /// If corrupted (e.g. all zero bytes from unclean write), heals it so OpenLocalMachineGPO does not fail with 0x80004005.
    #[cfg(windows)]
    fn ensure_valid_registry_pol() {
        let pol_path = r"C:\Windows\System32\GroupPolicy\Machine\Registry.pol";
        if std::fs::read(pol_path)
            .ok()
            .filter(|b| b.len() >= 8 && &b[0..4] != b"PReg")
            .is_some()
        {
            let valid_header = [0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00];
            let _ = std::fs::write(pol_path, valid_header);
        }
    }

    /// Comprehensive check of the Local GPO COM API capability and policy-store access.
    pub fn check_capability() -> Result<(), String> {
        #[cfg(windows)]
        {
            Self::ensure_valid_registry_pol();
            let _com = ComGuard::init();
            let mut gpo_raw: *mut c_void = ptr::null_mut();
            // SAFETY: CoCreateInstance for CLSID_GROUP_POLICY_OBJECT.
            let hr = unsafe {
                CoCreateInstance(
                    &CLSID_GROUP_POLICY_OBJECT,
                    ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_IGROUP_POLICY_OBJECT,
                    &mut gpo_raw,
                )
            };
            if hr < 0 || gpo_raw.is_null() {
                return Err(format!(
                    "CoCreateInstance(CLSID_GroupPolicyObject) failed: HRESULT {hr:#010X} (0x80040154 = REGDB_E_CLASSNOTREG)"
                ));
            }
            let gpo = GpoObject(gpo_raw.cast());
            // SAFETY: Dereference valid vtable pointer from COM interface.
            let vtbl = unsafe { *gpo.0 };

            // Check opening Local Machine GPO with registry load flag
            // SAFETY: Call OpenLocalMachineGPO through valid COM vtable.
            let hr = unsafe { ((*vtbl).OpenLocalMachineGPO)(gpo.0.cast::<c_void>(), GPO_OPEN_LOAD_REGISTRY) };
            if hr < 0 {
                return Err(format!("OpenLocalMachineGPO failed: HRESULT {hr:#010X}"));
            }

            // Check obtaining Machine Registry root key handle
            let mut h_gpo_root: HKEY = ptr::null_mut();
            // SAFETY: Call GetRegistryKey through valid COM vtable.
            let hr = unsafe { ((*vtbl).GetRegistryKey)(gpo.0.cast::<c_void>(), GPO_SECTION_MACHINE, &mut h_gpo_root) };
            if hr < 0 || h_gpo_root.is_null() {
                return Err(format!("GetRegistryKey(GPO_SECTION_MACHINE) failed: HRESULT {hr:#010X}"));
            }
            let _gpo_root_guard = KeyGuard(h_gpo_root);

            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err("Local Group Policy COM operations require Windows".into())
        }
    }

    /// Check whether GPO COM API is accessible and functional.
    #[must_use]
    pub fn is_available() -> bool {
        Self::check_capability().is_ok()
    }

    /// Apply a single device restriction via Local GPO COM API and direct registry.
    pub fn apply_device_block(hardware_id: &str, retroactive: bool) -> Result<(), String> {
        Self::apply_compound_policy(&[hardware_id.to_string()], &[], retroactive)
    }

    /// Remove a device restriction via Local GPO COM API and direct registry.
    pub fn restore_device_policy(_hardware_id: &str) -> Result<(), String> {
        Self::restore_compound_policy()
    }

    /// Apply a compound multi-device restriction via Local GPO COM API and direct registry.
    pub fn apply_compound_policy(
        deny_hardware_ids: &[String],
        allow_hardware_ids: &[String],
        retroactive: bool,
    ) -> Result<(), String> {
        for hwid in deny_hardware_ids {
            Self::validate_hardware_id(hwid)?;
        }
        for hwid in allow_hardware_ids {
            Self::validate_hardware_id(hwid)?;
        }

        #[cfg(windows)]
        {
            Self::ensure_valid_registry_pol();
            let _com = ComGuard::init();
            let mut gpo_raw: *mut c_void = ptr::null_mut();
            // SAFETY: CoCreateInstance for CLSID_GROUP_POLICY_OBJECT.
            let hr = unsafe {
                CoCreateInstance(
                    &CLSID_GROUP_POLICY_OBJECT,
                    ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_IGROUP_POLICY_OBJECT,
                    &mut gpo_raw,
                )
            };
            if hr < 0 || gpo_raw.is_null() {
                return Err(format!("CoCreateInstance(CLSID_GroupPolicyObject) failed: HRESULT {hr:#X}"));
            }
            let gpo = GpoObject(gpo_raw.cast());
            // SAFETY: Dereference valid vtable pointer from COM interface.
            let vtbl = unsafe { *gpo.0 };

            // Open Local Machine GPO with registry load flag
            // SAFETY: Call OpenLocalMachineGPO through valid COM vtable.
            let hr = unsafe { ((*vtbl).OpenLocalMachineGPO)(gpo.0.cast::<c_void>(), GPO_OPEN_LOAD_REGISTRY) };
            if hr < 0 {
                return Err(format!("OpenLocalMachineGPO failed: HRESULT {hr:#X}"));
            }

            // Get Machine Registry root key in the GPO
            let mut h_gpo_root: HKEY = ptr::null_mut();
            // SAFETY: Call GetRegistryKey through valid COM vtable.
            let hr = unsafe { ((*vtbl).GetRegistryKey)(gpo.0.cast::<c_void>(), GPO_SECTION_MACHINE, &mut h_gpo_root) };
            if hr < 0 || h_gpo_root.is_null() {
                return Err(format!("GetRegistryKey(GPO_SECTION_MACHINE) failed: HRESULT {hr:#X}"));
            }
            let _gpo_root_guard = KeyGuard(h_gpo_root);

            // Write compound restrictions into the GPO registry hive
            Self::write_compound_restrictions_hive(
                h_gpo_root,
                GPO_RESTRICTIONS_SUBKEY,
                deny_hardware_ids,
                allow_hardware_ids,
                retroactive,
            )?;

            // Save GPO Machine section with Registry CSE Extension and GPE Snapin GUIDs
            // SAFETY: Call Save through valid COM vtable.
            let hr = unsafe {
                ((*vtbl).Save)(
                    gpo.0.cast::<c_void>(),
                    1, // bMachine = TRUE
                    1, // bAdd = TRUE
                    &REGISTRY_EXTENSION_GUID,
                    &CLSID_GPE_SNAPIN,
                )
            };
            if hr < 0 {
                return Err(format!("IGroupPolicyObject::Save failed: HRESULT {hr:#X}"));
            }

            // Also mirror directly to HKLM for instantaneous PnP kernel visibility
            Self::write_compound_restrictions_hive(
                HKEY_LOCAL_MACHINE,
                HKLM_RESTRICTIONS_PATH,
                deny_hardware_ids,
                allow_hardware_ids,
                retroactive,
            )?;

            // Trigger policy notification / PnP sweep
            Self::trigger_policy_refresh();
            Self::trigger_device_rescan();

            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (deny_hardware_ids, allow_hardware_ids, retroactive);
            Err("Local Group Policy operations require Windows".into())
        }
    }

    /// Restore compound policy by removing RustWard-managed restrictions from Local GPO COM API and direct registry.
    pub fn restore_compound_policy() -> Result<(), String> {
        #[cfg(windows)]
        {
            Self::ensure_valid_registry_pol();
            let _com = ComGuard::init();
            let mut gpo_raw: *mut c_void = ptr::null_mut();
            // SAFETY: CoCreateInstance for CLSID_GROUP_POLICY_OBJECT.
            let hr = unsafe {
                CoCreateInstance(
                    &CLSID_GROUP_POLICY_OBJECT,
                    ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_IGROUP_POLICY_OBJECT,
                    &mut gpo_raw,
                )
            };
            if hr >= 0 && !gpo_raw.is_null() {
                let gpo = GpoObject(gpo_raw.cast());
                // SAFETY: Dereference valid vtable pointer from COM interface.
                let vtbl = unsafe { *gpo.0 };
                // SAFETY: Call OpenLocalMachineGPO through valid COM vtable.
                let hr = unsafe { ((*vtbl).OpenLocalMachineGPO)(gpo.0.cast::<c_void>(), GPO_OPEN_LOAD_REGISTRY) };
                if hr >= 0 {
                    let mut h_gpo_root: HKEY = ptr::null_mut();
                    // SAFETY: Call GetRegistryKey through valid COM vtable.
                    let hr = unsafe { ((*vtbl).GetRegistryKey)(gpo.0.cast::<c_void>(), GPO_SECTION_MACHINE, &mut h_gpo_root) };
                    if hr >= 0 && !h_gpo_root.is_null() {
                        let _gpo_root_guard = KeyGuard(h_gpo_root);
                        let _ = Self::clean_compound_restrictions_hive(h_gpo_root, GPO_RESTRICTIONS_SUBKEY);
                        // SAFETY: Call Save through valid COM vtable.
                        let _ = unsafe {
                            ((*vtbl).Save)(
                                gpo.0.cast::<c_void>(),
                                1, // bMachine = TRUE
                                1, // bAdd = TRUE
                                &REGISTRY_EXTENSION_GUID,
                                &CLSID_GPE_SNAPIN,
                            )
                        };
                    }
                }
            }

            // Clean direct HKLM registry path
            let _ = Self::clean_compound_restrictions_hive(HKEY_LOCAL_MACHINE, HKLM_RESTRICTIONS_PATH);

            // Trigger policy notification and hardware re-scan
            Self::trigger_policy_refresh();
            Self::trigger_device_rescan();

            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err("Local Group Policy operations require Windows".into())
        }
    }

    fn validate_hardware_id(hwid: &str) -> Result<(), String> {
        let trimmed = hwid.trim();
        if trimmed.is_empty() {
            return Err("hardware ID cannot be empty".into());
        }
        if trimmed.len() > 260 {
            return Err("hardware ID exceeds maximum allowed length".into());
        }
        if trimmed.contains('*') || trimmed.contains('?') || trimmed.contains("..") || trimmed.contains('\0') {
            return Err("hardware ID contains invalid characters or wildcards".into());
        }
        // Strict boundary: Only USB storage devices are allowed.
        // Rejects NVMe, internal SCSI, SATA, boot disks, PCI, ACPI, HID.
        let upper = trimmed.to_ascii_uppercase();
        if !upper.starts_with("USBSTOR\\") && !upper.starts_with("USB\\") {
            return Err(format!("Device ID '{trimmed}' is not a USB device; non-USB devices are strictly rejected"));
        }
        if upper.contains("NVME") || upper.contains("VMW_") || upper.contains("PCI\\") || upper.contains("SCSI\\") || upper.contains("IDE\\") || upper.contains("ACPI\\") {
            return Err(format!("Device ID '{trimmed}' matches system disk patterns; operation aborted for safety"));
        }
        if upper.contains("HID\\") || upper.contains("KBD") || upper.contains("MOU") {
            return Err(format!("Device ID '{trimmed}' matches input device patterns; operation aborted for safety"));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn write_compound_restrictions_hive(
        root: HKEY,
        subkey_path: &str,
        deny_hardware_ids: &[String],
        allow_hardware_ids: &[String],
        retroactive: bool,
    ) -> Result<(), String> {
        let wide_sub = to_wide(subkey_path);
        let mut h_restr: HKEY = ptr::null_mut();
        // SAFETY: Create or open the registry key with administrative access rights.
        let rc = unsafe {
            RegCreateKeyExW(
                root,
                wide_sub.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE | KEY_READ | KEY_WOW64_64KEY,
                ptr::null(),
                &mut h_restr,
                ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS || h_restr.is_null() {
            return Err(format!("RegCreateKeyExW({subkey_path}) failed with Win32 error {rc}"));
        }
        let _restr_guard = KeyGuard(h_restr);

        // 1. Manage DenyDeviceIDs
        let val_deny = to_wide("DenyDeviceIDs");
        let val_retro = to_wide("DenyDeviceIDsRetroactive");
        let wide_list_deny = to_wide("DenyDeviceIDs");

        if !deny_hardware_ids.is_empty() {
            let dword_one = 1u32;
            // SAFETY: Set DenyDeviceIDs and retroactive flag DWORD values on the valid open key.
            unsafe {
                RegSetValueExW(
                    h_restr,
                    val_deny.as_ptr(),
                    0,
                    REG_DWORD,
                    (&raw const dword_one).cast::<u8>(),
                    4,
                );
                let dword_retro = if retroactive { 1u32 } else { 0u32 };
                RegSetValueExW(
                    h_restr,
                    val_retro.as_ptr(),
                    0,
                    REG_DWORD,
                    (&raw const dword_retro).cast::<u8>(),
                    4,
                );
            }

            // Clean previous list subkey to prevent stale excess entries
            // SAFETY: Delete any existing DenyDeviceIDs subkey to prevent stale entries.
            unsafe {
                RegDeleteKeyW(h_restr, wide_list_deny.as_ptr());
            }

            let mut h_list: HKEY = ptr::null_mut();
            // SAFETY: Create or open the DenyDeviceIDs subkey with read/write permissions.
            let rc = unsafe {
                RegCreateKeyExW(
                    h_restr,
                    wide_list_deny.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE | KEY_READ | KEY_WOW64_64KEY,
                    ptr::null(),
                    &mut h_list,
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_SUCCESS && !h_list.is_null() {
                let _list_guard = KeyGuard(h_list);
                for (idx, hwid) in deny_hardware_ids.iter().enumerate() {
                    let val_name = to_wide(&(idx + 1).to_string());
                    let val_data = to_wide(hwid);
                    let byte_len = u32::try_from(val_data.len() * 2).unwrap_or(u32::MAX);
                    // SAFETY: Write the individual hardware ID into the indexed value.
                    unsafe {
                        RegSetValueExW(
                            h_list,
                            val_name.as_ptr(),
                            0,
                            REG_SZ,
                            val_data.as_ptr().cast::<u8>(),
                            byte_len,
                        );
                    }
                }
            }
        } else {
            // No deny IDs - clean deny list
            // SAFETY: Clean DenyDeviceIDs subkey and values when the deny list is empty.
            unsafe {
                RegDeleteKeyW(h_restr, wide_list_deny.as_ptr());
                RegDeleteValueW(h_restr, val_deny.as_ptr());
                RegDeleteValueW(h_restr, val_retro.as_ptr());
            }
        }

        // 2. Manage AllowDeviceIDs
        let val_allow = to_wide("AllowDeviceIDs");
        let val_layered = to_wide("AllowDenyLayered");
        let wide_list_allow = to_wide("AllowDeviceIDs");

        if !allow_hardware_ids.is_empty() {
            let dword_one = 1u32;
            // SAFETY: Set AllowDeviceIDs and AllowDenyLayered DWORD values on the valid open key.
            unsafe {
                RegSetValueExW(
                    h_restr,
                    val_allow.as_ptr(),
                    0,
                    REG_DWORD,
                    (&raw const dword_one).cast::<u8>(),
                    4,
                );
                RegSetValueExW(
                    h_restr,
                    val_layered.as_ptr(),
                    0,
                    REG_DWORD,
                    (&raw const dword_one).cast::<u8>(),
                    4,
                );
            }

            // SAFETY: Delete any existing AllowDeviceIDs subkey to prevent stale entries.
            unsafe {
                RegDeleteKeyW(h_restr, wide_list_allow.as_ptr());
            }

            let mut h_list: HKEY = ptr::null_mut();
            // SAFETY: Create or open the AllowDeviceIDs subkey with read/write permissions.
            let rc = unsafe {
                RegCreateKeyExW(
                    h_restr,
                    wide_list_allow.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE | KEY_READ | KEY_WOW64_64KEY,
                    ptr::null(),
                    &mut h_list,
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_SUCCESS && !h_list.is_null() {
                let _list_guard = KeyGuard(h_list);
                for (idx, hwid) in allow_hardware_ids.iter().enumerate() {
                    let val_name = to_wide(&(idx + 1).to_string());
                    let val_data = to_wide(hwid);
                    let byte_len = u32::try_from(val_data.len() * 2).unwrap_or(u32::MAX);
                    // SAFETY: Write the individual hardware ID into the indexed value.
                    unsafe {
                        RegSetValueExW(
                            h_list,
                            val_name.as_ptr(),
                            0,
                            REG_SZ,
                            val_data.as_ptr().cast::<u8>(),
                            byte_len,
                        );
                    }
                }
            }
        } else {
            // No allow IDs - clean allow list
            // SAFETY: Clean AllowDeviceIDs subkey and values when the allow list is empty.
            unsafe {
                RegDeleteKeyW(h_restr, wide_list_allow.as_ptr());
                RegDeleteValueW(h_restr, val_allow.as_ptr());
                RegDeleteValueW(h_restr, val_layered.as_ptr());
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn clean_compound_restrictions_hive(
        root: HKEY,
        subkey_path: &str,
    ) -> Result<(), String> {
        let wide_sub = to_wide(subkey_path);
        let mut h_restr: HKEY = ptr::null_mut();
        // SAFETY: Open the registry key to remove device restrictions.
        let rc = unsafe {
            RegOpenKeyExW(
                root,
                wide_sub.as_ptr(),
                0,
                KEY_WRITE | KEY_READ | KEY_WOW64_64KEY,
                &mut h_restr,
            )
        };
        if rc != ERROR_SUCCESS || h_restr.is_null() {
            return Ok(()); // Already absent
        }
        let _restr_guard = KeyGuard(h_restr);

        // Delete subkeys and values managed by RustWard
        // SAFETY: Clean up all RustWard-managed restriction subkeys and values from the Restrictions key.
        unsafe {
            RegDeleteKeyW(h_restr, to_wide("DenyDeviceIDs").as_ptr());
            RegDeleteValueW(h_restr, to_wide("DenyDeviceIDs").as_ptr());
            RegDeleteValueW(h_restr, to_wide("DenyDeviceIDsRetroactive").as_ptr());

            RegDeleteKeyW(h_restr, to_wide("AllowDeviceIDs").as_ptr());
            RegDeleteValueW(h_restr, to_wide("AllowDeviceIDs").as_ptr());
            RegDeleteValueW(h_restr, to_wide("AllowDenyLayered").as_ptr());
        }

        // Drop the handle before deleting the Restrictions key itself
        drop(_restr_guard);

        // SAFETY: Delete Restrictions key from root if now empty.
        unsafe {
            RegDeleteKeyW(root, wide_sub.as_ptr());
        }

        Ok(())
    }

    /// Trigger Windows Group Policy refresh and notify policy extensions.
    pub fn trigger_policy_refresh() {
        #[cfg(windows)]
        {
            // Dynamically load userenv.dll and call RefreshPolicyEx if available
            type RefreshPolicyExFn = unsafe extern "system" fn(b_machine: BOOL, dw_options: u32) -> BOOL;
            let userenv_name = to_wide("userenv.dll");
            // SAFETY: standard DLL load and symbol lookup for optional policy refresh.
            let h_mod = unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryW(userenv_name.as_ptr()) };
            if !h_mod.is_null() {
                let proc_name = c"RefreshPolicyEx";
                // SAFETY: Get procedure address for RefreshPolicyEx.
                let proc = unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_mod, proc_name.as_ptr().cast()) };
                if let Some(f) = proc {
                    // SAFETY: Transmute FARPROC to known function signature.
                    let refresh: RefreshPolicyExFn = unsafe { std::mem::transmute(f) };
                    // RP_FORCE = 1
                    // SAFETY: Call RefreshPolicyEx to refresh machine policy.
                    unsafe { refresh(1, 1) };
                }
                // SAFETY: Free userenv.dll handle.
                unsafe { windows_sys::Win32::Foundation::FreeLibrary(h_mod) };
            }
        }
    }

    /// Trigger Windows PnP manager to rescan for hardware changes.
    pub fn trigger_device_rescan() {
        #[cfg(windows)]
        {
            // Execute pnputil /scan-devices via system path
            let _ = std::process::Command::new("pnputil.exe")
                .arg("/scan-devices")
                .output();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_hardware_id_accepts_valid_usb_ids() {
        assert!(GpoPolicyWriter::validate_hardware_id("USBSTOR\\DiskKingstonDataTraveler_3.0____").is_ok());
        assert!(GpoPolicyWriter::validate_hardware_id("USB\\VID_0951&PID_1666").is_ok());
        assert!(GpoPolicyWriter::validate_hardware_id("USB\\VID_346D&PID_5678").is_ok());
        assert!(GpoPolicyWriter::validate_hardware_id("USBSTOR\\GenDisk").is_ok());
    }

    #[test]
    fn validate_hardware_id_rejects_empty_and_oversized() {
        assert!(GpoPolicyWriter::validate_hardware_id("").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("   ").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id(&"USB\\".repeat(70)).is_err());
    }

    #[test]
    fn validate_hardware_id_rejects_wildcards_and_traversal() {
        assert!(GpoPolicyWriter::validate_hardware_id("USBSTOR\\*").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("USB\\VID_????").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("USB\\..\\something").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("USB\\test\0junk").is_err());
    }

    #[test]
    fn validate_hardware_id_rejects_system_disks_and_inputs() {
        assert!(GpoPolicyWriter::validate_hardware_id("SCSI\\DiskNVMe____").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("IDE\\DiskVMware_Virtual_IDE_Hard_Drive").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("PCI\\VEN_8086&DEV_1234").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("HID\\VID_046D&PID_C077").is_err());
        assert!(GpoPolicyWriter::validate_hardware_id("ACPI\\PNP0303").is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_gpo_com_capability() {
        let cap = GpoPolicyWriter::check_capability();
        assert!(
            cap.is_ok(),
            "GpoPolicyWriter::check_capability() failed: {:?}",
            cap.err()
        );
        assert!(GpoPolicyWriter::is_available());
    }
}
