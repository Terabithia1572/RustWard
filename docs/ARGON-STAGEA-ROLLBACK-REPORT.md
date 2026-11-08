# Stage A Rollback Verification Report

## Environment & Target
- **Workspace**: `C:\Users\Yunus\Desktop\RustWard2`
- **Branch**: `experiment/argon4-vm-enforcement`
- **Target VM**: `D:\Windows10VM\Windows 10 x64.vmx` (`Windows 10 Pro 22H2 build 19045.6466`)
- **Offline Snapshot**: `Before-Argon4-StageA` (UID 9) preserved intact
- **Session ID**: `6b80fb90cf7c52d3`

---

## 1. Registry Policy Verification
Setting Group Policy to *Not Configured* (`Yapılandırılmadı`) and running `gpupdate /force` in the guest produced:
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`: **ABSENT**
- Result: **Exact match** with the pre-enforcement baseline (`baseline = []`).

---

## 2. PnP & Storage Stack Verification
- **Kingston DataTraveler 3.0** (`0951:1666`):
  - PnP Instance: `USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_\4CEDFB74A335F721191112BC&0`
  - Status: **`OK`**
  - ProblemCode: **`0`**
  - Active Driver: `disk.sys`
  - Disk: `Disk 2` (61.87 GB MBR, Online, Healthy)
  - Partitions:
    - Partition 1 (`E:\`, exFAT, Removable): Directory read verified (`[Zula, Sons Of The Forest 4, F6]`)
    - Partition 2 (`F:\`, FAT VTOYEFI, Removable): Directory read verified (`[grub, ventoy, EFI]`)
- **VendorC ProductCode** (`346D:5678`):
  - PnP Instance: `USBSTOR\DISK&VEN_VENDORC&PROD_PRODUCTCODE&REV_3.20\FC1158E772D5C&0`
  - Status: **`OK`**, ProblemCode: **`0`**
  - Disk: `Disk 1` (31.46 GB GPT, Online, Healthy)
  - Partition 1 (`G:\`, FAT32 WIN10_11_AI): Directory read verified (`[boot, efi, software]`)
- **VMware Virtual NVMe Disk** (Internal System Disk):
  - Status: **`OK`**, ProblemCode: **`0`**
  - Disk: `Disk 0` (64.42 GB GPT, Online, Healthy)
  - Partition 3 (`C:\`, NTFS Boot/OS): Healthy, `disk.sys` read verified
- **Peripherals**:
  - `VMware USB Pointing Device`: `Status = OK`, `ProblemCode = 0`
  - `HID-compliant mouse`: `Status = OK`, `ProblemCode = 0`
  - `Standard PS/2 Keyboard`: `Status = OK`, `ProblemCode = 0`
  - `USB Input Device`: `Status = OK`, `ProblemCode = 0`

---

## 3. RustWard Audit & State Verification
- Pipe call `verify_enforcement_rollback` on `\\.\pipe\RustWard.Admin.v1`: Completed in `60 ms`.
- Session state: Closed (`session: null`, state reverted to `policy_simulation`).
- Audit events appended:
  - Event `#358`: `windows_install_denial_ended`
  - Event `#359`: `enforcement_session_rollback_verified`
- Audit chain status: `intact (359 entries)`, `chain_ok: true`.
- UI State: Badges show `Etkin değil`, `KORUMA ETKİN DEĞİL`, `Gerçek engel kanıtı yok`, `Windows'un reddettiği (doğrulanmış): 0`.
