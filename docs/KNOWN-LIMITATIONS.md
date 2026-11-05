# Known Limitations

Each limitation is a residual risk. "Accepted" requires written sign-off by the
security owner before Phase 9.

| ID | Limitation | Consequence | Mitigation | Status |
|---|---|---|---|---|
| L-01 | USB VID/PID and SCSI INQUIRY strings are not authenticated. | A device that reports an approved vendor (e.g. `SanDisk`) is allowed even if physically from another maker. Demonstrated by the `SPOOF0001` fixture test. | Physical control of media; VID mismatch shown as a warning; audit trail. Cannot be fixed in software. | Open — needs acceptance |
| L-02 | Some products report a controller/bridge vendor (`Generic`, `JMicron`, `ASMT`, `SMI`, `Phison`…) instead of the brand. | Such products of an approved brand are **denied**; they cannot be allowed at brand level without allowing every product using that controller. | Catalog rejects generic vendors. Any model-level exception must be a separate, explicit business decision. | Open |
| L-03 | New products of an approved brand that use a new INQUIRY vendor string are denied until the catalog is updated. | "Unseen devices work automatically" holds only while the brand keeps reporting a known vendor string. | Controlled offline catalog update with lab evidence. | By design |
| L-04 | TÜBİTAK SIR II identifiers are unknown. | Until inspected, every SIR II device is **denied** (default deny). If its vendor string is generic, brand-level allowlisting of SIR II is impossible. | Hardware inspection in Phase 2 (TEST-PLAN T-04..T-07). | Blocking |
| L-05 | Device Installation Restrictions do not re-evaluate already-installed devices. | Unauthorized drives connected before activation keep working. | Reviewed baseline cleanup of USB disk devnodes before activation; verification scan. | Open — Phase 2 |
| L-06 | A local administrator can change or remove OS policy. | Protection assumes operators are standard users. | Separate admin accounts; audit; tamper-evident logs (not tamper-proof). | By design |
| L-07 | The `SCSI\` namespace is shared by UASP USB disks and internal disks. | An allow rule for a vendor also matches internal disks of that vendor; vendor padding is unconfirmed. | Instance-ID allow rules for internal disks; hardware verification. | Open |
| L-08 | USB CD/DVD and MTP/PTP devices are outside the DiskDrive rule. | Not blocked unless a scope decision adds their classes. Reported as `enforcement_gap`. | Scope decision required. | Open |
| L-09 | Preventing the DiskDrive class blocks new internal disks and VHD/VHDX mounts. | Maintenance needs an admin procedure. | Baseline instance-ID allow rules; documented maintenance window. | By design |
| L-10 | Windows 10 left mainstream support on 2025-10-14. | Unpatched OS weakens every control. | Confirm ESU or Windows 11 migration plan. | Open — owner decision |
| L-11 | Local logs can be altered by a sufficiently privileged administrator. | Logs are tamper-evident at best. | Hash chain + Windows Event Log; never claimed tamper-proof. | By design |
| L-12 | Phase 1 has no enforcement at all. | Running RustWard today protects nothing. | Every output says "SIMULATION ONLY". | Current state |
