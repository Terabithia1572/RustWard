//! Windows enforcement observation and the administrator checklist.
//!
//! Both are read-only towards Windows. The only write is an append-only,
//! deduplicated audit event when an installation denial starts or stops
//! being observed.

use rustward_core::device::SnapshotSource;
use rustward_enforcement::checklist::{ChecklistError, device_deny_checklist};
use rustward_enforcement::observer::{
    EvidenceLevel, HistoricalDenial, ObservedDevice, ObservedState, attach_history, observe,
};
use rustward_enforcement::policy_eval::InstallOutcome;
use rustward_enforcement::policy_inspect::CapturedPolicy;
use rustward_ipc::messages::{EnforcementObservationView, ObservedDeviceView, PolicyChecklistView};
use rustward_ipc::{ErrorCode, IpcError};
use rustward_storage::{
    EventFilter, NewEvent, SecurityEvent, Severity, device_key, mask_instance_id,
};

use super::{AppService, Inner, empty_snapshot, storage_err};

/// Audit kind: an installation denial started being observed.
pub const KIND_DENIAL_OBSERVED: &str = "windows_install_denied_observed";
/// Audit kind: a previously observed denial is no longer observed.
pub const KIND_DENIAL_ENDED: &str = "windows_install_denial_ended";

fn last_event(g: &Inner, kind: &str, key: &str) -> Result<Option<SecurityEvent>, IpcError> {
    Ok(g.store
        .list_events(&EventFilter {
            kind: Some(kind.into()),
            device_key: Some(key.into()),
            limit: Some(1),
            ..EventFilter::default()
        })
        .map_err(storage_err)?
        .into_iter()
        .next())
}

fn historical(e: &SecurityEvent) -> HistoricalDenial {
    HistoricalDenial {
        observed_ms: e.utc_ms,
        problem_code: e
            .details
            .get("problem_code")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or_default(),
        rule_entry: e
            .details
            .get("rule_entry")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

fn rule_of(d: &ObservedDevice) -> (String, String) {
    match &d.windows_rule {
        InstallOutcome::Prevented { rule } | InstallOutcome::Allowed { rule } => {
            (rule.list.clone(), rule.entry.clone())
        }
        InstallOutcome::NotRestricted => (String::new(), String::new()),
    }
}

impl AppService {
    /// Observe, attach history and record deduplicated audit events.
    pub(crate) fn enforcement_observation(
        &self,
        g: &mut Inner,
    ) -> Result<EnforcementObservationView, IpcError> {
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let now = self.clock.now_ms();
        let captured = self.policy_source.capture(now);
        let (policy_source, policy_error, cap) = match captured {
            Ok(c) => (self.policy_source.name().to_string(), None, c),
            Err(e) => (
                "unavailable".to_string(),
                Some(e),
                CapturedPolicy {
                    captured_ms: now,
                    ..CapturedPolicy::default()
                },
            ),
        };
        let mut obs = observe(&snap, &v.policy, &v.catalog, &cap);
        // Without a readable policy nothing can be correlated: never report
        // a Windows rule state then.
        let policy_ok = policy_error.is_none();
        let mut newly = Vec::new();
        let mut devices = Vec::new();
        for mut d in obs.devices.drain(..) {
            let key = device_key(&d.instance_id);
            let last_seen = last_event(g, KIND_DENIAL_OBSERVED, &key)?;
            let last_end = last_event(g, KIND_DENIAL_ENDED, &key)?;
            let active = match (&last_seen, &last_end) {
                (Some(s), Some(e)) => s.id > e.id,
                (Some(_), None) => true,
                _ => false,
            };
            let masked = mask_instance_id(&d.instance_id);
            if policy_ok && d.evidence == EvidenceLevel::InstallDenied {
                let (list, entry) = rule_of(&d);
                // One event per denial episode: a reconnect that changes
                // Code 1 into Code 28 is the same denial.
                let same = active
                    && last_seen
                        .as_ref()
                        .is_some_and(|s| historical(s).rule_entry == entry);
                if !same {
                    g.store
                        .append_event(&NewEvent {
                            severity: Severity::Warning,
                            kind: KIND_DENIAL_OBSERVED.into(),
                            device_key: Some(key.clone()),
                            message: format!(
                                "{}: Windows denied the installation (Code {}) by {list} entry \"{entry}\". Evidence: installation denied; read/write paths not tested.",
                                d.name,
                                d.problem_code.unwrap_or_default()
                            ),
                            simulated: false,
                            enforcement_state: self.enforcement_state_code().into(),
                            policy_version: None,
                            details: serde_json::json!({
                                "device": masked,
                                "hardware_id": d.hardware_id,
                                "vid_pid": d.vid_pid,
                                "policy_list": list,
                                "rule_entry": entry,
                                "problem_code": d.problem_code,
                                "observed_ms": now,
                                "verification_level": "install_denied",
                                "read_write_tested": false,
                                "evidence_source": "SetupAPI device problem code + HKLM DeviceInstall\\Restrictions (read-only)",
                                "applied_by": "windows_group_policy_not_rustward",
                            }),
                        })
                        .map_err(storage_err)?;
                    newly.push(key.clone());
                }
            } else if policy_ok && active {
                let reason = if d.present != Some(true) {
                    "device not connected"
                } else if matches!(d.windows_rule, InstallOutcome::Prevented { .. }) {
                    "device installed despite the rule"
                } else {
                    "no matching Windows rule"
                };
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Info,
                        kind: KIND_DENIAL_ENDED.into(),
                        device_key: Some(key.clone()),
                        message: format!(
                            "{}: the earlier Windows installation denial is no longer observed ({reason}).",
                            d.name
                        ),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "device": masked,
                            "reason": reason,
                            "observed_ms": now,
                        }),
                    })
                    .map_err(storage_err)?;
            }
            if !policy_ok {
                // Unknown policy: never claim "no rule".
                d.states.retain(|s| {
                    !matches!(
                        s,
                        ObservedState::NoWindowsRestriction | ObservedState::PolicyMismatch
                    )
                });
                if !d.states.contains(&ObservedState::StatusUnknown) {
                    d.states.push(ObservedState::StatusUnknown);
                }
                d.label_policy_tr = "Windows politikası okunamadı".into();
                d.explanation_tr =
                    "Windows politikası okunamadığı için gerçek kısıtlama durumu bilinmiyor."
                        .into();
            }
            if d.evidence != EvidenceLevel::InstallDenied {
                attach_history(&mut d, last_seen.as_ref().map(historical));
            }
            d.instance_id = masked;
            devices.push(ObservedDeviceView {
                device_key: key,
                observed: d,
            });
        }
        let inventory_collected_unix_seconds = g.last.as_ref().and_then(|s| match &s.source {
            SnapshotSource::Live {
                collected_unix_seconds,
                ..
            } => i64::try_from(*collected_unix_seconds).ok(),
            SnapshotSource::Synthetic { .. } => None,
        });
        Ok(EnforcementObservationView {
            policy_source,
            policy_error,
            policy_captured_ms: obs.policy_captured_ms,
            policy_key_present: obs.policy_key_present,
            windows_restrictions_configured: obs.windows_restrictions_configured,
            inventory_collected_unix_seconds,
            devices,
            newly_observed_denials: newly,
            rustward_applies_nothing: true,
        })
    }

    /// Generate (never apply) the Group Policy checklist for one device.
    pub(crate) fn policy_checklist(
        &self,
        g: &Inner,
        key: &str,
        retroactive: bool,
    ) -> Result<PolicyChecklistView, IpcError> {
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let instance = snap
            .devices
            .iter()
            .find(|d| device_key(&d.instance_id) == key)
            .map(|d| d.instance_id.clone())
            .ok_or_else(|| {
                IpcError::new(ErrorCode::NotFound, "device not in the current inventory")
            })?;
        let captured = self
            .policy_source
            .capture(self.clock.now_ms())
            .map_err(|e| {
                IpcError::new(ErrorCode::Unavailable, format!("policy not readable: {e}"))
            })?;
        let checklist = device_deny_checklist(
            &snap,
            &v.policy,
            &v.catalog,
            &captured.values,
            &instance,
            retroactive,
        )
        .map_err(|e| {
            let code = match e {
                ChecklistError::DeviceNotFound => ErrorCode::NotFound,
                _ => ErrorCode::ValidationFailed,
            };
            IpcError::new(code, e.to_string())
        })?;
        let text = checklist.render_text();
        Ok(PolicyChecklistView { checklist, text })
    }
}
