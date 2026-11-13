//! Per-user persistent preferences, cursor tracking, and deduplication window
//! for `rustward-notifier` stored under `%LOCALAPPDATA%\RustWard\notifier-prefs.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Cooldown window (milliseconds) for repeating the same `dedup_key`.
pub const DEDUP_COOLDOWN_MS: i64 = 60_000;
const MAX_DEDUP_ENTRIES: usize = 256;

/// Persistent per-user notifier state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifierPrefs {
    /// Last processed audit event id from the read-only notification feed.
    pub last_event_id: i64,
    /// Optional local user override enabling/disabling desktop notifications.
    pub notifications_enabled_override: Option<bool>,
    /// Optional local user override for verified blocked-USB toasts.
    pub notify_on_blocked_override: Option<bool>,
    /// Optional local user override for denied-but-unblocked warnings.
    pub notify_on_unblocked_warning_override: Option<bool>,
    /// Optional local language override (`"tr"` or `"en"`).
    pub language_override: Option<String>,
    /// Last notification timestamp (UTC ms) keyed by `dedup_key`.
    pub recent_dedup_ms: BTreeMap<String, i64>,
}

impl NotifierPrefs {
    /// Default per-user preference path (`%LOCALAPPDATA%\RustWard\notifier-prefs.json`).
    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .filter(|v| !v.is_empty())
                    .map(|u| PathBuf::from(u).join("AppData").join("Local"))
            })?;
        Some(base.join("RustWard").join("notifier-prefs.json"))
    }

    /// Load persisted preferences; missing or unreadable files fall back to
    /// clean defaults so notifications continue working.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str::<Self>(&raw).unwrap_or_default()
    }

    /// Save preferences safely into the per-user directory.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize notifier prefs failed: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body)
            .map_err(|e| format!("write {} failed: {e}", tmp.display()))?;
        if std::fs::rename(&tmp, path).is_err() {
            std::fs::write(path, &body)
                .map_err(|e| format!("write {} failed: {e}", path.display()))?;
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(())
    }

    /// Resolve effective `(notifications_enabled, notify_blocked, notify_warning, language)`
    /// merging local user overrides over service defaults.
    #[must_use]
    pub fn effective_settings(
        &self,
        service_enabled: bool,
        service_blocked: bool,
        service_warning: bool,
        service_language: &str,
    ) -> (bool, bool, bool, String) {
        let enabled = self.notifications_enabled_override.unwrap_or(service_enabled);
        let blocked = self.notify_on_blocked_override.unwrap_or(service_blocked);
        let warning = self
            .notify_on_unblocked_warning_override
            .unwrap_or(service_warning);
        let lang = match self.language_override.as_deref().unwrap_or(service_language) {
            "en" | "EN" => "en".to_owned(),
            _ => "tr".to_owned(),
        };
        (enabled, blocked, warning, lang)
    }

    /// Check whether `dedup_key` is suppressed due to a recent notification at `now_ms`.
    #[must_use]
    pub fn is_deduped(&self, dedup_key: &str, now_ms: i64) -> bool {
        self.recent_dedup_ms
            .get(dedup_key)
            .is_some_and(|last| now_ms.saturating_sub(*last) < DEDUP_COOLDOWN_MS)
    }

    /// Record that `dedup_key` was notified at `now_ms`, pruning expired keys.
    pub fn record_notified(&mut self, dedup_key: &str, now_ms: i64) {
        self.prune_dedup(now_ms);
        self.recent_dedup_ms.insert(dedup_key.to_owned(), now_ms);
        while self.recent_dedup_ms.len() > MAX_DEDUP_ENTRIES {
            let Some(oldest_key) = self
                .recent_dedup_ms
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.recent_dedup_ms.remove(&oldest_key);
        }
    }

    fn prune_dedup(&mut self, now_ms: i64) {
        self.recent_dedup_ms
            .retain(|_, ts| now_ms.saturating_sub(*ts) < DEDUP_COOLDOWN_MS);
    }
}
