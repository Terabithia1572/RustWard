//! Notification feed polling, filtering, honest severity formatting, and deduplication.

use std::path::PathBuf;

use rustward_ipc::messages::{NotificationFeedView, NotificationItemView};

use crate::prefs::NotifierPrefs;

/// Maximum age (ms) on cold start (when no prior cursor exists) for emitting
/// recent backlog events instead of flooding the desktop with old history.
pub const COLD_START_WINDOW_MS: i64 = 120_000;

/// Rendered toast payload ready for desktop presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToastMessage {
    pub event_id: i64,
    pub dedup_key: String,
    pub title: String,
    pub body: String,
    pub is_warning: bool,
}

/// Abstract read-only notification feed client.
pub trait FeedClient {
    fn fetch_feed(&mut self, after_event_id: Option<i64>) -> Result<NotificationFeedView, String>;
}

/// Abstract native desktop toast presenter.
pub trait ToastPresenter {
    fn show_toast(&mut self, toast: &ToastMessage) -> Result<(), String>;
}

/// Summary of one polling cycle.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollSummary {
    pub received: usize,
    pub shown: usize,
    pub suppressed: usize,
    pub latest_event_id: i64,
}

/// Format an IPC feed item strictly honoring enforcement honesty and language.
#[must_use]
pub fn format_toast(item: &NotificationItemView, language: &str) -> ToastMessage {
    let use_en = language.eq_ignore_ascii_case("en");
    let raw_title = if use_en { &item.title_en } else { &item.title_tr };
    let body = if use_en {
        item.body_en.clone()
    } else {
        item.body_tr.clone()
    };

    // Never show a "USB Engellendi" / "Blocked" verified toast unless GPO + PnP Code 28
    // evidence verified real installation denial.
    let verified_block = item.category == "blocked_verified" && item.enforced_verified;
    let is_warning = !verified_block;
    let title = if !verified_block && raw_title.to_ascii_lowercase().contains("engellendi") {
        if use_en {
            "RustWard — Policy Warning (Not Blocked)".to_owned()
        } else {
            "RustWard — Politika Uyarısı (Engellenmedi)".to_owned()
        }
    } else {
        raw_title.clone()
    };

    ToastMessage {
        event_id: item.event_id,
        dedup_key: item.dedup_key.clone(),
        title,
        body,
        is_warning,
    }
}

/// Stateful per-user notification coordinator.
pub struct NotifierEngine<C: FeedClient, P: ToastPresenter> {
    client: C,
    presenter: P,
    prefs: NotifierPrefs,
    prefs_path: Option<PathBuf>,
}

impl<C: FeedClient, P: ToastPresenter> NotifierEngine<C, P> {
    /// Construct a notifier engine with loaded preferences.
    #[must_use]
    pub fn new(client: C, presenter: P, prefs: NotifierPrefs, prefs_path: Option<PathBuf>) -> Self {
        Self {
            client,
            presenter,
            prefs,
            prefs_path,
        }
    }

    /// Current persisted preferences (for tests).
    #[cfg(test)]
    #[must_use]
    pub const fn prefs(&self) -> &NotifierPrefs {
        &self.prefs
    }

    /// Reference to the presenter (for tests).
    #[cfg(test)]
    #[must_use]
    pub const fn presenter(&self) -> &P {
        &self.presenter
    }

    /// Mutable reference to the presenter (for message pumping / lifecycle checks).
    pub fn presenter_mut(&mut self) -> &mut P {
        &mut self.presenter
    }

    /// Poll once at `now_ms`, display eligible deduplicated notifications, and persist cursor.
    pub fn poll_once(&mut self, now_ms: i64) -> Result<PollSummary, String> {
        let cold_start = self.prefs.last_event_id <= 0;
        let cursor = (!cold_start).then_some(self.prefs.last_event_id);
        let feed = self.client.fetch_feed(cursor)?;

        let (enabled, allow_blocked, allow_warning, lang) = self.prefs.effective_settings(
            feed.notifications_enabled,
            feed.notify_on_blocked,
            feed.notify_on_unblocked_warning,
            &feed.language,
        );

        let mut summary = PollSummary {
            received: feed.items.len(),
            shown: 0,
            suppressed: 0,
            latest_event_id: feed.latest_event_id.max(self.prefs.last_event_id),
        };

        for item in &feed.items {
            if item.event_id <= self.prefs.last_event_id {
                summary.suppressed += 1;
                continue;
            }
            if cold_start && now_ms.saturating_sub(item.utc_ms) > COLD_START_WINDOW_MS {
                summary.suppressed += 1;
                continue;
            }
            if !enabled {
                summary.suppressed += 1;
                continue;
            }
            let verified_block = item.category == "blocked_verified" && item.enforced_verified;
            if verified_block && !allow_blocked {
                summary.suppressed += 1;
                continue;
            }
            if !verified_block && !allow_warning {
                summary.suppressed += 1;
                continue;
            }
            if self.prefs.is_deduped(&item.dedup_key, now_ms) {
                summary.suppressed += 1;
                continue;
            }

            let toast = format_toast(item, &lang);
            self.presenter.show_toast(&toast)?;
            self.prefs.record_notified(&item.dedup_key, now_ms);
            summary.shown += 1;
        }

        if summary.latest_event_id > self.prefs.last_event_id || summary.shown > 0 {
            self.prefs.last_event_id = summary.latest_event_id;
            if let Some(ref path) = self.prefs_path {
                self.prefs.save(path)?;
            }
        }

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::VecDeque;

    use rustward_ipc::messages::{NotificationFeedView, NotificationItemView};

    use super::*;

    struct MockFeed {
        responses: VecDeque<Result<NotificationFeedView, String>>,
        seen_cursors: Vec<Option<i64>>,
    }

    impl FeedClient for MockFeed {
        fn fetch_feed(
            &mut self,
            after_event_id: Option<i64>,
        ) -> Result<NotificationFeedView, String> {
            self.seen_cursors.push(after_event_id);
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err("empty mock".into()))
        }
    }

    #[derive(Default)]
    struct MockPresenter {
        shown: Vec<ToastMessage>,
    }

    impl ToastPresenter for MockPresenter {
        fn show_toast(&mut self, toast: &ToastMessage) -> Result<(), String> {
            self.shown.push(toast.clone());
            Ok(())
        }
    }

    fn item(id: i64, utc_ms: i64, category: &str, enforced_verified: bool) -> NotificationItemView {
        NotificationItemView {
            event_id: id,
            utc_ms,
            category: category.into(),
            dedup_key: format!("{category}:USBSTOR\\DISK\\1:{id}"),
            title_tr: if enforced_verified {
                "RustWard — USB Engellendi".into()
            } else {
                "RustWard — USB Politikası Uyarısı".into()
            },
            title_en: if enforced_verified {
                "RustWard — USB Blocked".into()
            } else {
                "RustWard — USB Policy Warning".into()
            },
            body_tr: "Aygıt ayrıntısı".into(),
            body_en: "Device detail".into(),
            manufacturer_name: Some("Kingston".into()),
            device_name: Some("Kingston DataTraveler".into()),
            vid_pid: Some("0951:1666".into()),
            enforced_verified,
        }
    }

    #[test]
    fn dedup_cursor_persistence_and_honest_formatting_work() {
        let dir = std::env::temp_dir().join(format!(
            "rw-notifier-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let prefs_path = dir.join("notifier-prefs.json");
        let now = 1_794_100_000_000;

        let mut old = item(5, now - 500_000, "blocked_verified", true);
        old.dedup_key = "blocked_verified:old".into();
        let mut fresh_blocked = item(12, now - 5_000, "blocked_verified", true);
        fresh_blocked.dedup_key = "blocked_verified:kingston".into();
        let mut fake_verified = item(13, now - 4_000, "deny_not_enforced_warning", false);
        fake_verified.title_tr = "RustWard — USB Engellendi".into();
        fake_verified.dedup_key = "warn:sandisk".into();

        let feed1 = NotificationFeedView {
            latest_event_id: 13,
            notifications_enabled: true,
            notify_on_blocked: true,
            notify_on_unblocked_warning: true,
            language: "tr".into(),
            items: vec![old, fresh_blocked.clone(), fake_verified],
        };
        let mut dup_blocked = fresh_blocked;
        dup_blocked.event_id = 14;
        let feed2 = NotificationFeedView {
            latest_event_id: 14,
            notifications_enabled: true,
            notify_on_blocked: true,
            notify_on_unblocked_warning: true,
            language: "tr".into(),
            items: vec![dup_blocked],
        };

        let mock_feed = MockFeed {
            responses: VecDeque::from([Ok(feed1), Ok(feed2)]),
            seen_cursors: Vec::new(),
        };
        let mut engine = NotifierEngine::new(
            mock_feed,
            MockPresenter::default(),
            NotifierPrefs::load(&prefs_path),
            Some(prefs_path.clone()),
        );

        let sum1 = engine.poll_once(now).unwrap();
        assert_eq!(sum1.shown, 2);
        assert_eq!(sum1.suppressed, 1);
        assert_eq!(sum1.latest_event_id, 13);
        assert_eq!(engine.presenter().shown[0].title, "RustWard — USB Engellendi");
        assert!(!engine.presenter().shown[0].is_warning);
        // Never allow an unverified warning to display "Engellendi".
        assert!(engine.presenter().shown[1].is_warning);
        assert!(!engine.presenter().shown[1].title.contains("Engellendi"));

        // Second poll within cooldown suppresses identical dedup_key and uses cursor 13.
        let sum2 = engine.poll_once(now + 5_000).unwrap();
        assert_eq!(sum2.shown, 0);
        assert_eq!(sum2.suppressed, 1);
        assert_eq!(sum2.latest_event_id, 14);

        let reloaded = NotifierPrefs::load(&prefs_path);
        assert_eq!(reloaded.last_event_id, 14);
        assert_eq!(engine.client.seen_cursors, vec![None, Some(13)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_user_overrides_and_toggles_suppress_toasts() {
        let now = 1_794_100_000_000;
        let it = item(20, now - 1_000, "blocked_verified", true);
        let feed = NotificationFeedView {
            latest_event_id: 20,
            notifications_enabled: true,
            notify_on_blocked: true,
            notify_on_unblocked_warning: true,
            language: "tr".into(),
            items: vec![it],
        };
        let mock_feed = MockFeed {
            responses: VecDeque::from([Ok(feed)]),
            seen_cursors: Vec::new(),
        };
        let prefs = NotifierPrefs {
            notify_on_blocked_override: Some(false),
            ..NotifierPrefs::default()
        };
        let mut engine = NotifierEngine::new(mock_feed, MockPresenter::default(), prefs, None);
        let sum = engine.poll_once(now).unwrap();
        assert_eq!(sum.shown, 0);
        assert_eq!(sum.suppressed, 1);
        assert_eq!(engine.prefs().last_event_id, 20);
    }
}
