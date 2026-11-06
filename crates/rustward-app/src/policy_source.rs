//! Sources of the read-only Device Installation policy capture.

use rustward_enforcement::policy_inspect::CapturedPolicy;

/// Supplies a read-only capture of the Restrictions policy.
pub trait PolicySource: Send + Sync {
    /// Capture now. Never writes anything.
    ///
    /// # Errors
    /// When the policy cannot be read (e.g. not on Windows).
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String>;
    /// `windows_registry_read_only` or `fixture`.
    fn name(&self) -> &'static str;
}

/// The Windows registry, read with `KEY_READ` only (see
/// `rustward_windows::policy_reader`). Off Windows every capture fails.
#[derive(Debug, Default, Clone, Copy)]
pub struct LivePolicySource;

impl PolicySource for LivePolicySource {
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String> {
        rustward_windows::capture_device_install_policy(now_ms)
    }
    fn name(&self) -> &'static str {
        "windows_registry_read_only"
    }
}

/// A fixed capture (tests, development backend with a synthetic file).
#[derive(Debug, Clone)]
pub struct StaticPolicySource(pub CapturedPolicy);

impl PolicySource for StaticPolicySource {
    fn capture(&self, now_ms: i64) -> Result<CapturedPolicy, String> {
        Ok(CapturedPolicy {
            captured_ms: now_ms,
            ..self.0.clone()
        })
    }
    fn name(&self) -> &'static str {
        "fixture"
    }
}
