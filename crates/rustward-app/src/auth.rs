//! Operator authentication, session lifecycle, RBAC enforcement, brute-force
//! backoff, DPAPI-sealed recovery verification, and exit nonces.

use std::collections::HashMap;

use zeroize::Zeroizing;

use rustward_ipc::messages::{AccessLevel, AuthStatusView, AuthUserView, Request};
use rustward_storage::auth::{
    constant_time_str_eq, decode_dpapi_envelope, encode_dpapi_envelope, generate_random_hex_token,
    generate_recovery_key, hash_secret, normalize_recovery_key, validate_password_strength,
    validate_username, verify_secret,
};
use rustward_storage::{AppUserRecord, AuthAttemptOutcome, StorageError, Store, UserRole};

/// Consecutive failed attempts before temporary lockout kicks in.
pub const MAX_AUTH_FAILURES: u32 = 5;
/// Account / client lockout duration on brute-force threshold (5 minutes).
pub const LOCKOUT_DURATION_MS: i64 = 5 * 60 * 1000;
/// Maximum absolute lifetime for a session token (8 hours).
pub const SESSION_ABSOLUTE_TTL_MS: i64 = 8 * 60 * 60 * 1000;
/// Single-use exit nonce validity window (60 seconds).
pub const EXIT_NONCE_TTL_MS: i64 = 60 * 1000;
/// Number of CSPRNG bytes used for session tokens and exit nonces (256-bit).
const OPAQUE_TOKEN_BYTES: usize = 32;
/// Maximum simultaneous in-memory UI sessions retained before pruning oldest.
const MAX_ACTIVE_SESSIONS: usize = 16;

#[cfg(not(windows))]
const TEST_NONWIN_RECOVERY_PREFIX: &str = "test-nonwin-v1:";

/// Authenticated operator context bound to the current request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    /// Canonical username.
    pub username: String,
    /// Human display name.
    pub display_name: String,
    /// Role (`admin` | `read_only`).
    pub role: UserRole,
    /// Creation timestamp (UTC ms).
    pub created_ms: i64,
    /// Absolute expiration timestamp (UTC ms).
    pub expires_at_ms: i64,
}

impl SessionContext {
    #[must_use]
    pub fn to_view(&self) -> AuthUserView {
        AuthUserView {
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            role: self.role.as_str().to_owned(),
            created_ms: self.created_ms,
        }
    }
}

#[derive(Debug, Clone)]
struct SessionRecord {
    token: Zeroizing<String>,
    username: String,
    display_name: String,
    role: UserRole,
    account_created_ms: i64,
    last_activity_ms: i64,
    expires_at_ms: i64,
    locked: bool,
}

#[derive(Debug, Clone)]
struct ExitNonceRecord {
    nonce: Zeroizing<String>,
    expires_ms: i64,
}

#[derive(Debug, Default)]
struct BucketLimiter {
    failures: u32,
    locked_until_ms: Option<i64>,
}

/// Coordinates UI session authentication, lock state, exit nonces, and rate limits.
#[derive(Debug, Default)]
pub struct AuthManager {
    force_auth: bool,
    sessions: Vec<SessionRecord>,
    exit_nonces: Vec<ExitNonceRecord>,
    unknown_user_buckets: HashMap<String, BucketLimiter>,
    exit_fail_bucket: BucketLimiter,
}

impl AuthManager {
    /// Constructs a new session manager. When `force_auth` is false, authentication
    /// enforces automatically once at least one account exists in SQLite (`has_any_users`).
    #[must_use]
    pub fn new(force_auth: bool) -> Self {
        Self {
            force_auth,
            sessions: Vec::new(),
            exit_nonces: Vec::new(),
            unknown_user_buckets: HashMap::new(),
            exit_fail_bucket: BucketLimiter::default(),
        }
    }

    /// Explicitly toggles mandatory in-app authentication (`true` in production service & desktop).
    pub fn set_force_auth(&mut self, enabled: bool) {
        self.force_auth = enabled;
    }

    /// Returns `true` when requests must carry an authenticated session unless exempt.
    pub fn is_enforced(&self, store: &Store) -> Result<bool, StorageError> {
        if self.force_auth {
            return Ok(true);
        }
        store.has_any_users()
    }

    /// Prunes expired sessions, locks idle sessions, and returns current token's index if found.
    fn sync_and_find_token(&mut self, token: Option<&str>, idle_minutes: u32, now_ms: i64) -> Option<usize> {
        let idle_ms = i64::from(idle_minutes.clamp(1, 240)) * 60_000;
        self.sessions.retain(|s| now_ms < s.expires_at_ms);
        self.exit_nonces.retain(|n| now_ms < n.expires_ms);
        for s in &mut self.sessions {
            if !s.locked && now_ms.saturating_sub(s.last_activity_ms) >= idle_ms {
                s.locked = true;
            }
        }
        let candidate = token?;
        self.sessions
            .iter()
            .position(|s| constant_time_str_eq(&s.token, candidate))
    }

    /// Checks client-level brute-force backoff for unknown usernames or exit prompts.
    #[must_use]
    pub fn unknown_bucket_locked_seconds(&self, key: &str, now_ms: i64) -> Option<u64> {
        let b = self.unknown_user_buckets.get(key)?;
        remaining_lock_seconds(b.locked_until_ms, now_ms)
    }

    #[must_use]
    pub fn exit_locked_seconds(&self, now_ms: i64) -> Option<u64> {
        remaining_lock_seconds(self.exit_fail_bucket.locked_until_ms, now_ms)
    }

    pub fn record_unknown_user_failure(&mut self, key: &str, now_ms: i64) -> Option<u64> {
        let entry = self.unknown_user_buckets.entry(key.to_owned()).or_default();
        if entry.locked_until_ms.is_some_and(|u| now_ms >= u) {
            entry.failures = 0;
            entry.locked_until_ms = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= MAX_AUTH_FAILURES {
            let until = now_ms.saturating_add(LOCKOUT_DURATION_MS);
            entry.locked_until_ms = Some(until);
            remaining_lock_seconds(Some(until), now_ms)
        } else {
            None
        }
    }

    pub fn clear_unknown_user_failures(&mut self, key: &str) {
        self.unknown_user_buckets.remove(key);
    }

    pub fn record_exit_failure(&mut self, now_ms: i64) -> Option<u64> {
        if self.exit_fail_bucket.locked_until_ms.is_some_and(|u| now_ms >= u) {
            self.exit_fail_bucket.failures = 0;
            self.exit_fail_bucket.locked_until_ms = None;
        }
        self.exit_fail_bucket.failures = self.exit_fail_bucket.failures.saturating_add(1);
        if self.exit_fail_bucket.failures >= MAX_AUTH_FAILURES {
            let until = now_ms.saturating_add(LOCKOUT_DURATION_MS);
            self.exit_fail_bucket.locked_until_ms = Some(until);
            remaining_lock_seconds(Some(until), now_ms)
        } else {
            None
        }
    }

    pub fn clear_exit_failures(&mut self) {
        self.exit_fail_bucket = BucketLimiter::default();
    }

    /// Computes sanitized auth status view without touching active idle deadline unless asked.
    pub fn status(
        &mut self,
        store: &Store,
        token: Option<&str>,
        idle_minutes: u32,
        now_ms: i64,
        windows_admin_channel: bool,
    ) -> Result<AuthStatusView, StorageError> {
        let has_users = store.has_any_users()?;
        let setup_required = !has_users;
        let auth_enforced = self.force_auth || has_users;

        let idx = self.sync_and_find_token(token, idle_minutes, now_ms);
        let (authenticated, locked, current_user, session_expires_at_ms) = match idx {
            Some(i) => {
                let s = &self.sessions[i];
                if s.locked {
                    (
                        false,
                        true,
                        Some(AuthUserView {
                            username: s.username.clone(),
                            display_name: s.display_name.clone(),
                            role: s.role.as_str().to_owned(),
                            created_ms: s.account_created_ms,
                        }),
                        Some(s.expires_at_ms),
                    )
                } else {
                    (
                        true,
                        false,
                        Some(AuthUserView {
                            username: s.username.clone(),
                            display_name: s.display_name.clone(),
                            role: s.role.as_str().to_owned(),
                            created_ms: s.account_created_ms,
                        }),
                        Some(s.expires_at_ms),
                    )
                }
            }
            None => (false, false, None, None),
        };

        Ok(AuthStatusView {
            setup_required,
            auth_enforced,
            authenticated,
            locked,
            current_user,
            session_expires_at_ms,
            idle_timeout_minutes: idle_minutes,
            lockout_remaining_seconds: None,
            windows_admin_channel,
        })
    }

    /// Validates token (refreshing idle activity timer if valid), returning `Ok(Some(ctx))`
    /// only for active unlocked non-expired tokens.
    pub fn touch_authenticated_session(
        &mut self,
        token: Option<&str>,
        idle_minutes: u32,
        now_ms: i64,
    ) -> Option<SessionContext> {
        let idx = self.sync_and_find_token(token, idle_minutes, now_ms)?;
        let rec = &mut self.sessions[idx];
        if rec.locked {
            return None;
        }
        rec.last_activity_ms = now_ms;
        Some(SessionContext {
            username: rec.username.clone(),
            display_name: rec.display_name.clone(),
            role: rec.role,
            created_ms: rec.account_created_ms,
            expires_at_ms: rec.expires_at_ms,
        })
    }

    /// Issues a brand-new 256-bit opaque session token for `user`.
    pub fn issue_session(&mut self, user: &AppUserRecord, now_ms: i64) -> Result<(Zeroizing<String>, i64), String> {
        let token = generate_random_hex_token(OPAQUE_TOKEN_BYTES)?;
        let expires_at_ms = now_ms.saturating_add(SESSION_ABSOLUTE_TTL_MS);
        while self.sessions.len() >= MAX_ACTIVE_SESSIONS {
            self.sessions.remove(0);
        }
        self.sessions.push(SessionRecord {
            token: token.clone(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: user.role,
            account_created_ms: user.created_ms,
            last_activity_ms: now_ms,
            expires_at_ms,
            locked: false,
        });
        Ok((token, expires_at_ms))
    }

    /// Removes a specific session token cleanly on Logout. Returns removed username if any.
    pub fn revoke_token(&mut self, token: Option<&str>) -> Option<String> {
        let candidate = token?;
        if let Some(pos) = self
            .sessions
            .iter()
            .position(|s| constant_time_str_eq(&s.token, candidate))
        {
            let removed = self.sessions.remove(pos);
            Some(removed.username)
        } else {
            None
        }
    }

    /// Revokes all active sessions owned by `username` (e.g., on password reset or deletion).
    pub fn revoke_user_sessions(&mut self, username: &str) {
        self.sessions
            .retain(|s| !s.username.eq_ignore_ascii_case(username));
    }

    /// Locks the specified session token immediately while preserving identity display.
    pub fn lock_token(&mut self, token: Option<&str>, idle_minutes: u32, now_ms: i64) -> Option<String> {
        let idx = self.sync_and_find_token(token, idle_minutes, now_ms)?;
        let rec = &mut self.sessions[idx];
        rec.locked = true;
        Some(rec.username.clone())
    }

    /// Generates and tracks a short-lived single-use exit nonce for native shell verification.
    pub fn issue_exit_nonce(&mut self, now_ms: i64) -> Result<Zeroizing<String>, String> {
        self.exit_nonces.retain(|n| now_ms < n.expires_ms);
        let nonce = generate_random_hex_token(OPAQUE_TOKEN_BYTES)?;
        self.exit_nonces.push(ExitNonceRecord {
            nonce: nonce.clone(),
            expires_ms: now_ms.saturating_add(EXIT_NONCE_TTL_MS),
        });
        Ok(nonce)
    }

    /// Consumes a single-use exit nonce if valid and unexpired.
    pub fn consume_exit_nonce(&mut self, candidate: &str, now_ms: i64) -> bool {
        self.exit_nonces.retain(|n| now_ms < n.expires_ms);
        if let Some(pos) = self
            .exit_nonces
            .iter()
            .position(|n| constant_time_str_eq(&n.nonce, candidate))
        {
            self.exit_nonces.remove(pos);
            true
        } else {
            false
        }
    }

    /// Checks whether `request` may proceed unauthenticated even when auth is enforced.
    #[must_use]
    pub fn is_public_or_boot_request(request: &Request) -> bool {
        matches!(
            request,
            Request::GetAuthStatus
                | Request::SetupInitialAdmin { .. }
                | Request::Login { .. }
                | Request::Logout
                | Request::LockSession
                | Request::ResetPasswordWithRecovery { .. }
                | Request::VerifyExitAuthorization { .. }
                | Request::GetNotificationFeed { .. }
        )
    }

    /// Checks RBAC: returns `true` when the request requires in-app `admin` role.
    #[must_use]
    pub fn requires_admin_role(request: &Request) -> bool {
        request.access_level() == AccessLevel::Administrator
    }

    /// Refreshes display/role cached on active sessions if needed (e.g. sanity lookup).
    pub fn authenticate_credentials(
        &mut self,
        store: &mut Store,
        username: &str,
        password: &str,
        client_bucket: &str,
        now_ms: i64,
    ) -> Result<AuthAttemptOutcome, String> {
        if let Some(secs) = self.unknown_bucket_locked_seconds(client_bucket, now_ms) {
            return Ok(AuthAttemptOutcome::Locked {
                username: username.trim().to_owned(),
                locked_until_ms: now_ms.saturating_add(
                    i64::try_from(secs).unwrap_or(300).saturating_mul(1000),
                ),
                failed_attempts: MAX_AUTH_FAILURES,
            });
        }
        let outcome = store
            .authenticate_user(username, password, MAX_AUTH_FAILURES, LOCKOUT_DURATION_MS)
            .map_err(|e| e.to_string())?;
        match &outcome {
            AuthAttemptOutcome::Success(_) => {
                self.clear_unknown_user_failures(client_bucket);
            }
            AuthAttemptOutcome::InvalidCredentials {
                now_locked_until_ms,
                ..
            } => {
                if now_locked_until_ms.is_none() {
                    // Unknown account or not yet per-account locked: also track bucket backoff
                    // so attacker probing many unknown usernames is rate-limited.
                    if let Some(secs) = self.record_unknown_user_failure(client_bucket, now_ms) {
                        return Ok(AuthAttemptOutcome::Locked {
                            username: username.trim().to_owned(),
                            locked_until_ms: now_ms.saturating_add(
                                i64::try_from(secs).unwrap_or(300).saturating_mul(1000),
                            ),
                            failed_attempts: MAX_AUTH_FAILURES,
                        });
                    }
                }
            }
            AuthAttemptOutcome::Locked { .. } => {}
        }
        Ok(outcome)
    }
}

/// Computes positive remaining seconds for a lockout expiration timestamp.
#[must_use]
pub fn remaining_lock_seconds(until_ms: Option<i64>, now_ms: i64) -> Option<u64> {
    let until = until_ms?;
    if now_ms >= until {
        return None;
    }
    let diff = until.saturating_sub(now_ms);
    let secs = (diff + 999) / 1000;
    u64::try_from(secs).ok()
}

/// Validates username and password before hashing and generates + seals a fresh recovery key.
pub fn prepare_admin_credentials(
    username: &str,
    password: &str,
) -> Result<(String, String, Zeroizing<String>, String), String> {
    let canonical_user = validate_username(username)?;
    validate_password_strength(Some(&canonical_user), password)?;
    let password_hash = hash_secret(password)?;
    let (recovery_key, sealed_recovery) = generate_and_seal_recovery_key()?;
    Ok((canonical_user, password_hash, recovery_key, sealed_recovery))
}

pub type PreparedOperatorCredentials = (String, String, Option<Zeroizing<String>>, Option<String>);

/// Validates credentials for any operator (`admin` receives a sealed recovery key;
/// `read_only` receives `None`).
pub fn prepare_operator_credentials(
    username: &str,
    password: &str,
    role: UserRole,
) -> Result<PreparedOperatorCredentials, String> {
    let canonical_user = validate_username(username)?;
    validate_password_strength(Some(&canonical_user), password)?;
    let password_hash = hash_secret(password)?;
    if role == UserRole::Admin {
        let (rk, sealed) = generate_and_seal_recovery_key()?;
        Ok((canonical_user, password_hash, Some(rk), Some(sealed)))
    } else {
        Ok((canonical_user, password_hash, None, None))
    }
}

/// Generates a one-time `RWREC-...` recovery key, computes its Argon2id verifier hash,
/// and machine-seals that verifier with Windows DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`).
pub fn generate_and_seal_recovery_key() -> Result<(Zeroizing<String>, String), String> {
    let key = generate_recovery_key()?;
    let norm = normalize_recovery_key(&key);
    let verifier_phc = Zeroizing::new(hash_secret(&norm)?);
    let sealed = seal_verifier_envelope(&verifier_phc)?;
    Ok((key, sealed))
}

/// Seals a verifier PHC hash string via Windows LocalMachine DPAPI envelope.
pub fn seal_verifier_envelope(verifier_phc: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        let ct = rustward_windows::dpapi::seal_machine_secret(verifier_phc.as_bytes())?;
        Ok(encode_dpapi_envelope(&ct))
    }
    #[cfg(not(windows))]
    {
        let _ = (decode_dpapi_envelope, encode_dpapi_envelope);
        Ok(format!("{TEST_NONWIN_RECOVERY_PREFIX}{verifier_phc}"))
    }
}

/// Unseals a stored recovery verifier envelope and verifies `candidate_recovery_key`.
#[must_use]
pub fn verify_recovery_key_against_sealed(candidate_recovery_key: &str, stored: &str) -> bool {
    let norm = normalize_recovery_key(candidate_recovery_key);
    if norm.len() < 10 {
        return false;
    }
    #[cfg(windows)]
    {
        let Ok(ct) = decode_dpapi_envelope(stored) else {
            return false;
        };
        let Ok(plain_bytes) = rustward_windows::dpapi::unseal_machine_secret(&ct) else {
            return false;
        };
        let Ok(verifier_phc) = String::from_utf8(plain_bytes) else {
            return false;
        };
        let wrapped = Zeroizing::new(verifier_phc);
        verify_secret(&norm, &wrapped)
    }
    #[cfg(not(windows))]
    {
        let Some(verifier_phc) = stored.strip_prefix(TEST_NONWIN_RECOVERY_PREFIX) else {
            return false;
        };
        verify_secret(&norm, verifier_phc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_sealing_and_constant_time_token_work() -> Result<(), String> {
        let (key, sealed) = generate_and_seal_recovery_key()?;
        assert!(verify_recovery_key_against_sealed(&key, &sealed));
        assert!(verify_recovery_key_against_sealed(
            &key.to_ascii_lowercase().replace('-', " "),
            &sealed
        ));
        assert!(!verify_recovery_key_against_sealed("RWREC-WRONG-WRONG-WRONG-WRONG-WRONG", &sealed));
        assert!(constant_time_str_eq("abc123", "abc123"));
        assert!(!constant_time_str_eq("abc123", "abc124"));
        Ok(())
    }
}
