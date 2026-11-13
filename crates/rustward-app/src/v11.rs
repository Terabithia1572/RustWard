//! V1.1 enterprise security, authentication, bulk policy operations,
//! audit querying, desktop notification feed, About metadata, and accurate
//! protection categorization.

use std::collections::BTreeSet;

use rustward_core::catalog::BrandEntry;
use rustward_core::classify::DeviceCategory;
use rustward_core::evaluate::{Verdict, evaluate_snapshot};
use rustward_core::policy_edit::{BulkManufacturerAction, PolicyEdit, apply_edit};
use rustward_enforcement::compound_policy::{
    CompoundPolicyPlanView, ConfiguredIntention, DeviceOutcomeStatus, compile_compound_policy,
};
use rustward_ipc::messages::{
    AboutInfoView, AccessLevel, AppUserView, AuditChainVerificationView, AuditPageView,
    AuthStatusView, BulkManufacturerApplyResultView, BulkManufacturerPreviewView,
    ExitAuthorizationView, LoginResultView, MutationView, NotificationFeedView,
    NotificationItemView, RecoveryResetView, Request, ResponseBody,
};
use rustward_ipc::{ClientIdentity, ErrorCode, IpcError};
use rustward_storage::auth::{hash_secret, validate_password_strength};
use rustward_storage::{
    AuthAttemptOutcome, ChainStatus, EventFilter, NewEvent, Severity, UserRole,
};

use crate::auth::{
    SessionContext, generate_and_seal_recovery_key, prepare_admin_credentials,
    prepare_operator_credentials, remaining_lock_seconds, verify_recovery_key_against_sealed,
};
use crate::{AppService, Inner, edit_err, empty_snapshot, l10n, storage_err};

/// Accurate Phase 13 dashboard protection categorization without false
/// simulation/inactive warnings when Windows GPO enforcement is active.
pub(crate) struct DashboardProtectionSummary {
    pub protection_category: String,
    pub protection_detail_tr: String,
    pub protection_detail_en: String,
    pub protection_verified: bool,
    pub not_validated_banner: Option<String>,
    pub pending_policy_apply: bool,
    pub approved_policy_version: Option<u64>,
}

fn brand_has_custom_identifier(brand: &BrandEntry) -> bool {
    brand.identifiers.iter().any(|i| {
        let src = i.source.trim().to_ascii_lowercase();
        !src.is_empty()
            && (src.contains("manual")
                || src.contains("custom")
                || src.contains("admin")
                || src.contains("operator")
                || src.contains("user"))
    })
}

pub(crate) fn compute_dashboard_protection(
    service: &AppService,
    store: &rustward_storage::Store,
    compound_plan: Option<&CompoundPolicyPlanView>,
    windows_protection: &rustward_ipc::messages::WindowsProtectionView,
    synthetic_data_present: bool,
    v: Option<&crate::Validated>,
) -> DashboardProtectionSummary {
    let approved = store.approved_policy().ok().flatten();
    let approved_policy_version = approved.as_ref().map(|a| a.policy_version);

    let pending_policy_apply = match (compound_plan, approved.as_ref()) {
        (Some(plan), Some(app)) => {
            app.deny_ids != plan.compiled.deny_hardware_ids
                || app.allow_ids != plan.compiled.allow_hardware_ids
                || !plan.diff.is_synchronized
        }
        (Some(plan), None) => !plan.compiled.deny_hardware_ids.is_empty() && !plan.is_applied,
        _ => false,
    };

    let has_active_gpo_denies = compound_plan
        .is_some_and(|p| p.observed.raw_gpo_present && !p.observed.active_denies.is_empty());
    let plan_synchronized = compound_plan.is_some_and(|p| p.diff.is_synchronized);
    let any_conflict_or_unblocked_deny = compound_plan.is_some_and(|p| {
        p.manufacturers.iter().any(|m| {
            m.configured_intention == ConfiguredIntention::ExplicitDeny
                && matches!(
                    m.device_outcome,
                    DeviceOutcomeStatus::Accessible | DeviceOutcomeStatus::Unknown
                )
        }) || p
            .manufacturers
            .iter()
            .any(|m| m.windows_policy == rustward_enforcement::compound_policy::WindowsPolicyStatus::Conflict)
    });

    let real_denials_observed = windows_protection.denied_now > 0
        || matches!(
            windows_protection.state.as_str(),
            "verified_active" | "profile_verified" | "denial_observed"
        );

    let is_live = service.is_live_windows();
    let denied_id_count = compound_plan.map_or(0, |p| p.observed.active_denies.len());
    let _ = v;

    let (protection_category, protection_detail_tr, protection_detail_en, protection_verified, not_validated_banner) =
        if (real_denials_observed || has_active_gpo_denies) && any_conflict_or_unblocked_deny
        {
            (
                "protection_partial".to_owned(),
                format!(
                    "Windows Grup İlkesi etkin ({denied_id_count} kural), ancak bağlı bazı reddedilen USB aygıtları için yeniden bağlama veya çakışma giderme gerekiyor."
                ),
                format!(
                    "Windows Group Policy is active ({denied_id_count} rules), though some connected denied USB devices need reconnection or conflict resolution."
                ),
                windows_protection.denied_now > 0,
                None,
            )
        } else if real_denials_observed {
            (
                "protection_active".to_owned(),
                format!(
                    "Windows engelleme politikası aktif ve doğrulandı: {} bağlı USB aygıtının kurulumu PnP Kod 28 ile engellendi.",
                    windows_protection.denied_now
                ),
                format!(
                    "Windows blocking policy is active and verified: {} connected USB device(s) denied installation with PnP Code 28.",
                    windows_protection.denied_now
                ),
                true,
                None,
            )
        } else if has_active_gpo_denies && plan_synchronized {
            (
                "policy_applied_no_target".to_owned(),
                format!(
                    "Windows Grup İlkesi uygulandı ve güncel ({denied_id_count} donanım kimliği engelli); şu anda bağlı engelli USB depolama aygıtı yok."
                ),
                format!(
                    "Windows Group Policy is applied and synchronized ({denied_id_count} hardware IDs blocked); no denied USB storage device is currently attached."
                ),
                true,
                None,
            )
        } else if has_active_gpo_denies {
            (
                "protection_partial".to_owned(),
                "Windows Grup İlkesi etkin, ancak bekleyen yerel değişiklikler henüz Windows'a uygulanmadı.".to_owned(),
                "Windows Group Policy is active, but pending local changes have not yet been committed to Windows.".to_owned(),
                false,
                None,
            )
        } else if pending_policy_apply {
            (
                "pending_apply".to_owned(),
                "Üretici kuralları hazırlandı; Windows Grup İlkesi henüz uygulanmadı.".to_owned(),
                "Manufacturer rules are configured; Windows Group Policy has not been applied yet.".to_owned(),
                false,
                Some(crate::NOT_VALIDATED_BANNER_TR.to_owned()),
            )
        } else if synthetic_data_present && !is_live {
            (
                "protection_inactive".to_owned(),
                "Önizleme modu: yerel envanter verileri Windows işletim sistemi ilkesi yazmaz.".to_owned(),
                "Preview mode: local fixture inventory does not write Windows Group Policy.".to_owned(),
                false,
                Some(crate::NOT_VALIDATED_BANNER_TR.to_owned()),
            )
        } else {
            (
                "protection_inactive".to_owned(),
                "Etkin bir Windows USB engelleme Grup İlkesi yapılandırılmadı.".to_owned(),
                "No active Windows USB restriction Group Policy is currently configured.".to_owned(),
                false,
                Some(crate::NOT_VALIDATED_BANNER_TR.to_owned()),
            )
        };

    DashboardProtectionSummary {
        protection_category,
        protection_detail_tr,
        protection_detail_en,
        protection_verified,
        not_validated_banner,
        pending_policy_apply,
        approved_policy_version,
    }
}

impl AppService {
    pub(crate) fn current_windows_user(&self) -> Option<String> {
        (self.windows_user_resolver)()
    }

    pub(crate) fn get_auth_status_view(
        &self,
        auth_token: Option<&str>,
        identity: &ClientIdentity,
    ) -> Result<AuthStatusView, IpcError> {
        let mut g = self.lock()?;
        let settings = g.store.settings().map_err(storage_err)?;
        let now_ms = self.clock.now_ms();
        let Inner { store, auth, .. } = &mut *g;
        auth.status(
            store,
            auth_token,
            settings.session_idle_timeout_minutes,
            now_ms,
            identity.is_administrator,
        )
        .map_err(storage_err)
    }

    pub(crate) fn setup_initial_admin(
        &self,
        username: &str,
        display_name: &str,
        password: &str,
        identity: &ClientIdentity,
    ) -> Result<LoginResultView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator rights (elevated) are required for this operation",
            ));
        }
        let (canonical_user, password_hash, recovery_key, sealed_recovery) =
            prepare_admin_credentials(username, password)
                .map_err(|e| IpcError::new(ErrorCode::ValidationFailed, e))?;
        let now_ms = self.clock.now_ms();
        let mut g = self.lock()?;
        let settings = g.store.settings().map_err(storage_err)?;
        let user = g
            .store
            .create_initial_admin(&canonical_user, display_name, &password_hash, &sealed_recovery)
            .map_err(|e| match e {
                rustward_storage::StorageError::Invalid(msg) => {
                    if msg.contains("already been created") {
                        IpcError::new(ErrorCode::Conflict, msg)
                    } else {
                        IpcError::new(ErrorCode::ValidationFailed, msg)
                    }
                }
                other => storage_err(other),
            })?;
        let (token, expires_at_ms) = g
            .auth
            .issue_session(&user, now_ms)
            .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;
        Ok(LoginResultView {
            user: rustward_ipc::messages::AuthUserView {
                username: user.username,
                display_name: user.display_name,
                role: user.role.as_str().to_owned(),
                created_ms: user.created_ms,
            },
            session_token: (*token).clone(),
            expires_at_ms,
            idle_timeout_minutes: settings.session_idle_timeout_minutes,
            recovery_key_once: Some((*recovery_key).clone()),
        })
    }

    pub(crate) fn login_operator(
        &self,
        username: &str,
        password: &str,
        identity: &ClientIdentity,
    ) -> Result<LoginResultView, IpcError> {
        let now_ms = self.clock.now_ms();
        let windows_user = self.current_windows_user();
        let mut g = self.lock()?;
        if !g.store.has_any_users().map_err(storage_err)? {
            return Err(IpcError::new(
                ErrorCode::Conflict,
                "initial administrator setup must be completed before signing in",
            ));
        }
        let settings = g.store.settings().map_err(storage_err)?;
        let computer_name = Self::validated(&g.store)
            .map(|v| v.policy.policy().workstation_id.clone())
            .unwrap_or_else(|_| "WORKSTATION".to_owned());
        let client_bucket = identity.actor();

        let outcome = {
            let Inner { store, auth, .. } = &mut *g;
            auth.authenticate_credentials(store, username, password, &client_bucket, now_ms)
                .map_err(|e| IpcError::new(ErrorCode::Internal, e))?
        };

        match outcome {
            AuthAttemptOutcome::Success(user) => {
                let (token, expires_at_ms) = g
                    .auth
                    .issue_session(&user, now_ms)
                    .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Info,
                        kind: "auth_login_succeeded".into(),
                        device_key: None,
                        message: format!("operator '{}' signed in", user.username),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "computer_name": computer_name,
                            "actor_username": user.username,
                            "role": user.role.as_str(),
                            "windows_user": windows_user,
                        }),
                    })
                    .map_err(storage_err)?;
                Ok(LoginResultView {
                    user: rustward_ipc::messages::AuthUserView {
                        username: user.username,
                        display_name: user.display_name,
                        role: user.role.as_str().to_owned(),
                        created_ms: user.created_ms,
                    },
                    session_token: (*token).clone(),
                    expires_at_ms,
                    idle_timeout_minutes: settings.session_idle_timeout_minutes,
                    recovery_key_once: None,
                })
            }
            AuthAttemptOutcome::InvalidCredentials {
                username: target,
                failed_attempts,
                ..
            } => {
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Warning,
                        kind: "auth_login_failed".into(),
                        device_key: None,
                        message: format!("failed login attempt for username '{target}'"),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "computer_name": computer_name,
                            "target_username": target,
                            "failed_attempts": failed_attempts,
                            "windows_user": windows_user,
                        }),
                    })
                    .map_err(storage_err)?;
                Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    "invalid username or password",
                ))
            }
            AuthAttemptOutcome::Locked {
                username: target,
                locked_until_ms,
                failed_attempts,
            } => {
                let secs = remaining_lock_seconds(Some(locked_until_ms), now_ms).unwrap_or(60);
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Warning,
                        kind: "auth_login_locked".into(),
                        device_key: None,
                        message: format!(
                            "account '{target}' temporarily locked for {secs}s after {failed_attempts} failed attempts"
                        ),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "computer_name": computer_name,
                            "target_username": target,
                            "failed_attempts": failed_attempts,
                            "lockout_seconds": secs,
                            "windows_user": windows_user,
                        }),
                    })
                    .map_err(storage_err)?;
                Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    format!("account temporarily locked; try again in {secs} seconds"),
                ))
            }
        }
    }

    pub(crate) fn logout_operator(
        &self,
        auth_token: Option<&str>,
        identity: &ClientIdentity,
    ) -> Result<AuthStatusView, IpcError> {
        let windows_user = self.current_windows_user();
        let now_ms = self.clock.now_ms();
        let mut g = self.lock()?;
        let settings = g.store.settings().map_err(storage_err)?;
        let computer_name = Self::validated(&g.store)
            .map(|v| v.policy.policy().workstation_id.clone())
            .unwrap_or_else(|_| "WORKSTATION".to_owned());
        if let Some(username) = g.auth.revoke_token(auth_token) {
            let _ = g.store.append_event(&NewEvent {
                severity: Severity::Info,
                kind: "auth_logout".into(),
                device_key: None,
                message: format!("operator '{username}' signed out"),
                simulated: false,
                enforcement_state: self.enforcement_state_code().into(),
                policy_version: None,
                details: serde_json::json!({
                    "computer_name": computer_name,
                    "actor_username": username,
                    "windows_user": windows_user,
                }),
            });
        }
        let Inner { store, auth, .. } = &mut *g;
        auth.status(
            store,
            None,
            settings.session_idle_timeout_minutes,
            now_ms,
            identity.is_administrator,
        )
        .map_err(storage_err)
    }

    pub(crate) fn lock_operator_session(
        &self,
        auth_token: Option<&str>,
        identity: &ClientIdentity,
    ) -> Result<AuthStatusView, IpcError> {
        let windows_user = self.current_windows_user();
        let now_ms = self.clock.now_ms();
        let mut g = self.lock()?;
        let settings = g.store.settings().map_err(storage_err)?;
        let computer_name = Self::validated(&g.store)
            .map(|v| v.policy.policy().workstation_id.clone())
            .unwrap_or_else(|_| "WORKSTATION".to_owned());
        if let Some(username) =
            g.auth
                .lock_token(auth_token, settings.session_idle_timeout_minutes, now_ms)
        {
            let _ = g.store.append_event(&NewEvent {
                severity: Severity::Info,
                kind: "auth_session_locked".into(),
                device_key: None,
                message: format!("session locked for '{username}'"),
                simulated: false,
                enforcement_state: self.enforcement_state_code().into(),
                policy_version: None,
                details: serde_json::json!({
                    "computer_name": computer_name,
                    "actor_username": username,
                    "windows_user": windows_user,
                }),
            });
        }
        let Inner { store, auth, .. } = &mut *g;
        auth.status(
            store,
            auth_token,
            settings.session_idle_timeout_minutes,
            now_ms,
            identity.is_administrator,
        )
        .map_err(storage_err)
    }

    pub(crate) fn change_operator_password(
        &self,
        session: Option<&SessionContext>,
        current_password: &str,
        new_password: &str,
    ) -> Result<ResponseBody, IpcError> {
        let Some(sess) = session else {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "authentication required",
            ));
        };
        validate_password_strength(Some(&sess.username), new_password)
            .map_err(|e| IpcError::new(ErrorCode::ValidationFailed, e))?;

        let now_ms = self.clock.now_ms();
        let mut g = self.lock()?;
        let outcome = g
            .store
            .authenticate_user(&sess.username, current_password, 5, 300_000)
            .map_err(storage_err)?;
        match outcome {
            AuthAttemptOutcome::Success(_) => {}
            AuthAttemptOutcome::Locked {
                locked_until_ms, ..
            } => {
                let secs = remaining_lock_seconds(Some(locked_until_ms), now_ms).unwrap_or(60);
                return Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    format!("account temporarily locked; try again in {secs} seconds"),
                ));
            }
            AuthAttemptOutcome::InvalidCredentials { .. } => {
                return Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    "current password is incorrect",
                ));
            }
        }
        let new_hash = hash_secret(new_password)
            .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;
        g.store
            .update_user_password(&sess.username, &new_hash, None, false, &sess.username)
            .map_err(storage_err)?;
        Ok(ResponseBody::Done {
            message: "Password updated successfully.".into(),
            message_tr: "Parola başarıyla güncellendi.".into(),
        })
    }

    pub(crate) fn reset_password_with_recovery(
        &self,
        username: &str,
        recovery_key: &str,
        new_password: &str,
        identity: &ClientIdentity,
    ) -> Result<RecoveryResetView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator rights (elevated) are required for this operation",
            ));
        }
        let now_ms = self.clock.now_ms();
        let bucket = format!("recovery:{}", identity.actor());
        let mut g = self.lock()?;
        if let Some(secs) = g.auth.unknown_bucket_locked_seconds(&bucket, now_ms) {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                format!("too many failed recovery attempts; try again in {secs} seconds"),
            ));
        }
        let row = g.store.get_recovery_sealed(username).map_err(storage_err)?;
        let Some((canonical_user, role, Some(sealed))) = row else {
            g.auth.record_unknown_user_failure(&bucket, now_ms);
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "recovery key is invalid or not configured for this account",
            ));
        };
        if role != UserRole::Admin {
            g.auth.record_unknown_user_failure(&bucket, now_ms);
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "recovery key is invalid or not configured for this account",
            ));
        }
        if !verify_recovery_key_against_sealed(recovery_key, &sealed) {
            g.auth.record_unknown_user_failure(&bucket, now_ms);
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "recovery key is invalid or not configured for this account",
            ));
        }
        validate_password_strength(Some(&canonical_user), new_password)
            .map_err(|e| IpcError::new(ErrorCode::ValidationFailed, e))?;
        let new_hash = hash_secret(new_password)
            .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;
        let (new_recovery_key, new_sealed) = generate_and_seal_recovery_key()
            .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;

        g.store
            .update_user_password(
                &canonical_user,
                &new_hash,
                Some(&new_sealed),
                true,
                &identity.actor(),
            )
            .map_err(storage_err)?;
        g.auth.clear_unknown_user_failures(&bucket);
        g.auth.revoke_user_sessions(&canonical_user);

        Ok(RecoveryResetView {
            username: canonical_user,
            new_recovery_key_once: Some((*new_recovery_key).clone()),
            message: "Password reset completed and replacement recovery key issued.".into(),
            message_tr: "Parola kurtarma anahtarıyla sıfırlandı ve yeni tek kullanımlık kurtarma anahtarı oluşturuldu.".into(),
        })
    }

    pub(crate) fn create_app_user_cmd(
        &self,
        username: &str,
        display_name: &str,
        role_str: &str,
        password: &str,
        actor: &str,
    ) -> Result<LoginResultView, IpcError> {
        let Some(role) = UserRole::parse(role_str.trim()) else {
            return Err(IpcError::new(
                ErrorCode::ValidationFailed,
                "role must be 'admin' or 'read_only'",
            ));
        };
        let (canonical_user, password_hash, recovery_once, sealed_opt) =
            prepare_operator_credentials(username, password, role)
                .map_err(|e| IpcError::new(ErrorCode::ValidationFailed, e))?;
        let mut g = self.lock()?;
        let settings = g.store.settings().map_err(storage_err)?;
        let user = g
            .store
            .create_app_user(
                &canonical_user,
                display_name,
                role,
                &password_hash,
                sealed_opt.as_deref(),
                actor,
            )
            .map_err(|e| match e {
                rustward_storage::StorageError::Invalid(m) => {
                    IpcError::new(ErrorCode::ValidationFailed, m)
                }
                other => storage_err(other),
            })?;

        Ok(LoginResultView {
            user: rustward_ipc::messages::AuthUserView {
                username: user.username,
                display_name: user.display_name,
                role: user.role.as_str().to_owned(),
                created_ms: user.created_ms,
            },
            session_token: String::new(),
            expires_at_ms: 0,
            idle_timeout_minutes: settings.session_idle_timeout_minutes,
            recovery_key_once: recovery_once.map(|rk| (*rk).clone()),
        })
    }

    pub(crate) fn list_app_users_cmd(&self) -> Result<Vec<AppUserView>, IpcError> {
        let g = self.lock()?;
        let rows = g.store.list_app_users().map_err(storage_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AppUserView {
                username: r.username,
                display_name: r.display_name,
                role: r.role.as_str().to_owned(),
                failed_attempts: r.failed_attempts,
                locked_until_ms: r.locked_until_ms,
                created_ms: r.created_ms,
                has_recovery_key: r.has_recovery_key,
            })
            .collect())
    }

    pub(crate) fn delete_app_user_cmd(
        &self,
        target_username: &str,
        actor: &str,
    ) -> Result<ResponseBody, IpcError> {
        if target_username.trim().eq_ignore_ascii_case(actor.trim()) {
            return Err(IpcError::new(
                ErrorCode::ValidationFailed,
                "signed-in administrator cannot delete their own active account",
            ));
        }
        let mut g = self.lock()?;
        g.store
            .delete_app_user(target_username, actor)
            .map_err(|e| match e {
                rustward_storage::StorageError::Invalid(m) => {
                    IpcError::new(ErrorCode::ValidationFailed, m)
                }
                other => storage_err(other),
            })?;
        g.auth.revoke_user_sessions(target_username);
        Ok(ResponseBody::Done {
            message: format!("Operator account '{}' removed.", target_username.trim()),
            message_tr: format!("'{}' operatör hesabı kaldırıldı.", target_username.trim()),
        })
    }

    pub(crate) fn verify_exit_authorization(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ExitAuthorizationView, IpcError> {
        let now_ms = self.clock.now_ms();
        let windows_user = self.current_windows_user();
        let mut g = self.lock()?;
        let computer_name = Self::validated(&g.store)
            .map(|v| v.policy.policy().workstation_id.clone())
            .unwrap_or_else(|_| "WORKSTATION".to_owned());

        if let Some(secs) = g.auth.exit_locked_seconds(now_ms) {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                format!("exit verification locked after failed attempts; try again in {secs} seconds"),
            ));
        }

        let outcome = g
            .store
            .authenticate_user(username, password, 5, 300_000)
            .map_err(storage_err)?;
        match outcome {
            AuthAttemptOutcome::Success(user) if user.role == UserRole::Admin => {
                g.auth.clear_exit_failures();
                let nonce = g
                    .auth
                    .issue_exit_nonce(now_ms)
                    .map_err(|e| IpcError::new(ErrorCode::Internal, e))?;
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Info,
                        kind: "auth_exit_authorized".into(),
                        device_key: None,
                        message: format!(
                            "administrator '{}' authorized RustWard desktop exit",
                            user.username
                        ),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "computer_name": computer_name,
                            "actor_username": user.username,
                            "windows_user": windows_user,
                        }),
                    })
                    .map_err(storage_err)?;
                Ok(ExitAuthorizationView {
                    authorized: true,
                    authorized_by: user.username,
                    exit_nonce: (*nonce).clone(),
                    message_tr: "Yönetici doğrulaması başarılı; uygulama güvenli şekilde kapatılıyor.".into(),
                    message_en: "Administrator verification succeeded; exiting application cleanly.".into(),
                })
            }
            AuthAttemptOutcome::Success(user) => {
                g.auth.record_exit_failure(now_ms);
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Warning,
                        kind: "auth_exit_denied".into(),
                        device_key: None,
                        message: format!(
                            "non-administrator operator '{}' attempted desktop exit authorization",
                            user.username
                        ),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "computer_name": computer_name,
                            "target_username": user.username,
                            "windows_user": windows_user,
                        }),
                    })
                    .map_err(storage_err)?;
                Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    "administrator role required for this operation",
                ))
            }
            AuthAttemptOutcome::InvalidCredentials { username: target, .. } => {
                g.auth.record_exit_failure(now_ms);
                g.store
                    .append_event(&NewEvent {
                        severity: Severity::Warning,
                        kind: "auth_exit_denied".into(),
                        device_key: None,
                        message: format!("failed desktop exit authorization for '{target}'"),
                        simulated: false,
                        enforcement_state: self.enforcement_state_code().into(),
                        policy_version: None,
                        details: serde_json::json!({
                            "computer_name": computer_name,
                            "target_username": target,
                            "windows_user": windows_user,
                        }),
                    })
                    .map_err(storage_err)?;
                Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    "invalid username or password",
                ))
            }
            AuthAttemptOutcome::Locked {
                locked_until_ms, ..
            } => {
                let secs = remaining_lock_seconds(Some(locked_until_ms), now_ms).unwrap_or(60);
                Err(IpcError::new(
                    ErrorCode::Unauthorized,
                    format!("account temporarily locked; try again in {secs} seconds"),
                ))
            }
        }
    }

    pub(crate) fn preview_bulk_manufacturers(
        &self,
        action: BulkManufacturerAction,
    ) -> Result<BulkManufacturerPreviewView, IpcError> {
        let g = self.lock()?;
        let v = Self::validated(&g.store)?;
        let snap = g.last.clone().unwrap_or_else(empty_snapshot);
        let brands = &v.catalog.catalog().brands;
        let p = v.policy.policy();

        let total_manufacturers = u32::try_from(brands.len()).unwrap_or(u32::MAX);
        let mut currently_allowed = 0u32;
        let mut currently_denied = 0u32;
        let mut currently_unconfigured = 0u32;
        let mut manufacturers_changing = 0u32;
        let mut preserved_custom_identifiers_count = 0u32;

        for b in brands {
            if brand_has_custom_identifier(b) {
                preserved_custom_identifiers_count = preserved_custom_identifiers_count.saturating_add(1);
            }
            let is_allowed = p.allowed_brands.iter().any(|r| r.brand_id == b.id && r.enabled);
            let is_denied = p.denied_brands.iter().any(|r| r.brand_id == b.id && r.enabled);
            if is_denied {
                currently_denied = currently_denied.saturating_add(1);
                if action != BulkManufacturerAction::ExplicitDenyAll {
                    manufacturers_changing = manufacturers_changing.saturating_add(1);
                }
            } else if is_allowed {
                currently_allowed = currently_allowed.saturating_add(1);
                if action != BulkManufacturerAction::AllowAll {
                    manufacturers_changing = manufacturers_changing.saturating_add(1);
                }
            } else {
                currently_unconfigured = currently_unconfigured.saturating_add(1);
                if action != BulkManufacturerAction::UnconfiguredAll {
                    manufacturers_changing = manufacturers_changing.saturating_add(1);
                }
            }
        }

        let next_state = match apply_edit(&v.state, &PolicyEdit::BulkManufacturers { action }) {
            Ok(out) => out.state,
            Err(rustward_core::policy_edit::EditError::NoChange) => v.state.clone(),
            Err(e) => return Err(edit_err(e)),
        };
        let next_validated = next_state.validate().map_err(edit_err)?;
        let next_plan = compile_compound_policy(
            &next_validated.policy,
            &next_validated.catalog,
            &snap.devices,
            None,
            true,
        );
        let decisions = evaluate_snapshot(&snap, &next_validated.policy, &next_validated.catalog);
        let mut connected_storage_devices = 0u32;
        let mut connected_likely_blocked = 0u32;
        let mut connected_likely_allowed = 0u32;
        for (rec, dec) in snap.devices.iter().zip(decisions.iter()) {
            if rec.present == Some(false) {
                continue;
            }
            if matches!(dec.classification.category, DeviceCategory::UsbStorageDisk { .. }) {
                connected_storage_devices = connected_storage_devices.saturating_add(1);
                match dec.verdict {
                    Verdict::Allow => {
                        connected_likely_allowed = connected_likely_allowed.saturating_add(1);
                    }
                    Verdict::Deny => {
                        connected_likely_blocked = connected_likely_blocked.saturating_add(1);
                    }
                    Verdict::NotApplicable => {}
                }
            }
        }

        let overrides = p.denied_devices.len().saturating_add(p.allowed_devices.len());
        Ok(BulkManufacturerPreviewView {
            action,
            current_policy_version: v.version,
            total_manufacturers,
            currently_allowed,
            currently_denied,
            currently_unconfigured,
            manufacturers_changing,
            connected_storage_devices,
            connected_likely_blocked,
            connected_likely_allowed,
            compiled_deny_ids_count: u32::try_from(next_plan.compiled.deny_hardware_ids.len())
                .unwrap_or(u32::MAX),
            compiled_allow_ids_count: u32::try_from(next_plan.compiled.allow_hardware_ids.len())
                .unwrap_or(u32::MAX),
            preserved_custom_identifiers_count,
            preserved_device_overrides_count: u32::try_from(overrides).unwrap_or(u32::MAX),
        })
    }

    pub(crate) fn apply_bulk_manufacturers(
        &self,
        action: BulkManufacturerAction,
        apply_to_windows: bool,
        retroactive: bool,
        expected_policy_version: u64,
        identity: &ClientIdentity,
        actor_override: Option<&str>,
    ) -> Result<BulkManufacturerApplyResultView, IpcError> {
        if !identity.is_administrator {
            return Err(IpcError::new(
                ErrorCode::Unauthorized,
                "administrator rights (elevated) are required for this operation",
            ));
        }
        let preview = self.preview_bulk_manufacturers(action)?;
        let actor_name = actor_override
            .map(str::to_owned)
            .unwrap_or_else(|| identity.actor());
        let mut warnings_tr = Vec::new();
        let mut warnings_en = Vec::new();
        let mut new_version = preview.current_policy_version;
        let mut changed = false;

        match self.apply_edit_with_actor(
            &PolicyEdit::BulkManufacturers { action },
            expected_policy_version,
            identity,
            Some(&actor_name),
        ) {
            Ok(ResponseBody::Mutation(m)) => {
                new_version = m.policy_version;
                changed = true;
            }
            Ok(_) => {}
            Err(e) if e.message == "the edit does not change anything" => {
                // Idempotent when already in target bulk configuration.
            }
            Err(e) => return Err(e),
        }

        let (windows_plan, windows_apply_result) = if apply_to_windows {
            let plan =
                self.apply_compound_policy_direct(retroactive, new_version, identity, Some(&actor_name))?;
            let catalog_version = {
                let g = self.lock()?;
                Self::validated(&g.store)
                    .map(|v| v.catalog.catalog().catalog_version.clone())
                    .unwrap_or_default()
            };
            let summary = "Compound Windows Group Policy applied and verified.".to_owned();
            let mutation = MutationView {
                policy_version: new_version,
                catalog_version,
                summary: summary.clone(),
                summary_tr: l10n::text(&summary),
                warnings: Vec::new(),
                warnings_tr: Vec::new(),
            };
            (Some(plan), Some(mutation))
        } else {
            let plan = self.get_compound_policy_plan().ok();
            warnings_tr.push(
                "Üretici kuralları taslak olarak güncellendi; Windows Grup İlkesi henüz güncellenmedi ('Windows'a Uygula' gerekir).".into(),
            );
            warnings_en.push(
                "Manufacturer rules saved to local policy; Windows Group Policy is not updated until 'Apply to Windows'.".into(),
            );
            (plan, None)
        };

        Ok(BulkManufacturerApplyResultView {
            action,
            policy_version: new_version,
            total_manufacturers: preview.total_manufacturers,
            manufacturers_updated: if changed {
                preview.manufacturers_changing
            } else {
                0
            },
            applied_to_windows: apply_to_windows,
            windows_plan,
            windows_apply_result,
            warnings_tr,
            warnings_en,
        })
    }

    pub(crate) fn get_notification_feed(
        &self,
        after_event_id: Option<i64>,
    ) -> Result<NotificationFeedView, IpcError> {
        let g = self.lock()?;
        let settings = g.store.settings().map_err(storage_err)?;
        let names = Self::brand_names(&g.store);
        let events = g
            .store
            .list_events(&EventFilter {
                simulated: Some(false),
                limit: Some(100),
                ..EventFilter::default()
            })
            .map_err(storage_err)?;

        let latest_event_id = g
            .store
            .list_events(&EventFilter {
                limit: Some(1),
                ..EventFilter::default()
            })
            .map_err(storage_err)?
            .first()
            .map_or(0, |e| e.id);

        let lang_str = match settings.language {
            rustward_storage::Language::Tr => "tr".to_owned(),
            rustward_storage::Language::En => "en".to_owned(),
        };
        if !settings.notifications_enabled {
            return Ok(NotificationFeedView {
                latest_event_id,
                notifications_enabled: settings.notifications_enabled,
                notify_on_blocked: settings.notify_on_blocked,
                notify_on_unblocked_warning: settings.notify_on_unblocked_warning,
                language: lang_str,
                items: Vec::new(),
            });
        }

        let after_id = after_event_id.unwrap_or(0);
        let mut items = Vec::new();
        let mut seen_dedup = BTreeSet::new();

        // Process chronologically oldest->newest among eligible events newer than cursor.
        for e in events.into_iter().rev() {
            if e.id <= after_id || e.simulated {
                continue;
            }
            let meta = rustward_storage::EventMetadata::from_details(&e.details);
            let manufacturer_name = meta.manufacturer_id.as_deref().map(&names);
            let device_name = meta.device_name.clone();
            let vid_pid = meta.vid_pid.clone();
            let dev_label = device_name
                .as_deref()
                .or(manufacturer_name.as_deref())
                .unwrap_or("USB depolama aygıtı");
            let dev_key = e.device_key.as_deref().unwrap_or("unknown");

            if e.kind == crate::observation::KIND_DENIAL_OBSERVED && settings.notify_on_blocked {
                let dedup_key = format!("blocked_verified:{dev_key}:{}", meta.policy_revision.as_deref().unwrap_or("gpo"));
                if !seen_dedup.insert(dedup_key.clone()) {
                    continue;
                }
                let vid_suffix = vid_pid
                    .as_deref()
                    .map(|vp| format!(" ({vp})"))
                    .unwrap_or_default();
                items.push(NotificationItemView {
                    event_id: e.id,
                    utc_ms: e.utc_ms,
                    category: "blocked_verified".into(),
                    dedup_key,
                    title_tr: "RustWard — USB Engellendi".into(),
                    title_en: "RustWard — USB Blocked".into(),
                    body_tr: format!(
                        "{dev_label}{vid_suffix} aygıtının kurulumu Windows Grup İlkesi ile engellendi (PnP Kod 28 doğrulandı)."
                    ),
                    body_en: format!(
                        "Installation of {dev_label}{vid_suffix} was blocked by Windows Group Policy (PnP Code 28 verified)."
                    ),
                    manufacturer_name,
                    device_name,
                    vid_pid,
                    enforced_verified: true,
                });
            } else if e.kind == "usb_deny_not_enforced" && settings.notify_on_unblocked_warning {
                let dedup_key = format!("deny_not_enforced_warning:{dev_key}:{}", e.policy_version.unwrap_or(0));
                if !seen_dedup.insert(dedup_key.clone()) {
                    continue;
                }
                let vid_suffix = vid_pid
                    .as_deref()
                    .map(|vp| format!(" ({vp})"))
                    .unwrap_or_default();
                items.push(NotificationItemView {
                    event_id: e.id,
                    utc_ms: e.utc_ms,
                    category: "deny_not_enforced_warning".into(),
                    dedup_key,
                    title_tr: "RustWard — USB Uyarısı (Engellenmedi)".into(),
                    title_en: "RustWard — USB Warning (Not Enforced)".into(),
                    body_tr: format!(
                        "{dev_label}{vid_suffix} politika tarafından reddedildi ancak Windows henüz engellemedi; Windows'a Uygulayın."
                    ),
                    body_en: format!(
                        "{dev_label}{vid_suffix} is denied in policy, but Windows did not enforce blocking; apply Windows policy."
                    ),
                    manufacturer_name,
                    device_name,
                    vid_pid,
                    enforced_verified: false,
                });
            }
        }

        Ok(NotificationFeedView {
            latest_event_id,
            notifications_enabled: settings.notifications_enabled,
            notify_on_blocked: settings.notify_on_blocked,
            notify_on_unblocked_warning: settings.notify_on_unblocked_warning,
            language: lang_str,
            items,
        })
    }

    pub(crate) fn query_audit_events(
        &self,
        query: &rustward_ipc::messages::EventQuery,
    ) -> Result<AuditPageView, IpcError> {
        let g = self.lock()?;
        let names = Self::brand_names(&g.store);
        let filter = Self::event_filter(query)?;
        let limit = filter.limit.unwrap_or(50);
        let offset = filter.offset.unwrap_or(0);
        let total_count = g.store.count_events(&filter).map_err(storage_err)?;
        let rows = g.store.list_events(&filter).map_err(storage_err)?;
        let events = rows.into_iter().map(|e| Self::event_view(e, &names)).collect();
        let chain = g.store.verify_chain().map_err(storage_err)?;
        let (chain_ok, chain_status) = match chain {
            ChainStatus::Intact { .. } => (true, "intact".to_owned()),
            ChainStatus::Broken { .. } => (false, "broken".to_owned()),
            ChainStatus::Missing { .. } => (false, "missing".to_owned()),
            ChainStatus::Truncated { .. } => (false, "truncated".to_owned()),
        };
        Ok(AuditPageView {
            events,
            total_count,
            limit,
            offset,
            chain_ok,
            chain_status,
        })
    }

    pub(crate) fn verify_audit_chain_view(&self) -> Result<AuditChainVerificationView, IpcError> {
        let g = self.lock()?;
        let chain = g.store.verify_chain().map_err(storage_err)?;
        let view = match chain {
            ChainStatus::Intact { entries } => AuditChainVerificationView {
                intact: true,
                status_code: "intact".into(),
                entries,
                summary_tr: format!(
                    "Denetim günlüğü bütünlüğü doğrulandı: {entries} kaydın SHA-256 karma zinciri sağlam."
                ),
                summary_en: format!(
                    "Audit log integrity verified: SHA-256 hash chain is intact across {entries} entries."
                ),
                first_bad_id: None,
            },
            ChainStatus::Broken { first_bad_id } => AuditChainVerificationView {
                intact: false,
                status_code: "broken".into(),
                entries: 0,
                summary_tr: format!(
                    "UYARI: Denetim zinciri bozuk! İlk geçersiz kayıt kimliği: #{first_bad_id}."
                ),
                summary_en: format!(
                    "WARNING: Audit hash chain is broken! First invalid event ID: #{first_bad_id}."
                ),
                first_bad_id: Some(first_bad_id),
            },
            ChainStatus::Missing {
                entries,
                after_id,
                next_id,
            } => AuditChainVerificationView {
                intact: false,
                status_code: "missing".into(),
                entries,
                summary_tr: format!(
                    "UYARI: Denetim kayıtlarında #{after_id} ile #{next_id} arasında eksik kimlik boşluğu tespit edildi."
                ),
                summary_en: format!(
                    "WARNING: Missing audit sequence gap detected between #{after_id} and #{next_id}."
                ),
                first_bad_id: Some(after_id + 1),
            },
            ChainStatus::Truncated {
                entries,
                last_id,
                highest_issued,
            } => AuditChainVerificationView {
                intact: false,
                status_code: "truncated".into(),
                entries,
                summary_tr: format!(
                    "UYARI: Son denetim kayıtları kesilmiş görünüyor (son kalan #{last_id}, verilen en yüksek #{highest_issued})."
                ),
                summary_en: format!(
                    "WARNING: Recent audit entries appear truncated (last remaining #{last_id}, highest issued #{highest_issued})."
                ),
                first_bad_id: Some(last_id + 1),
            },
        };
        Ok(view)
    }

    #[must_use]
    pub(crate) fn about_info(&self) -> AboutInfoView {
        let sha = option_env!("RUSTWARD_GIT_SHA").unwrap_or("unknown");
        let build_ts = option_env!("RUSTWARD_BUILD_TIMESTAMP").unwrap_or("unknown");
        AboutInfoView {
            app_name: "RustWard".into(),
            tagline_tr: "Çevrimdışı USB Depolama Erişim Kontrolü ve Güvenlik Yönetimi".into(),
            tagline_en: "Offline USB Storage Access Control and Security Management".into(),
            version: self.config.app_version.clone(),
            commit_sha: sha.to_owned(),
            build_timestamp: build_ts.to_owned(),
            author: "Yunus İNAN".into(),
            repository_url: "https://github.com/Terabithia1572/RustWard".into(),
            license: "MIT / Apache-2.0 Açık Kaynak Bileşenler · Yerel Kurumsal Güvenlik Aracı"
                .into(),
            copyright_tr: "Telif Hakkı © 2026 Yunus İNAN. Tüm hakları saklıdır.".into(),
            copyright_en: "Copyright © 2026 Yunus İNAN. All rights reserved.".into(),
            architecture_summary_tr: "RustWard, SYSTEM yetkisiyle çalışan arka plan Windows hizmeti (RustWardService), Argon2id + DPAPI ile korunan yönetici oturumu, adlandırılmış kanal (Named Pipe DACL) tabanlı IPC sınırı, SHA-256 karma zincirli SQLite denetim günlüğü, Session-0 dışı masaüstü uyarı ajanı (rustward-notifier) ve Yerel Grup İlkesi (IGroupPolicyObject COM + HKLM) USB aygıt kurulum kısıtlama derleyicisinden oluşur.".into(),
            architecture_summary_en: "RustWard consists of a LocalSystem background Windows service (RustWardService), Argon2id + DPAPI protected operator sessions, DACL-hardened named pipe IPC, a SHA-256 hash-chained SQLite audit log, an out-of-Session-0 desktop notifier (rustward-notifier), and a Local Group Policy (IGroupPolicyObject COM + HKLM) USB device installation policy compiler.".into(),
            tech_stack: vec![
                "Rust (rustward-core, rustward-enforcement, rustward-storage, rustward-ipc, rustward-windows, rustward-service, rustward-notifier)".into(),
                "Tauri v2 + WebView2 + React + TypeScript + Vite".into(),
                "SQLite (WAL + SHA-256 Hash Chain + Schema Migrations)".into(),
                "Argon2id (16-byte CSPRNG Salt) + Windows DPAPI (CRYPTPROTECT_LOCAL_MACHINE)".into(),
                "Windows Local Group Policy (IGroupPolicyObject COM) & SetupAPI / PnP Code 28 Evidence".into(),
                "WiX Toolset v4 Makine Genelinde MSI Kurulum Paketi".into(),
            ],
            verified_environments: vec![
                "Windows 10 x64 (VMware lab: Kingston USBSTOR 0951:1666 & SanDisk UASP/SCSI 0781:55A3 PnP Kod 28 ve SetupAPI kanıtı ile doğrulandı)".into(),
                "Windows 11 x64 (Makine genelinde MSI, hizmet & UAC sınır test adayı)".into(),
            ],
            security_limits_tr: vec![
                "Yerel yönetici (Administrator) yetkisine sahip kullanıcılar Windows Grup İlkesini elle değiştirebilir veya hizmeti durdurabilir; operatörler standart Windows kullanıcısı olmalıdır.".into(),
                "Üretici kuralları aygıtın bildirdiği USB/SCSI kimlik dizelerine dayanır; donanım düzeyinde kriptografik kimlik doğrulaması sağlamaz.".into(),
                "MTP/PTP (WPD) telefon medyası ve optik (CD/DVD) aygıtlar bu sürümün USB depolama kapsamı dışındadır.".into(),
                "Uygulamadan çıkış kilidi normal kullanıcı penceresi kapatmasını korur; Task Manager sonlandırması veya Windows oturum kapatma akışını engellemez.".into(),
            ],
            security_limits_en: vec![
                "Local Windows administrators can modify Group Policy directly or stop services; non-admin operators should run as standard Windows users.".into(),
                "Manufacturer rules rely on self-reported USB/SCSI hardware strings rather than hardware cryptographic attestation.".into(),
                "MTP/PTP (WPD) portable media and optical drives remain out of scope for this release.".into(),
                "Protected exit governs normal GUI closing only and never blocks OS shutdown, sign-out, or Task Manager.".into(),
            ],
            acknowledgments_tr: vec![
                "Geliştirici: Yunus İNAN".into(),
                "Tamamen çevrimdışı, telemetrisiz ve şeffaf Windows güvenlik mühendisliği ilkeleriyle geliştirilmiştir.".into(),
            ],
            third_party_notices: vec![
                "argon2, getrandom, zeroize, subtle, sha2 (RustCrypto)".into(),
                "rusqlite / SQLite (Public Domain)".into(),
                "Tauri (MIT / Apache-2.0) & React (MIT)".into(),
                "windows-sys (MIT / Apache-2.0) & serde (MIT / Apache-2.0)".into(),
            ],
        }
    }

    pub(crate) fn requires_authenticated_session(request: &Request) -> bool {
        !crate::auth::AuthManager::is_public_or_boot_request(request)
    }

    pub(crate) fn requires_admin_role(request: &Request) -> bool {
        request.access_level() == AccessLevel::Administrator
    }
}
