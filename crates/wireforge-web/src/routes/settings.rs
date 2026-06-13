//! System settings page (admin-only). Reads/writes the runtime-mutable
//! `RuntimeSettings`, persists overrides to the `settings` table, and applies
//! changes immediately (no restart).

use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use wireforge_core::domain::audit::AuditAction;
use wireforge_core::domain::RuntimeSettings;

use crate::audit::record as audit_record;
use crate::extractors::AuthUser;
use crate::flash::{set_flash, take_flash, Flash};
use crate::templates::{SettingsFormState, SettingsPage, SettingsReadonly};
use crate::{AppState, WebError};

const MASTER_KEY_MASK: &str = "••••••••••••••••";
const LOCALES: &[&str] = &["en", "tr", "es", "de", "fr"];
const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

fn form_from_settings(s: &RuntimeSettings) -> SettingsFormState {
    SettingsFormState {
        locale_default: s.locale_default.clone(),
        totp_issuer: s.totp_issuer.clone(),
        login_max_attempts: s.login_max_attempts.to_string(),
        login_lockout_secs: s.login_lockout_secs.to_string(),
        session_timeout_hours: s.session_timeout_hours.to_string(),
        endpoint: s.endpoint.clone().unwrap_or_default(),
        traffic_poller_interval_secs: s.traffic_poller_interval_secs.to_string(),
        traffic_enabled: s.traffic_enabled,
        backup_retention_days: s.backup_retention_days.to_string(),
        log_level: s.log_level.clone(),
    }
}

fn readonly_from_state(state: &AppState) -> SettingsReadonly {
    SettingsReadonly {
        database_path: state.config.database_path.clone(),
        server_bind: state.config.server_bind.clone(),
        session_secure: state.config.session_secure,
        master_key_masked: MASTER_KEY_MASK.to_string(),
    }
}

fn render(page: &SettingsPage) -> Result<Html<String>, WebError> {
    page.render()
        .map(Html)
        .map_err(|e| WebError::Internal(format!("render: {e}")))
}

pub async fn index(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    if !user.role.can_manage_settings() {
        return Err(WebError::Forbidden);
    }
    let snapshot = state.settings_snapshot();
    let flash = take_flash(&session).await;
    let page = SettingsPage {
        user: &user,
        flash: flash.as_ref(),
        error: None,
        form: form_from_settings(&snapshot),
        readonly: readonly_from_state(&state),
    };
    render(&page)
}

#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    pub locale_default: String,
    pub totp_issuer: String,
    pub login_max_attempts: u32,
    pub login_lockout_secs: u64,
    pub session_timeout_hours: u32,
    pub endpoint: String,
    pub traffic_poller_interval_secs: u64,
    // Unchecked checkbox sends nothing; serde default = false.
    #[serde(default)]
    pub traffic_enabled: bool,
    pub backup_retention_days: u32,
    pub log_level: String,
}

/// Validate, returning a human-readable error on the first failure.
fn validate(f: &SettingsForm) -> Result<(), String> {
    if !LOCALES.contains(&f.locale_default.as_str()) {
        return Err(format!("Unsupported locale: {}", f.locale_default));
    }
    if !LOG_LEVELS.contains(&f.log_level.as_str()) {
        return Err(format!("Unsupported log level: {}", f.log_level));
    }
    if f.totp_issuer.trim().is_empty() {
        return Err("TOTP issuer cannot be empty".into());
    }
    if !(1..=50).contains(&f.login_max_attempts) {
        return Err("Login max attempts must be 1–50".into());
    }
    if !(60..=86_400).contains(&f.login_lockout_secs) {
        return Err("Lockout must be 60–86400 seconds".into());
    }
    if !(1..=168).contains(&f.session_timeout_hours) {
        return Err("Session timeout must be 1–168 hours".into());
    }
    if !(10..=3_600).contains(&f.traffic_poller_interval_secs) {
        return Err("Poller interval must be 10–3600 seconds".into());
    }
    if !(1..=365).contains(&f.backup_retention_days) {
        return Err("Backup retention must be 1–365 days".into());
    }
    Ok(())
}

pub async fn save(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Form(form): Form<SettingsForm>,
) -> Result<Response, WebError> {
    if !user.role.can_manage_settings() {
        return Err(WebError::Forbidden);
    }

    if let Err(msg) = validate(&form) {
        // Re-render with the submitted values and the error.
        let page = SettingsPage {
            user: &user,
            flash: None,
            error: Some(&msg),
            form: SettingsFormState {
                locale_default: form.locale_default,
                totp_issuer: form.totp_issuer,
                login_max_attempts: form.login_max_attempts.to_string(),
                login_lockout_secs: form.login_lockout_secs.to_string(),
                session_timeout_hours: form.session_timeout_hours.to_string(),
                endpoint: form.endpoint,
                traffic_poller_interval_secs: form.traffic_poller_interval_secs.to_string(),
                traffic_enabled: form.traffic_enabled,
                backup_retention_days: form.backup_retention_days.to_string(),
                log_level: form.log_level,
            },
            readonly: readonly_from_state(&state),
        };
        return Ok(render(&page)?.into_response());
    }

    let endpoint_json = if form.endpoint.trim().is_empty() {
        json!("")
    } else {
        json!(form.endpoint.trim())
    };

    let svc = state.settings_service();
    svc.set_many(
        vec![
            ("locale_default", json!(form.locale_default)),
            ("totp_issuer", json!(form.totp_issuer.trim())),
            ("login_max_attempts", json!(form.login_max_attempts)),
            ("login_lockout_secs", json!(form.login_lockout_secs)),
            ("session_timeout_hours", json!(form.session_timeout_hours)),
            ("endpoint", endpoint_json),
            (
                "traffic_poller_interval_secs",
                json!(form.traffic_poller_interval_secs),
            ),
            ("traffic_enabled", json!(form.traffic_enabled)),
            ("backup_retention_days", json!(form.backup_retention_days)),
            ("log_level", json!(form.log_level)),
        ],
        Some(user.id),
    )
    .await?;

    // Apply log level immediately.
    if let Err(e) = (state.log_reload)(&form.log_level) {
        tracing::warn!(error = %e, "log level reload failed");
    }

    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::SettingsUpdated,
        Some("settings"),
        None,
        Some(json!({
            "login_max_attempts": form.login_max_attempts,
            "traffic_enabled": form.traffic_enabled,
            "log_level": form.log_level,
            "locale_default": form.locale_default,
        })),
    )
    .await;

    set_flash(
        &session,
        Flash::success("Settings saved — changes apply immediately."),
    )
    .await;
    Ok(Redirect::to("/settings").into_response())
}
