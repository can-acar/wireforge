use std::net::SocketAddr;

use askama::Template;
use axum::extract::{ConnectInfo, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use wireforge_core::application::ports::{BanRepository, UserRepository};
use wireforge_core::crypto::verify_totp;
use wireforge_core::crypto::{seal, unseal};
use wireforge_core::domain::audit::AuditAction;
use wireforge_core::domain::Role;
use wireforge_core::CoreError;

use crate::audit::record as audit_record;
use crate::extractors::AuthUser;
use crate::templates::{LoginPage, SetupPage, TotpChallengePage};
use crate::{AppState, WebError};

const PENDING_USER_KEY: &str = "auth_pending_user_id";

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupForm {
    pub username: String,
    pub password: String,
    pub password_confirm: String,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TotpForm {
    pub code: String,
}

#[derive(Serialize, Deserialize)]
struct PendingUser {
    user_id: String,
    username: String,
}

pub async fn login_page(State(state): State<AppState>) -> Result<impl IntoResponse, WebError> {
    if state.users.count().await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    Ok(render_login(None, "").into_response())
}

pub async fn login_submit(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Result<Response, WebError> {
    let client_ip = addr.ip().to_string();

    // Brute-force lockout check.
    if let Some(ban) = state.bans.find(&client_ip).await? {
        if ban.is_active(Utc::now()) {
            audit_record(
                &state,
                None,
                Some(&client_ip),
                AuditAction::UserLoginFailed,
                None,
                None,
                Some(serde_json::json!({ "reason": "ip_locked" })),
            )
            .await;
            return Ok(render_login(
                Some("Too many failed attempts. Try again later."),
                &form.username,
            )
            .into_response());
        }
    }

    let svc = state.auth_service();
    match svc
        .authenticate_password(&form.username, &form.password)
        .await
    {
        Ok(user) => {
            let _ = state.bans.clear(&client_ip).await;
            // 2FA gating: if TOTP is enabled, stash a pending session and
            // require the verification code.
            if user.totp_enabled {
                let pending = PendingUser {
                    user_id: user.id.to_string(),
                    username: user.username.clone(),
                };
                let _ = session.insert(PENDING_USER_KEY, pending).await;
                return Ok(render_totp(None).into_response());
            }
            state.users.touch_last_login(user.id).await?;
            AuthUser {
                id: user.id,
                username: user.username.clone(),
                role: user.role,
            }
            .store(&session)
            .await?;
            audit_record(
                &state,
                Some(user.id),
                Some(&client_ip),
                AuditAction::UserLogin,
                Some("user"),
                Some(&user.id.to_string()),
                None,
            )
            .await;
            Ok(Redirect::to("/").into_response())
        }
        Err(CoreError::InvalidCredentials) => {
            let s = state.settings_snapshot();
            let _ = state
                .bans
                .record_failure(
                    &client_ip,
                    s.login_max_attempts,
                    std::time::Duration::from_secs(s.login_lockout_secs),
                )
                .await;
            audit_record(
                &state,
                None,
                Some(&client_ip),
                AuditAction::UserLoginFailed,
                None,
                None,
                Some(serde_json::json!({ "username": form.username })),
            )
            .await;
            Ok(render_login(Some("Invalid username or password"), &form.username).into_response())
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn totp_submit(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<TotpForm>,
) -> Result<Response, WebError> {
    let pending: PendingUser = match session.get::<PendingUser>(PENDING_USER_KEY).await {
        Ok(Some(p)) => p,
        _ => return Ok(Redirect::to("/login").into_response()),
    };
    let user_id = uuid::Uuid::parse_str(&pending.user_id)
        .map(wireforge_core::domain::Id::from_uuid)
        .map_err(|_| WebError::Unauthorized)?;

    let user = state
        .users
        .find_by_id(user_id)
        .await?
        .ok_or(WebError::Unauthorized)?;
    let secret_blob = user
        .totp_secret_encrypted
        .as_ref()
        .ok_or(WebError::Unauthorized)?;
    let secret_bytes = unseal(secret_blob, &state.seal_key)?;
    let secret_b32 = String::from_utf8(secret_bytes)
        .map_err(|e| WebError::Internal(format!("totp utf8: {e}")))?;

    if !verify_totp(
        &secret_b32,
        form.code.trim(),
        &state.settings_snapshot().totp_issuer,
        &user.username,
    ) {
        audit_record(
            &state,
            Some(user.id),
            Some(&addr.ip().to_string()),
            AuditAction::UserLoginFailed,
            Some("user"),
            Some(&user.id.to_string()),
            Some(serde_json::json!({ "reason": "totp_invalid" })),
        )
        .await;
        return Ok(render_totp(Some("Invalid code")).into_response());
    }

    let _ = session.remove::<PendingUser>(PENDING_USER_KEY).await;
    state.users.touch_last_login(user.id).await?;
    AuthUser {
        id: user.id,
        username: user.username.clone(),
        role: user.role,
    }
    .store(&session)
    .await?;
    audit_record(
        &state,
        Some(user.id),
        Some(&addr.ip().to_string()),
        AuditAction::UserLogin,
        Some("user"),
        Some(&user.id.to_string()),
        Some(serde_json::json!({ "totp": true })),
    )
    .await;
    Ok(Redirect::to("/").into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    if let Some(user) = crate::extractors::auth_user::read_session_user(&session).await {
        audit_record(
            &state,
            Some(user.id),
            None,
            AuditAction::UserLogout,
            Some("user"),
            Some(&user.id.to_string()),
            None,
        )
        .await;
    }
    AuthUser::clear(&session).await?;
    let _ = session.remove::<PendingUser>(PENDING_USER_KEY).await;
    Ok(Redirect::to("/login"))
}

pub async fn setup_page(State(state): State<AppState>) -> Result<impl IntoResponse, WebError> {
    if state.users.count().await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }
    let page = SetupPage { error: None };
    Ok(Html(render_str(&page)).into_response())
}

pub async fn setup_submit(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<SetupForm>,
) -> Result<Response, WebError> {
    if state.users.count().await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }
    if form.password != form.password_confirm {
        return Ok(setup_err("Passwords do not match").into_response());
    }
    if form.password.len() < 12 {
        return Ok(setup_err("Password must be at least 12 characters").into_response());
    }

    let user = state
        .auth_service()
        .register_initial_admin(&form.username, &form.password, form.email.as_deref())
        .await?;

    AuthUser {
        id: user.id,
        username: user.username.clone(),
        role: Role::Admin,
    }
    .store(&session)
    .await?;
    audit_record(
        &state,
        Some(user.id),
        Some(&addr.ip().to_string()),
        AuditAction::UserCreated,
        Some("user"),
        Some(&user.id.to_string()),
        Some(serde_json::json!({ "bootstrap": true })),
    )
    .await;
    // Silence unused: keep `seal` exported so `crypto` users can re-seal.
    let _ = seal;
    Ok(Redirect::to("/").into_response())
}

fn render_login(err: Option<&str>, username: &str) -> Html<String> {
    let page = LoginPage {
        error: err,
        username,
    };
    Html(render_str(&page))
}

fn render_totp(err: Option<&str>) -> Html<String> {
    let page = TotpChallengePage { error: err };
    Html(render_str(&page))
}

fn setup_err(msg: &str) -> Html<String> {
    let page = SetupPage { error: Some(msg) };
    Html(render_str(&page))
}

fn render_str<T: Template>(t: &T) -> String {
    t.render().unwrap_or_else(|e| format!("render error: {e}"))
}
