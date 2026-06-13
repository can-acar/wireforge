use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use qrcode::render::svg;
use qrcode::QrCode;
use serde::Deserialize;
use tower_sessions::Session;
use wireforge_core::application::ports::UserRepository;
use wireforge_core::crypto::{generate_totp_secret, seal, unseal, verify_totp};
use wireforge_core::domain::audit::AuditAction;

use crate::audit::record as audit_record;
use crate::extractors::AuthUser;
use crate::flash::{set_flash, take_flash, Flash};
use crate::templates::{ProfilePage, TotpSetupPage};
use crate::{AppState, WebError};

const TOTP_PENDING_KEY: &str = "_totp_setup_secret";

pub async fn index(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let db_user = state
        .users
        .find_by_id(user.id)
        .await?
        .ok_or(WebError::NotFound)?;
    let flash = take_flash(&session).await;
    let page = ProfilePage {
        user: &user,
        flash: flash.as_ref(),
        totp_enabled: db_user.totp_enabled,
    };
    Ok(render(&page))
}

pub async fn totp_setup_page(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    // Generate a fresh TOTP secret for the user. We keep it in the session
    // until the user confirms via a valid OTP — only then it is persisted.
    let issuer = state.settings_snapshot().totp_issuer;
    let totp = generate_totp_secret(&issuer, &user.username)?;
    let _ = session
        .insert(TOTP_PENDING_KEY, totp.base32.clone())
        .await;

    // Render QR ourselves (the totp-rs QR is PNG; we prefer inline SVG for
    // crisp scaling). The provisioning URI is what we encode.
    let code = QrCode::new(totp.uri.as_bytes())
        .map_err(|e| WebError::Internal(format!("qr: {e}")))?;
    let qr_svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .build();

    // Suppress unused warning: keep the PNG bytes accessible if a caller
    // wants them via a future API endpoint.
    let _ = totp.qr_png;

    let flash = take_flash(&session).await;
    let page = TotpSetupPage {
        user: &user,
        flash: flash.as_ref(),
        error: None,
        secret_base32: totp.base32,
        qr_svg,
    };
    Ok(render(&page))
}

#[derive(Debug, Deserialize)]
pub struct TotpConfirmForm {
    pub code: String,
}

pub async fn totp_confirm(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Form(form): Form<TotpConfirmForm>,
) -> Result<Response, WebError> {
    let secret_b32: String = match session.get::<String>(TOTP_PENDING_KEY).await {
        Ok(Some(s)) => s,
        _ => return Ok(Redirect::to("/profile/2fa").into_response()),
    };

    let issuer = state.settings_snapshot().totp_issuer;
    if !verify_totp(&secret_b32, form.code.trim(), &issuer, &user.username) {
        // Re-render the same setup page with an error.
        let code = QrCode::new(totp_uri(&issuer, &user.username, &secret_b32).as_bytes())
            .map_err(|e| WebError::Internal(format!("qr: {e}")))?;
        let qr_svg = code
            .render::<svg::Color<'_>>()
            .min_dimensions(220, 220)
            .build();
        let page = TotpSetupPage {
            user: &user,
            flash: None,
            error: Some("Invalid code; check the time on your device and retry."),
            secret_base32: secret_b32,
            qr_svg,
        };
        return Ok(render(&page).into_response());
    }

    let sealed = seal(secret_b32.as_bytes(), &state.seal_key)?;
    state.users.update_totp(user.id, true, Some(&sealed)).await?;
    let _ = session.remove::<String>(TOTP_PENDING_KEY).await;
    set_flash(&session, Flash::success("Two-factor authentication enabled")).await;
    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::TotpEnabled,
        Some("user"),
        Some(&user.id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/profile").into_response())
}

pub async fn totp_disable(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    state.users.update_totp(user.id, false, None).await?;
    set_flash(&session, Flash::success("Two-factor authentication disabled")).await;
    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::TotpDisabled,
        Some("user"),
        Some(&user.id.to_string()),
        None,
    )
    .await;
    Ok(Redirect::to("/profile"))
}

fn totp_uri(issuer: &str, account: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30"
    )
}

fn render<T: Template>(t: &T) -> Html<String> {
    Html(t.render().unwrap_or_else(|e| format!("render error: {e}")))
}

// Suppress the unused warning for `unseal` — exposed so callers can decrypt
// stored TOTP secrets in upcoming recovery-code work.
#[allow(dead_code)]
fn _unseal_passthrough(b: &[u8], k: &wireforge_core::crypto::SealKey) -> Result<Vec<u8>, WebError> {
    unseal(b, k).map_err(Into::into)
}
