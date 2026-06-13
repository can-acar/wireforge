use std::collections::HashMap;
use std::str::FromStr;

use askama::Template;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use ipnet::IpNet;
use qrcode::render::svg;
use qrcode::QrCode;
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;
use wireforge_core::application::ports::{InterfaceRepository, PeerRepository};
use wireforge_core::application::services::{CreatePeerInput, UpdatePeerInput};
use wireforge_core::crypto::unseal;
use wireforge_core::domain::audit::AuditAction;
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::domain::{Id, Peer};
use wireforge_core::peer_conf::render_peer_conf;
use wireforge_core::CoreError;

use crate::audit::record as audit_record;
use crate::extractors::AuthUser;
use crate::flash::{set_flash, take_flash, Flash};
use crate::templates::{
    EditPeerPage, InterfaceOption, NewPeerPage, PeerCreatedPage, PeerEditFormState,
    PeerEnabledFragment, PeerFormState, PeerRow, PeersPage,
};
use crate::{AppState, WebError};

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let interfaces = state.interfaces.list().await?;
    let iface_names: HashMap<_, _> = interfaces
        .iter()
        .map(|i| (i.id, i.name.clone()))
        .collect();

    let peers = state.peers.list_all().await?;
    let rows: Vec<PeerRow> = peers
        .into_iter()
        .map(|p| PeerRow {
            id: p.id.to_string(),
            name: p.name,
            interface_name: iface_names
                .get(&p.interface_id)
                .cloned()
                .unwrap_or_else(|| "(orphan)".into()),
            public_key_short: short_pk(p.public_key.as_str()),
            allowed_ips: p
                .allowed_ips
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            enabled: p.enabled,
            has_private_key: p.private_key_sealed.is_some(),
        })
        .collect();

    let flash = take_flash(&session).await;
    let page = PeersPage {
        user: &user,
        flash: flash.as_ref(),
        peers: rows,
        has_interfaces: !interfaces.is_empty(),
    };
    Ok(render(&page))
}

pub async fn new_page(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let interfaces = state.interfaces.list().await?;
    if interfaces.is_empty() {
        return Ok(Redirect::to("/interfaces/new").into_response());
    }
    let options: Vec<InterfaceOption> = interfaces
        .iter()
        .map(|i| InterfaceOption {
            id: i.id.to_string(),
            name: i.name.clone(),
        })
        .collect();

    let default_iface = interfaces[0].id.to_string();
    let flash = take_flash(&session).await;
    let page = NewPeerPage {
        user: &user,
        flash: flash.as_ref(),
        error: None,
        form: PeerFormState {
            interface_id: default_iface,
            persistent_keepalive: "25".into(),
            nat: true,
            ..Default::default()
        },
        interfaces: options,
    };
    Ok(render(&page).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    pub name: String,
    pub interface_id: String,
    #[serde(default)]
    pub allowed_ips: String,
    #[serde(default)]
    pub primary_dns: String,
    #[serde(default)]
    pub secondary_dns: String,
    #[serde(default)]
    pub nat: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub private_key: String,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Form(form): Form<CreateForm>,
) -> Result<Response, WebError> {
    require_mutate(&user)?;

    let interface_id = match Uuid::parse_str(&form.interface_id) {
        Ok(u) => Id::<InterfaceMarker>::from_uuid(u),
        Err(_) => return Ok(form_error(&state, &user, &form, "Invalid interface").await),
    };
    let allowed_ips = match parse_allowed(&form.allowed_ips) {
        Ok(v) => v,
        Err(msg) => return Ok(form_error(&state, &user, &form, &msg).await),
    };
    let persistent_keepalive = match parse_keepalive(&form.persistent_keepalive) {
        Ok(v) => v,
        Err(msg) => return Ok(form_error(&state, &user, &form, &msg).await),
    };
    let primary_dns = match parse_dns(&form.primary_dns) {
        Ok(v) => v,
        Err(msg) => return Ok(form_error(&state, &user, &form, &msg).await),
    };
    let secondary_dns = match parse_dns(&form.secondary_dns) {
        Ok(v) => v,
        Err(msg) => return Ok(form_error(&state, &user, &form, &msg).await),
    };

    let input = CreatePeerInput {
        interface_id,
        name: form.name.trim().to_string(),
        allowed_ips,
        primary_dns,
        secondary_dns,
        nat: form.nat.is_some(),
        persistent_keepalive,
        owner_user_id: Some(user.id),
        public_key: form.public_key.trim().to_string(),
        private_key: form.private_key.trim().to_string(),
    };

    let peer = match state.peer_service().create_with_server_keypair(input).await {
        Ok(p) => p,
        Err(CoreError::Validation(msg) | CoreError::Conflict(msg))
        | Err(CoreError::IpPoolExhausted(msg)) => {
            return Ok(form_error(&state, &user, &form, &msg).await);
        }
        Err(e) => return Err(e.into()),
    };

    let iface = state
        .interfaces
        .find_by_id(peer.interface_id)
        .await?
        .ok_or(WebError::NotFound)?;
    let endpoint = state
        .settings_snapshot()
        .endpoint
        .unwrap_or_else(|| "vpn.example.com".to_string());
    let conf = render_peer_conf(&iface, &peer, &endpoint, &state.seal_key)?;

    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::PeerCreated,
        Some("peer"),
        Some(&peer.id.to_string()),
        Some(serde_json::json!({ "name": peer.name, "interface_id": peer.interface_id.to_string() })),
    )
    .await;

    let page = PeerCreatedPage {
        user: &user,
        flash: None,
        peer_id: peer.id.to_string(),
        peer_name: peer.name,
        config: conf,
    };
    Ok(render(&page).into_response())
}

pub async fn edit_page(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    let id = parse_id(&id)?;
    let peer = state.peers.find_by_id(id).await?.ok_or(WebError::NotFound)?;
    let interfaces = state.interfaces.list().await?;
    let options: Vec<InterfaceOption> = interfaces
        .iter()
        .map(|i| InterfaceOption {
            id: i.id.to_string(),
            name: i.name.clone(),
        })
        .collect();
    let flash = take_flash(&session).await;
    let form = PeerEditFormState {
        name: peer.name.clone(),
        interface_id: peer.interface_id.to_string(),
        allowed_ips: peer
            .allowed_ips
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        primary_dns: peer.primary_dns.clone().unwrap_or_default(),
        secondary_dns: peer.secondary_dns.clone().unwrap_or_default(),
        nat: peer.nat,
        persistent_keepalive: peer
            .persistent_keepalive
            .map(|k| k.to_string())
            .unwrap_or_default(),
        enabled: peer.enabled,
        public_key: peer.public_key.as_str().to_string(),
        private_key: reveal_private_key(&state, &peer),
    };
    let page = EditPeerPage {
        user: &user,
        flash: flash.as_ref(),
        error: None,
        peer_id: peer.id.to_string(),
        form,
        interfaces: options,
    };
    Ok(render(&page))
}

#[derive(Debug, Deserialize)]
pub struct EditForm {
    pub name: String,
    #[serde(default)]
    pub interface_id: String,
    #[serde(default)]
    pub allowed_ips: String,
    #[serde(default)]
    pub primary_dns: String,
    #[serde(default)]
    pub secondary_dns: String,
    #[serde(default)]
    pub nat: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: String,
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub private_key: String,
}

pub async fn edit(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
    Form(form): Form<EditForm>,
) -> Result<Response, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;

    let allowed_ips = match parse_allowed(&form.allowed_ips) {
        Ok(Some(v)) if !v.is_empty() => v,
        Ok(_) => return Ok(edit_form_error(&state, &user, id, &form, "Allowed IPs required").await),
        Err(msg) => return Ok(edit_form_error(&state, &user, id, &form, &msg).await),
    };
    let persistent_keepalive = match parse_keepalive(&form.persistent_keepalive) {
        Ok(v) => v,
        Err(msg) => return Ok(edit_form_error(&state, &user, id, &form, &msg).await),
    };
    let primary_dns = match parse_dns(&form.primary_dns) {
        Ok(v) => v,
        Err(msg) => return Ok(edit_form_error(&state, &user, id, &form, &msg).await),
    };
    let secondary_dns = match parse_dns(&form.secondary_dns) {
        Ok(v) => v,
        Err(msg) => return Ok(edit_form_error(&state, &user, id, &form, &msg).await),
    };
    let interface_id = match Uuid::parse_str(&form.interface_id) {
        Ok(u) => Id::<InterfaceMarker>::from_uuid(u),
        Err(_) => return Ok(edit_form_error(&state, &user, id, &form, "Invalid interface").await),
    };

    let input = UpdatePeerInput {
        name: form.name.trim().to_string(),
        interface_id,
        allowed_ips,
        primary_dns,
        secondary_dns,
        nat: form.nat.is_some(),
        persistent_keepalive,
        enabled: form.enabled.as_deref() == Some("on"),
        public_key: form.public_key.trim().to_string(),
        private_key: form.private_key.trim().to_string(),
    };
    match state.peer_service().update(id, input).await {
        Ok(peer) => {
            set_flash(&session, Flash::success(format!("Peer '{}' updated", peer.name))).await;
            Ok(Redirect::to("/peers").into_response())
        }
        Err(CoreError::Validation(msg) | CoreError::Conflict(msg)) => {
            Ok(edit_form_error(&state, &user, id, &form, &msg).await)
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn toggle(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;
    let peer = state.peers.find_by_id(id).await?.ok_or(WebError::NotFound)?;
    let updated = state.peer_service().set_enabled(id, !peer.enabled).await?;
    audit_record(
        &state,
        Some(user.id),
        None,
        if updated.enabled {
            AuditAction::PeerEnabled
        } else {
            AuditAction::PeerDisabled
        },
        Some("peer"),
        Some(&updated.id.to_string()),
        None,
    )
    .await;

    // HTMX fragment response — only the swapped <td> cell, no full page.
    let fragment = PeerEnabledFragment {
        peer_id: updated.id.to_string(),
        enabled: updated.enabled,
    };
    Ok(render(&fragment))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;
    state.peer_service().delete(id).await?;
    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::PeerDeleted,
        Some("peer"),
        Some(&id.to_string()),
        None,
    )
    .await;
    set_flash(&session, Flash::success("Peer deleted")).await;
    Ok(Redirect::to("/peers"))
}

pub async fn download(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, WebError> {
    let id = parse_id(&id)?;
    let peer = state.peers.find_by_id(id).await?.ok_or(WebError::NotFound)?;
    let iface = state
        .interfaces
        .find_by_id(peer.interface_id)
        .await?
        .ok_or(WebError::NotFound)?;
    let endpoint = state
        .settings_snapshot()
        .endpoint
        .unwrap_or_else(|| "vpn.example.com".to_string());
    let conf = render_peer_conf(&iface, &peer, &endpoint, &state.seal_key)?;

    let filename = sanitize_filename(&peer.name);
    let disposition = format!("attachment; filename=\"{filename}.conf\"");

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok((StatusCode::OK, headers, conf).into_response())
}

pub async fn qr(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, WebError> {
    let id = parse_id(&id)?;
    let peer = state.peers.find_by_id(id).await?.ok_or(WebError::NotFound)?;
    let iface = state
        .interfaces
        .find_by_id(peer.interface_id)
        .await?
        .ok_or(WebError::NotFound)?;
    let endpoint = state
        .settings_snapshot()
        .endpoint
        .unwrap_or_else(|| "vpn.example.com".to_string());
    let conf = render_peer_conf(&iface, &peer, &endpoint, &state.seal_key)?;

    let code = QrCode::new(conf.as_bytes())
        .map_err(|e| WebError::Internal(format!("qr encode: {e}")))?;
    let svg_str = code
        .render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((StatusCode::OK, headers, Body::from(svg_str)).into_response())
}

fn parse_id(s: &str) -> Result<Id<PeerMarker>, WebError> {
    Uuid::parse_str(s)
        .map(Id::from_uuid)
        .map_err(|_| WebError::NotFound)
}

fn require_mutate(user: &AuthUser) -> Result<(), WebError> {
    if user.role.can_mutate() {
        Ok(())
    } else {
        Err(WebError::Forbidden)
    }
}

fn parse_allowed(s: &str) -> Result<Option<Vec<IpNet>>, String> {
    if s.trim().is_empty() {
        return Ok(None);
    }
    let parsed: Result<Vec<IpNet>, _> = s
        .split(',')
        .map(|t| IpNet::from_str(t.trim()))
        .collect();
    parsed.map(Some).map_err(|_| "Invalid Allowed IPs".into())
}

fn parse_keepalive(s: &str) -> Result<Option<u16>, String> {
    match s.trim() {
        "" => Ok(None),
        s => s.parse::<u16>().map(Some).map_err(|_| "Invalid keepalive".into()),
    }
}

/// Validate an optional DNS server entry. Empty → `None`; otherwise the value
/// must parse as a bare IP address.
fn parse_dns(s: &str) -> Result<Option<String>, String> {
    match s.trim() {
        "" => Ok(None),
        v => v
            .parse::<std::net::IpAddr>()
            .map(|_| Some(v.to_string()))
            .map_err(|_| "Invalid DNS address".into()),
    }
}

/// Unseal a peer's stored private key for display in the edit form. Returns an
/// empty string when the peer has no server-side private key or unsealing fails.
fn reveal_private_key(state: &AppState, peer: &Peer) -> String {
    peer.private_key_sealed
        .as_deref()
        .and_then(|blob| unseal(blob, &state.seal_key).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

async fn form_error(state: &AppState, user: &AuthUser, form: &CreateForm, msg: &str) -> Response {
    let interfaces = state.interfaces.list().await.unwrap_or_default();
    let options: Vec<InterfaceOption> = interfaces
        .into_iter()
        .map(|i| InterfaceOption {
            id: i.id.to_string(),
            name: i.name,
        })
        .collect();
    let page = NewPeerPage {
        user,
        flash: None,
        error: Some(msg),
        form: PeerFormState {
            name: form.name.clone(),
            interface_id: form.interface_id.clone(),
            allowed_ips: form.allowed_ips.clone(),
            primary_dns: form.primary_dns.clone(),
            secondary_dns: form.secondary_dns.clone(),
            nat: form.nat.is_some(),
            persistent_keepalive: form.persistent_keepalive.clone(),
            public_key: form.public_key.clone(),
            private_key: form.private_key.clone(),
        },
        interfaces: options,
    };
    render(&page).into_response()
}

async fn edit_form_error(
    state: &AppState,
    user: &AuthUser,
    id: Id<PeerMarker>,
    form: &EditForm,
    msg: &str,
) -> Response {
    let peer = state.peers.find_by_id(id).await.ok().flatten();
    let options: Vec<InterfaceOption> = state
        .interfaces
        .list()
        .await
        .unwrap_or_default()
        .iter()
        .map(|i| InterfaceOption {
            id: i.id.to_string(),
            name: i.name.clone(),
        })
        .collect();
    let page = EditPeerPage {
        user,
        flash: None,
        error: Some(msg),
        peer_id: peer
            .as_ref()
            .map(|p| p.id.to_string())
            .unwrap_or_else(|| id.to_string()),
        form: PeerEditFormState {
            name: form.name.clone(),
            interface_id: form.interface_id.clone(),
            allowed_ips: form.allowed_ips.clone(),
            primary_dns: form.primary_dns.clone(),
            secondary_dns: form.secondary_dns.clone(),
            nat: form.nat.is_some(),
            persistent_keepalive: form.persistent_keepalive.clone(),
            enabled: form.enabled.as_deref() == Some("on"),
            public_key: form.public_key.clone(),
            private_key: form.private_key.clone(),
        },
        interfaces: options,
    };
    render(&page).into_response()
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn short_pk(pk: &str) -> String {
    if pk.len() > 12 {
        format!("{}...{}", &pk[..6], &pk[pk.len() - 6..])
    } else {
        pk.to_string()
    }
}

fn render<T: Template>(t: &T) -> Html<String> {
    Html(t.render().unwrap_or_else(|e| format!("render error: {e}")))
}
