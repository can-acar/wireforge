use std::str::FromStr;

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use ipnet::IpNet;
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;
use wireforge_core::application::ports::{InterfaceRepository, PeerRepository, SysNetPort};
use wireforge_core::application::services::{CreateInterfaceInput, UpdateInterfaceInput};
use wireforge_core::crypto::unseal;
use wireforge_core::domain::audit::AuditAction;
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::{Id, Interface};
use wireforge_core::CoreError;
use wireforge_infra::nat::render_nat_rules;

use crate::audit::record as audit_record;
use crate::extractors::AuthUser;
use crate::flash::{set_flash, take_flash, Flash};
use crate::templates::{
    EditInterfacePage, GatewayOption, InterfaceFormState, InterfaceRow, InterfacesPage,
    NewInterfacePage,
};
use crate::{AppState, WebError};

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let interfaces = state.interfaces.list().await?;

    let mut rows = Vec::with_capacity(interfaces.len());
    for iface in interfaces {
        let peer_count = state.peers.list_for_interface(iface.id).await?.len();
        rows.push(InterfaceRow {
            id: iface.id.to_string(),
            name: iface.name,
            public_key_short: short_pk(iface.public_key.as_str()),
            listen_port: iface.listen_port,
            status: iface.status.as_str(),
            peer_count,
        });
    }

    let flash = take_flash(&session).await;
    let page = InterfacesPage {
        user: &user,
        flash: flash.as_ref(),
        interfaces: rows,
    };
    Ok(render(&page))
}

pub async fn new_page(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let flash = take_flash(&session).await;
    // Pre-fill a fresh keypair so the keys are visible up front (BYOK: the user
    // may replace the private key, or leave it to be (re)generated on submit).
    let (private_key, public_key) = state
        .interface_service()
        .fresh_keypair()
        .await
        .unwrap_or_default();
    let page = NewInterfacePage {
        user: &user,
        flash: flash.as_ref(),
        error: None,
        form: InterfaceFormState {
            listen_port: "51820".into(),
            ipv4_cidr: "10.7.0.1/24".into(),
            dns: "1.1.1.1, 1.0.0.1".into(),
            mtu: "1420".into(),
            public_key,
            private_key,
            ..Default::default()
        },
        gateways: gateways(&state),
    };
    Ok(render(&page))
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    pub name: String,
    pub listen_port: String,
    pub ipv4_cidr: String,
    #[serde(default)]
    pub ipv6_cidr: String,
    #[serde(default)]
    pub mtu: String,
    #[serde(default)]
    pub dns: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub on_up: String,
    #[serde(default)]
    pub on_down: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub private_key: String,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Form(form): Form<CreateForm>,
) -> Result<Response, WebError> {
    require_mutate(&user)?;

    let (listen_port, ipv4_cidr, ipv6_cidr, mtu, dns) = match parse_form(&form) {
        Ok(v) => v,
        Err(msg) => return Ok(form_error_new(&state, &user, &form, &msg)),
    };

    let input = CreateInterfaceInput {
        name: form.name.trim().to_string(),
        listen_port,
        endpoint: None,
        gateway: blank_to_none(&form.gateway),
        ipv4_cidr,
        ipv6_cidr,
        mtu,
        dns,
        on_up: blank_to_none(&form.on_up),
        on_down: blank_to_none(&form.on_down),
        private_key: form.private_key.trim().to_string(),
    };
    match state.interface_service().create(input).await {
        Ok(iface) => {
            audit_record(
                &state,
                Some(user.id),
                None,
                AuditAction::InterfaceCreated,
                Some("interface"),
                Some(&iface.id.to_string()),
                Some(serde_json::json!({ "name": iface.name })),
            )
            .await;
            set_flash(&session, Flash::success(format!("Interface '{}' created", iface.name)))
                .await;
            Ok(Redirect::to("/interfaces").into_response())
        }
        Err(CoreError::Conflict(msg) | CoreError::Validation(msg)) => {
            Ok(form_error_new(&state, &user, &form, &msg))
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn edit_page(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    let id = parse_id(&id)?;
    let iface = state
        .interfaces
        .find_by_id(id)
        .await?
        .ok_or(WebError::NotFound)?;
    let flash = take_flash(&session).await;
    let form = InterfaceFormState {
        name: iface.name.clone(),
        listen_port: iface.listen_port.to_string(),
        ipv4_cidr: iface.ipv4_cidr.map(|n| n.to_string()).unwrap_or_default(),
        ipv6_cidr: iface.ipv6_cidr.map(|n| n.to_string()).unwrap_or_default(),
        mtu: iface.mtu.map(|m| m.to_string()).unwrap_or_default(),
        dns: iface.dns.join(", "),
        gateway: iface.gateway.clone().unwrap_or_default(),
        on_up: iface.on_up.clone().unwrap_or_default(),
        on_down: iface.on_down.clone().unwrap_or_default(),
        public_key: iface.public_key.as_str().to_string(),
        private_key: reveal_interface_private_key(&state, &iface),
    };
    let generated_rules = generated_rules_for(&iface);
    let page = EditInterfacePage {
        user: &user,
        flash: flash.as_ref(),
        error: None,
        iface_id: iface.id.to_string(),
        iface_name: iface.name,
        iface_status: iface.status.as_str(),
        form,
        gateways: gateways(&state),
        generated_rules,
    };
    Ok(render(&page))
}

pub async fn edit(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
    Form(form): Form<CreateForm>,
) -> Result<Response, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;
    let iface = state
        .interfaces
        .find_by_id(id)
        .await?
        .ok_or(WebError::NotFound)?;

    let (listen_port, ipv4_cidr, ipv6_cidr, mtu, dns) = match parse_form(&form) {
        Ok(v) => v,
        Err(msg) => return Ok(form_error_edit(&state, &user, &iface, &form, &msg)),
    };

    let input = UpdateInterfaceInput {
        listen_port,
        endpoint: None,
        gateway: blank_to_none(&form.gateway),
        ipv4_cidr,
        ipv6_cidr,
        mtu,
        dns,
        on_up: blank_to_none(&form.on_up),
        on_down: blank_to_none(&form.on_down),
        private_key: form.private_key.trim().to_string(),
    };
    match state.interface_service().update(id, input).await {
        Ok(_) => {
            set_flash(&session, Flash::success(format!("Interface '{}' updated", iface.name)))
                .await;
            Ok(Redirect::to("/interfaces").into_response())
        }
        Err(CoreError::Validation(msg)) => {
            Ok(form_error_edit(&state, &user, &iface, &form, &msg))
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn start(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;
    let iface = state.interface_service().start(id).await?;
    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::InterfaceStarted,
        Some("interface"),
        Some(&iface.id.to_string()),
        None,
    )
    .await;
    set_flash(&session, Flash::success(format!("Interface '{}' is up", iface.name))).await;
    Ok(Redirect::to("/interfaces"))
}

pub async fn stop(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;
    let iface = state.interface_service().stop(id).await?;
    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::InterfaceStopped,
        Some("interface"),
        Some(&iface.id.to_string()),
        None,
    )
    .await;
    set_flash(&session, Flash::success(format!("Interface '{}' is down", iface.name))).await;
    Ok(Redirect::to("/interfaces"))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, WebError> {
    require_mutate(&user)?;
    let id = parse_id(&id)?;
    state.interface_service().delete(id).await?;
    audit_record(
        &state,
        Some(user.id),
        None,
        AuditAction::InterfaceDeleted,
        Some("interface"),
        Some(&id.to_string()),
        None,
    )
    .await;
    set_flash(&session, Flash::success("Interface deleted")).await;
    Ok(Redirect::to("/interfaces"))
}

fn parse_id(s: &str) -> Result<Id<InterfaceMarker>, WebError> {
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

type ParsedForm = (u16, Option<IpNet>, Option<IpNet>, Option<u16>, Vec<String>);

fn parse_form(form: &CreateForm) -> Result<ParsedForm, String> {
    let listen_port = form
        .listen_port
        .parse::<u16>()
        .map_err(|_| "Listen port must be 1-65535".to_string())
        .and_then(|v| if v > 0 { Ok(v) } else { Err("Listen port must be 1-65535".into()) })?;
    let ipv4_cidr = match form.ipv4_cidr.trim() {
        "" => None,
        s => Some(IpNet::from_str(s).map_err(|_| "Invalid IPv4 CIDR".to_string())?),
    };
    let ipv6_cidr = match form.ipv6_cidr.trim() {
        "" => None,
        s => Some(IpNet::from_str(s).map_err(|_| "Invalid IPv6 CIDR".to_string())?),
    };
    let mtu = match form.mtu.trim() {
        "" => None,
        s => Some(s.parse::<u16>().map_err(|_| "Invalid MTU".to_string())?),
    };
    let dns = form
        .dns
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Ok((listen_port, ipv4_cidr, ipv6_cidr, mtu, dns))
}

/// Trim a form string, mapping empty → `None`.
fn blank_to_none(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Selectable host egress interfaces for the gateway dropdown. Excludes
/// loopback and WireGuard interfaces themselves. A `getifaddrs` failure
/// degrades to an empty list rather than erroring the page.
fn gateways(state: &AppState) -> Vec<GatewayOption> {
    state
        .sysnet
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.name != "lo" && !i.name.starts_with("wg"))
        .map(|i| GatewayOption {
            name: i.name,
            up: i.up,
        })
        .collect()
}

/// The iptables rules NAT would install for this interface's gateway, rendered
/// read-only for display. Empty when no gateway is configured.
fn generated_rules_for(iface: &Interface) -> String {
    match iface.gateway.as_deref() {
        Some(gw) if !gw.is_empty() => {
            render_nat_rules(&iface.name, gw, iface.ipv6_cidr.is_some())
        }
        _ => String::new(),
    }
}

/// Unseal an interface's stored private key for display in the edit form.
/// Returns an empty string if unsealing fails. The plaintext lives only in the
/// transient form state returned to the template — never written back.
fn reveal_interface_private_key(state: &AppState, iface: &Interface) -> String {
    unseal(&iface.private_key_sealed, &state.seal_key)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

fn form_error_new(state: &AppState, user: &AuthUser, form: &CreateForm, msg: &str) -> Response {
    let page = NewInterfacePage {
        user,
        flash: None,
        error: Some(msg),
        form: form_state(form),
        gateways: gateways(state),
    };
    render(&page).into_response()
}

fn form_error_edit(
    state: &AppState,
    user: &AuthUser,
    iface: &Interface,
    form: &CreateForm,
    msg: &str,
) -> Response {
    let page = EditInterfacePage {
        user,
        flash: None,
        error: Some(msg),
        iface_id: iface.id.to_string(),
        iface_name: iface.name.clone(),
        iface_status: iface.status.as_str(),
        form: form_state(form),
        gateways: gateways(state),
        generated_rules: generated_rules_for(iface),
    };
    render(&page).into_response()
}

fn form_state(form: &CreateForm) -> InterfaceFormState {
    InterfaceFormState {
        name: form.name.clone(),
        listen_port: form.listen_port.clone(),
        ipv4_cidr: form.ipv4_cidr.clone(),
        ipv6_cidr: form.ipv6_cidr.clone(),
        mtu: form.mtu.clone(),
        dns: form.dns.clone(),
        gateway: form.gateway.clone(),
        on_up: form.on_up.clone(),
        on_down: form.on_down.clone(),
        public_key: form.public_key.clone(),
        private_key: form.private_key.clone(),
    }
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
