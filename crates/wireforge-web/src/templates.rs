//! Askama template type definitions.

use askama::Template;

use crate::extractors::AuthUser;
use crate::flash::Flash;

#[derive(Template)]
#[template(path = "auth/login.html")]
pub struct LoginPage<'a> {
    pub error: Option<&'a str>,
    pub username: &'a str,
}

#[derive(Template)]
#[template(path = "auth/setup.html")]
pub struct SetupPage<'a> {
    pub error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "auth/totp.html")]
pub struct TotpChallengePage<'a> {
    pub error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "profile/index.html")]
pub struct ProfilePage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub totp_enabled: bool,
}

#[derive(Template)]
#[template(path = "profile/totp_setup.html")]
pub struct TotpSetupPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub error: Option<&'a str>,
    pub secret_base32: String,
    pub qr_svg: String,
}

#[derive(Template)]
#[template(path = "audit/list.html")]
pub struct AuditPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub events: Vec<AuditRow>,
}

#[derive(Template)]
#[template(path = "settings/index.html")]
pub struct SettingsPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub error: Option<&'a str>,
    pub form: SettingsFormState,
    /// Read-only, boot-time values shown for reference (not editable).
    pub readonly: SettingsReadonly,
}

/// String-typed mirror of `RuntimeSettings` for form rendering (numbers as
/// strings so we can re-populate inputs verbatim on validation errors).
#[derive(Debug, Clone, Default)]
pub struct SettingsFormState {
    pub locale_default: String,
    pub totp_issuer: String,
    pub login_max_attempts: String,
    pub login_lockout_secs: String,
    pub session_timeout_hours: String,
    pub endpoint: String,
    pub traffic_poller_interval_secs: String,
    pub traffic_enabled: bool,
    pub backup_retention_days: String,
    pub log_level: String,
}

#[derive(Debug, Clone, Default)]
pub struct SettingsReadonly {
    pub database_path: String,
    pub server_bind: String,
    pub session_secure: bool,
    pub master_key_masked: String,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub created_at: String,
    pub actor: String,
    pub actor_ip: String,
    pub action: String,
    pub resource: String,
    pub metadata: String,
}

#[derive(Template)]
#[template(path = "dashboard/index.html")]
pub struct DashboardPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub interface_count: usize,
    pub peer_count: usize,
    pub up_interface_count: usize,
    /// Host (system) network interface counts for the summary card.
    pub host_iface_count: usize,
    pub host_iface_up: usize,
    /// Initial traffic snapshot as JSON; the browser paints from this then
    /// keeps it fresh over SSE (`/dashboard/traffic/stream`).
    pub traffic_json: String,
}

#[derive(Template)]
#[template(path = "system/index.html")]
pub struct SystemPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    /// Initial host-interface snapshot as JSON; the browser paints from this
    /// then keeps it fresh over SSE (`/system/interfaces/stream`).
    pub sysnet_json: String,
}

#[derive(Template)]
#[template(path = "interfaces/list.html")]
pub struct InterfacesPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub interfaces: Vec<InterfaceRow>,
}

#[derive(Template)]
#[template(path = "interfaces/new.html")]
pub struct NewInterfacePage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub error: Option<&'a str>,
    pub form: InterfaceFormState,
    pub gateways: Vec<GatewayOption>,
}

#[derive(Template)]
#[template(path = "interfaces/edit.html")]
pub struct EditInterfacePage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub error: Option<&'a str>,
    pub iface_id: String,
    pub iface_name: String,
    pub iface_status: &'static str,
    pub form: InterfaceFormState,
    pub gateways: Vec<GatewayOption>,
    /// Read-only iptables rules NAT will install for the current gateway.
    /// Empty when no gateway is set.
    pub generated_rules: String,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceFormState {
    pub name: String,
    pub listen_port: String,
    pub ipv4_cidr: String,
    pub ipv6_cidr: String,
    pub mtu: String,
    pub dns: String,
    pub gateway: String,
    pub on_up: String,
    pub on_down: String,
    /// BYOK key fields. `public_key` is read-only on edit (re-derived from the
    /// private key on save); `private_key` is the unsealed value, masked in UI.
    pub public_key: String,
    pub private_key: String,
}

/// A selectable host egress interface for the gateway dropdown.
#[derive(Debug, Clone)]
pub struct GatewayOption {
    pub name: String,
    pub up: bool,
}

#[derive(Debug, Clone)]
pub struct InterfaceRow {
    pub id: String,
    pub name: String,
    pub public_key_short: String,
    pub listen_port: u16,
    pub status: &'static str,
    pub peer_count: usize,
}

#[derive(Template)]
#[template(path = "peers/list.html")]
pub struct PeersPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub peers: Vec<PeerRow>,
    pub has_interfaces: bool,
}

#[derive(Template)]
#[template(path = "peers/new.html")]
pub struct NewPeerPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub error: Option<&'a str>,
    pub form: PeerFormState,
    pub interfaces: Vec<InterfaceOption>,
}

#[derive(Template)]
#[template(path = "peers/edit.html")]
pub struct EditPeerPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub error: Option<&'a str>,
    pub peer_id: String,
    pub form: PeerEditFormState,
    pub interfaces: Vec<InterfaceOption>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerFormState {
    pub name: String,
    pub interface_id: String,
    pub allowed_ips: String,
    pub primary_dns: String,
    pub secondary_dns: String,
    pub nat: bool,
    pub persistent_keepalive: String,
    /// BYOK key fields. Both blank → a keypair is generated server-side on create.
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct PeerEditFormState {
    pub name: String,
    pub interface_id: String,
    pub allowed_ips: String,
    pub primary_dns: String,
    pub secondary_dns: String,
    pub nat: bool,
    pub persistent_keepalive: String,
    pub enabled: bool,
    /// BYOK key fields. `public_key` is editable; `private_key` is the
    /// unsealed value pre-filled for display (masked) and re-submission.
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceOption {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "peers/created.html")]
pub struct PeerCreatedPage<'a> {
    pub user: &'a AuthUser,
    pub flash: Option<&'a Flash>,
    pub peer_id: String,
    pub peer_name: String,
    pub config: String,
}

#[derive(Template)]
#[template(path = "peers/_row_enabled.html")]
pub struct PeerEnabledFragment {
    pub peer_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct PeerRow {
    pub id: String,
    pub name: String,
    pub interface_name: String,
    pub public_key_short: String,
    pub allowed_ips: String,
    pub enabled: bool,
    pub has_private_key: bool,
}
