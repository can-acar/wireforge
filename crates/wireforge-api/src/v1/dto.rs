use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use wireforge_core::domain::{ApiToken, Interface, Peer};
use wireforge_core::CoreError;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InterfaceDto {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub listen_port: u16,
    pub endpoint: Option<String>,
    pub gateway: Option<String>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Interface> for InterfaceDto {
    fn from(i: Interface) -> Self {
        Self {
            id: i.id.to_string(),
            name: i.name,
            public_key: i.public_key.into_inner(),
            listen_port: i.listen_port,
            endpoint: i.endpoint,
            gateway: i.gateway,
            ipv4_cidr: i.ipv4_cidr.map(|n| n.to_string()),
            ipv6_cidr: i.ipv6_cidr.map(|n| n.to_string()),
            mtu: i.mtu,
            dns: i.dns,
            on_up: i.on_up,
            on_down: i.on_down,
            status: i.status.as_str().to_string(),
            created_at: i.created_at.to_rfc3339(),
            updated_at: i.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerDto {
    pub id: String,
    pub interface_id: String,
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    pub nat: bool,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub bandwidth_used_bytes: u64,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Peer> for PeerDto {
    fn from(p: Peer) -> Self {
        Self {
            id: p.id.to_string(),
            interface_id: p.interface_id.to_string(),
            name: p.name,
            public_key: p.public_key.into_inner(),
            allowed_ips: p.allowed_ips.iter().map(|n| n.to_string()).collect(),
            primary_dns: p.primary_dns,
            secondary_dns: p.secondary_dns,
            nat: p.nat,
            endpoint: p.endpoint,
            persistent_keepalive: p.persistent_keepalive,
            bandwidth_used_bytes: p.bandwidth_used_bytes,
            enabled: p.enabled,
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthDto {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiError {
    pub error: String,
    pub status: u16,
}

// ---------------------------------------------------------------------------
// Request bodies (write / lifecycle endpoints)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
pub struct CreateInterfaceRequest {
    #[validate(length(min = 1, max = 15))]
    pub name: String,
    #[validate(range(min = 1, max = 65535))]
    pub listen_port: u16,
    pub endpoint: Option<String>,
    /// Host egress interface for NAT/masquerade (e.g. `eth0`). Omit for no NAT.
    pub gateway: Option<String>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
    /// BYOK base64 private key. Omit/empty → a fresh keypair is generated.
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
pub struct UpdateInterfaceRequest {
    #[validate(range(min = 1, max = 65535))]
    pub listen_port: u16,
    pub endpoint: Option<String>,
    pub gateway: Option<String>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
    /// BYOK: a changed base64 private key re-derives the public key. Omit/empty
    /// → keep the current keypair.
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
pub struct CreatePeerRequest {
    pub interface_id: String,
    #[validate(length(min = 1, max = 64))]
    pub name: String,
    /// Allowed IPs (CIDRs). Omit to auto-assign from the interface subnet.
    pub allowed_ips: Option<Vec<String>>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    #[serde(default)]
    pub nat: bool,
    pub persistent_keepalive: Option<u16>,
    /// BYOK base64 public key (optional).
    #[serde(default)]
    pub public_key: String,
    /// BYOK base64 private key (optional). Empty → server generates a keypair.
    #[serde(default)]
    pub private_key: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
pub struct UpdatePeerRequest {
    #[validate(length(min = 1, max = 64))]
    pub name: String,
    pub interface_id: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    #[serde(default)]
    pub nat: bool,
    pub persistent_keepalive: Option<u16>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub private_key: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
pub struct CreateTokenRequest {
    #[validate(length(min = 1, max = 64))]
    pub name: String,
    /// Optional lifetime in days. Omit for a non-expiring token.
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TokenDto {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl From<ApiToken> for TokenDto {
    fn from(t: ApiToken) -> Self {
        Self {
            id: t.id.to_string(),
            name: t.name,
            scopes: t.scopes,
            created_at: t.created_at.to_rfc3339(),
            expires_at: t.expires_at.map(|d| d.to_rfc3339()),
            revoked_at: t.revoked_at.map(|d| d.to_rfc3339()),
        }
    }
}

/// Returned exactly once on token creation. `token` is the plaintext secret and
/// is never retrievable again.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CreatedTokenDto {
    pub token: String,
    #[serde(flatten)]
    pub info: TokenDto,
}

// ---------------------------------------------------------------------------
// Shared error helpers
// ---------------------------------------------------------------------------

/// Build a JSON error response with the given status.
pub fn error_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            error: msg.into(),
            status: status.as_u16(),
        }),
    )
}

pub fn unauthorized() -> (StatusCode, Json<ApiError>) {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

pub fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    error_response(StatusCode::FORBIDDEN, msg)
}

pub fn not_found() -> (StatusCode, Json<ApiError>) {
    error_response(StatusCode::NOT_FOUND, "not found")
}

pub fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    error_response(StatusCode::BAD_REQUEST, msg)
}

/// Map a domain `CoreError` onto an HTTP status + JSON body.
pub fn from_core(e: CoreError) -> (StatusCode, Json<ApiError>) {
    let status = match &e {
        CoreError::NotFound(_) => StatusCode::NOT_FOUND,
        CoreError::Conflict(_) => StatusCode::CONFLICT,
        CoreError::Validation(_) => StatusCode::BAD_REQUEST,
        CoreError::Forbidden(_) => StatusCode::FORBIDDEN,
        CoreError::Unauthorized => StatusCode::UNAUTHORIZED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, e.to_string())
}
