use std::path::Path;

use anyhow::Result;
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub wireguard: WireGuardConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub federation: FederationConfig,
}

/// Optional OIDC / SSO settings.
///
/// Faz 6 ships only the configuration surface — the actual provider client
/// (`openidconnect` crate) is wired in once the auth flow grows past
/// password / TOTP / API-token.
#[allow(dead_code)] // Faz 6 — wired in by upcoming OIDC handler.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub role_claim_mapping: std::collections::HashMap<String, String>,
}

/// Optional federation settings — connect a secondary VPN node to a remote
/// control plane via a long-lived gRPC channel. Faz 6 placeholder.
#[allow(dead_code)] // Faz 6 — wired in by upcoming federation client.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FederationConfig {
    #[serde(default)]
    pub enabled: bool,
    pub control_plane_url: Option<String>,
    pub node_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub session_secure: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            session_secure: false,
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:8080".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

fn default_db_path() -> String {
    "./data/wireforge.sqlite".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Master key used to seal encryption-at-rest secrets (TOTP, WG private keys).
    /// Generate with `openssl rand -base64 32` and keep it secret.
    pub master_key: String,
    #[serde(default = "default_max_attempts")]
    pub login_max_attempts: u32,
    #[serde(default = "default_lockout_secs")]
    pub login_lockout_secs: u64,
    #[serde(default = "default_issuer")]
    pub totp_issuer: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            master_key: "CHANGE-ME-32-bytes-or-more-recommended".into(),
            login_max_attempts: default_max_attempts(),
            login_lockout_secs: default_lockout_secs(),
            totp_issuer: default_issuer(),
        }
    }
}

fn default_max_attempts() -> u32 {
    5
}
fn default_lockout_secs() -> u64 {
    300
}
fn default_issuer() -> String {
    "Wireforge".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WireGuardConfig {
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
        }
    }
}

fn default_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_locale")]
    pub locale_default: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            locale_default: default_locale(),
        }
    }
}

fn default_locale() -> String {
    "en".into()
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut fig = Figment::new();
        if path.exists() {
            fig = fig.merge(Toml::file(path));
        }
        fig = fig.merge(Env::prefixed("WIREFORGE_").split("__"));
        let cfg: AppConfig = fig.extract()?;
        Ok(cfg)
    }
}
