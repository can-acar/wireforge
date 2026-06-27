use std::sync::Arc;

use parking_lot::RwLock;
use wireforge_core::application::services::{
    AuthService, InterfaceService, PeerService, SettingsService,
};
use wireforge_core::crypto::SealKey;
use wireforge_core::domain::RuntimeSettings;
use wireforge_infra::{
    DefguardAdapter, GetifaddrsAdapter, IptablesNatAdapter, SqliteApiTokenRepository,
    SqliteAuditRepository, SqliteBanRepository, SqliteInterfaceRepository, SqlitePeerRepository,
    SqliteSettingsRepository, SqliteTrafficRepository, SqliteUserRepository,
};

/// Concrete service type aliases composed from our SQLite adapters + the
/// defguard WireGuard adapter. Centralised here so handlers don't carry the
/// generic noise.
pub type InterfaceSvc = InterfaceService<
    SqliteInterfaceRepository,
    SqlitePeerRepository,
    DefguardAdapter,
    IptablesNatAdapter,
    GetifaddrsAdapter,
>;
pub type PeerSvc =
    PeerService<SqlitePeerRepository, SqliteInterfaceRepository, DefguardAdapter>;
pub type AuthSvc = AuthService<SqliteUserRepository>;
pub type SettingsSvc = SettingsService<SqliteSettingsRepository>;

/// Reloads the global tracing `EnvFilter` at runtime. Implemented by the
/// binary (which owns the subscriber); `Ok(())` on success, `Err(msg)` if the
/// new directive fails to parse. A no-op closure is used in tests.
pub type LogReload = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Shared, cheap-to-clone application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<SqliteUserRepository>,
    pub interfaces: Arc<SqliteInterfaceRepository>,
    pub peers: Arc<SqlitePeerRepository>,
    pub audit: Arc<SqliteAuditRepository>,
    pub bans: Arc<SqliteBanRepository>,
    pub traffic: Arc<SqliteTrafficRepository>,
    pub settings_repo: Arc<SqliteSettingsRepository>,
    /// API bearer tokens (personal access tokens) for programmatic clients.
    pub api_tokens: Arc<SqliteApiTokenRepository>,
    pub wg: Arc<DefguardAdapter>,
    /// NAT/masquerade + on_up/on_down hook executor (iptables-backed).
    pub nat: Arc<IptablesNatAdapter>,
    /// Read-only host network interface enumerator (`lo`, `eth0`, `docker0`, …).
    pub sysnet: Arc<GetifaddrsAdapter>,
    pub seal_key: SealKey,
    pub config: Arc<WebConfig>,
    /// Live runtime settings — mutated by the settings page, read by every
    /// consumer (auth lockout, poller interval, locale, totp issuer, …).
    pub settings: Arc<RwLock<RuntimeSettings>>,
    /// Hook to re-apply the log level without a restart.
    pub log_reload: LogReload,
}

impl AppState {
    pub fn interface_service(&self) -> InterfaceSvc {
        InterfaceService::new(
            self.interfaces.clone(),
            self.peers.clone(),
            self.wg.clone(),
            self.nat.clone(),
            self.sysnet.clone(),
            self.seal_key.clone(),
        )
    }

    pub fn peer_service(&self) -> PeerSvc {
        PeerService::new(
            self.peers.clone(),
            self.interfaces.clone(),
            self.wg.clone(),
            self.seal_key.clone(),
        )
    }

    pub fn auth_service(&self) -> AuthSvc {
        AuthService::new(self.users.clone())
    }

    pub fn settings_service(&self) -> SettingsSvc {
        SettingsService::new(self.settings_repo.clone(), self.settings.clone())
    }

    /// Cheap clone of the current runtime settings snapshot.
    pub fn settings_snapshot(&self) -> RuntimeSettings {
        self.settings.read().clone()
    }
}

#[derive(Clone, Debug)]
pub struct WebConfig {
    pub server_endpoint: Option<String>,
    pub session_secure: bool,
    pub locale_default: String,
    /// Maximum failed login attempts from a single IP before lockout.
    pub login_max_attempts: u32,
    /// Lockout duration after exceeding `login_max_attempts`.
    pub login_lockout: std::time::Duration,
    /// Issuer string shown in TOTP apps (e.g. "Wireforge").
    pub totp_issuer: String,
    /// Boot-time, restart-only values surfaced read-only on the settings page.
    pub database_path: String,
    pub server_bind: String,
}
