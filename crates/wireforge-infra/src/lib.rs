//! Wireforge infrastructure adapters: SQLite persistence + WireGuard backend.

pub mod nat;
pub mod persistence;
pub mod sysnet;
pub mod wireguard;

pub use nat::IptablesNatAdapter;
pub use persistence::{
    open_pool, run_migrations, SqliteApiTokenRepository, SqliteAuditRepository,
    SqliteBanRepository, SqliteInterfaceRepository, SqlitePeerRepository,
    SqliteSettingsRepository, SqliteTrafficRepository, SqliteUserRepository,
    SqliteWebhookRepository,
};
pub use sysnet::GetifaddrsAdapter;
pub use wireguard::DefguardAdapter;
