//! SQLite persistence adapters implementing the `wireforge-core` ports.

use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use wireforge_core::CoreError;

pub mod audit;
pub mod bans;
pub mod interfaces;
pub mod peers;
pub mod settings;
pub mod traffic;
pub mod users;
pub mod webhooks;

pub use audit::SqliteAuditRepository;
pub use bans::SqliteBanRepository;
pub use interfaces::SqliteInterfaceRepository;
pub use peers::SqlitePeerRepository;
pub use settings::SqliteSettingsRepository;
pub use traffic::SqliteTrafficRepository;
pub use users::SqliteUserRepository;
pub use webhooks::SqliteWebhookRepository;

/// Open (or create) the SQLite database at `path` with sensible defaults
/// for an embedded VPN management workload: WAL journal, NORMAL synchronous,
/// foreign keys ON, connection pool sized for a typical small-team server.
pub async fn open_pool(path: impl AsRef<Path>) -> Result<SqlitePool, CoreError> {
    let path_str = path.as_ref().to_string_lossy().to_string();
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path_str}?mode=rwc"))
        .map_err(|e| CoreError::Persistence(format!("sqlite opts: {e}")))?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));

    SqlitePoolOptions::new()
        .max_connections(16)
        .connect_with(opts)
        .await
        .map_err(|e| CoreError::Persistence(format!("sqlite connect: {e}")))
}

/// Run embedded migrations from the workspace `migrations/` directory.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), CoreError> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|e| CoreError::Persistence(format!("migrate: {e}")))
}

pub(crate) fn map_err(e: sqlx::Error) -> CoreError {
    match e {
        sqlx::Error::RowNotFound => CoreError::NotFound("row not found".into()),
        other => CoreError::Persistence(other.to_string()),
    }
}
