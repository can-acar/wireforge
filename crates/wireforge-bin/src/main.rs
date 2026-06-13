//! Wireforge server binary.
//!
//! Usage: `wireforge-server --config /etc/wireforge/wireforge.toml`

mod config;
mod poller;
mod scheduler;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::RwLock;
use tower_sessions::MemoryStore;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{reload, EnvFilter};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use wireforge_api::ApiDoc;
use wireforge_core::application::services::SettingsService;
use wireforge_core::crypto::SealKey;
use wireforge_core::domain::RuntimeSettings;
use wireforge_infra::{
    open_pool, run_migrations, DefguardAdapter, GetifaddrsAdapter, IptablesNatAdapter,
    SqliteAuditRepository, SqliteBanRepository, SqliteInterfaceRepository, SqlitePeerRepository,
    SqliteSettingsRepository, SqliteTrafficRepository, SqliteUserRepository,
};
use wireforge_web::app_state::{LogReload, WebConfig};
use wireforge_web::{router, AppState};

use crate::config::AppConfig;

#[derive(Parser)]
#[command(name = "wireforge-server", version)]
struct Cli {
    /// Path to TOML config file. Falls back to env vars + defaults.
    #[arg(long, env = "WIREFORGE_CONFIG", default_value = "wireforge.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = AppConfig::load(&cli.config).context("load config")?;

    let log_reload = init_tracing(&cfg.log.level);

    info!(version = env!("CARGO_PKG_VERSION"), "starting wireforge");

    // --- Database ---
    let pool = open_pool(&cfg.database.path)
        .await
        .context("open sqlite pool")?;
    run_migrations(&pool).await.context("run migrations")?;

    // --- Session store (in-memory for Faz 0; SQLite store re-enabled in Faz 3
    // once the tower-sessions ecosystem version conflict resolves) ---
    let session_store = MemoryStore::default();

    // --- Seal key for encryption-at-rest ---
    let seal_key = SealKey::from_passphrase(cfg.security.master_key.clone());

    // --- Adapters ---
    let users = Arc::new(SqliteUserRepository::new(pool.clone()));
    let interfaces = Arc::new(SqliteInterfaceRepository::new(pool.clone()));
    let peers = Arc::new(SqlitePeerRepository::new(pool.clone()));
    let audit = Arc::new(SqliteAuditRepository::new(pool.clone()));
    let bans = Arc::new(SqliteBanRepository::new(pool.clone()));
    let traffic = Arc::new(SqliteTrafficRepository::new(pool.clone()));
    let settings_repo = Arc::new(SqliteSettingsRepository::new(pool.clone()));
    let wg = Arc::new(DefguardAdapter::new(seal_key.clone()));
    let nat = Arc::new(IptablesNatAdapter::new());
    let sysnet = Arc::new(GetifaddrsAdapter::new());

    // --- Runtime settings: TOML baseline overlaid with persisted overrides ---
    let baseline = RuntimeSettings {
        locale_default: cfg.web.locale_default.clone(),
        totp_issuer: cfg.security.totp_issuer.clone(),
        login_max_attempts: cfg.security.login_max_attempts,
        login_lockout_secs: cfg.security.login_lockout_secs,
        endpoint: cfg.wireguard.endpoint.clone(),
        log_level: cfg.log.level.clone(),
        ..RuntimeSettings::default()
    };
    let merged = SettingsService::load(&*settings_repo, baseline)
        .await
        .context("load settings")?;
    // Honour a persisted log_level override at boot.
    let _ = log_reload(&merged.log_level);
    let settings = Arc::new(RwLock::new(merged));

    let state = AppState {
        users,
        interfaces,
        peers,
        audit,
        bans,
        traffic,
        settings_repo,
        wg,
        nat,
        sysnet,
        seal_key,
        config: Arc::new(WebConfig {
            server_endpoint: cfg.wireguard.endpoint.clone(),
            session_secure: cfg.server.session_secure,
            locale_default: cfg.web.locale_default.clone(),
            login_max_attempts: cfg.security.login_max_attempts,
            login_lockout: std::time::Duration::from_secs(cfg.security.login_lockout_secs),
            totp_issuer: cfg.security.totp_issuer.clone(),
            database_path: cfg.database.path.clone(),
            server_bind: cfg.server.bind.clone(),
        }),
        settings: settings.clone(),
        log_reload,
    };

    let session_layer = wireforge_web::build_session_layer(&state, session_store);
    let app = router(state.clone())
        .nest("/api/v1", wireforge_api::router().with_state(state.clone()))
        .merge(SwaggerUi::new("/swagger-ui").url("/api/v1/openapi.json", ApiDoc::openapi()))
        .layer(session_layer);

    // Background tasks: traffic poller + schedule enforcer.
    let _poller = poller::spawn(poller::PollerHandles {
        interfaces: state.interfaces.clone(),
        peers: state.peers.clone(),
        traffic: state.traffic.clone(),
        wg: state.wg.clone(),
        settings: settings.clone(),
    });
    let _scheduler = scheduler::spawn(scheduler::SchedulerHandles {
        interfaces: state.interfaces.clone(),
        peers: state.peers.clone(),
        wg: state.wg.clone(),
    });

    let addr: SocketAddr = cfg.server.bind.parse().context("parse bind addr")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind tcp listener")?;
    info!(%addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("axum serve")?;

    Ok(())
}

/// Initialise tracing with a hot-reloadable `EnvFilter`. Returns a closure
/// the settings page calls to change the log level at runtime.
fn init_tracing(level: &str) -> LogReload {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, handle) = reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
    Arc::new(move |new_level: &str| {
        let f = EnvFilter::try_new(new_level).map_err(|e| e.to_string())?;
        handle.reload(f).map_err(|e| e.to_string())
    })
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}
