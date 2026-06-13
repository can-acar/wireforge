//! `wireforge` — Wireforge management CLI.
//!
//! Connects to the same SQLite database the server uses (or via the HTTP
//! API for remote operation). Use `wireforge --help` for the full list.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;
use sqlx::SqlitePool;
use tracing_subscriber::EnvFilter;
use wireforge_core::application::ports::{
    AuditRepository, InterfaceRepository, PeerRepository, UserRepository,
};
use wireforge_core::application::services::AuthService;
use wireforge_core::crypto::{seal, unseal, SealKey};
use wireforge_core::domain::Role;
use wireforge_infra::{
    open_pool, run_migrations, SqliteAuditRepository, SqliteInterfaceRepository,
    SqlitePeerRepository, SqliteUserRepository,
};

mod backup;

#[derive(Parser)]
#[command(name = "wireforge", version, about = "Wireforge management CLI")]
struct Cli {
    /// Config file (TOML). Defaults to `wireforge.toml` in CWD or
    /// $WIREFORGE_CONFIG.
    #[arg(long, env = "WIREFORGE_CONFIG", default_value = "wireforge.toml")]
    config: String,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the version and exit.
    Version,

    /// Write a sample config file.
    Init {
        #[arg(long, default_value = "wireforge.toml")]
        output: String,
    },

    /// Run database migrations and exit.
    Migrate,

    /// User management.
    #[command(subcommand)]
    User(UserCmd),

    /// Peer inspection.
    #[command(subcommand)]
    Peer(PeerCmd),

    /// Interface inspection.
    #[command(subcommand)]
    Interface(IfaceCmd),

    /// Audit log.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },

    /// Encrypted database backup.
    #[command(subcommand)]
    Backup(BackupCmd),
}

#[derive(Subcommand)]
enum UserCmd {
    /// List all users.
    List,
    /// Create a new user with the given role.
    Create {
        username: String,
        #[arg(long, default_value = "operator")]
        role: String,
        /// Read password from stdin (no echo).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Reset a user's password (read new password from stdin).
    ResetPassword { username: String },
    /// Disable TOTP for a user (e.g. recovery if device lost).
    DisableTotp { username: String },
}

#[derive(Subcommand)]
enum PeerCmd {
    List,
}

#[derive(Subcommand)]
enum IfaceCmd {
    List,
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Create an encrypted backup at the given path.
    Create {
        #[arg(long, default_value = "./wireforge-backup.age")]
        output: PathBuf,
    },
    /// Restore from an encrypted backup (overwrites the existing DB).
    Restore { input: PathBuf },
}

#[derive(Debug, Clone, Deserialize)]
struct CliConfig {
    database: DatabaseSection,
    security: SecuritySection,
}

#[derive(Debug, Clone, Deserialize)]
struct DatabaseSection {
    #[serde(default = "default_db_path")]
    path: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SecuritySection {
    master_key: String,
}

fn default_db_path() -> String {
    "./data/wireforge.sqlite".into()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::Version => {
            println!("wireforge {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Cmd::Init { output } => {
            let path = std::path::Path::new(&output);
            if path.exists() {
                bail!("config already exists at {}", path.display());
            }
            let sample = include_str!("../../../config/wireforge.sample.toml");
            std::fs::write(path, sample)?;
            println!("Wrote sample config to {}", path.display());
            return Ok(());
        }
        _ => {}
    }

    let cfg = load_config(&cli.config)?;
    let pool = open_pool(&cfg.database.path)
        .await
        .context("open sqlite pool")?;

    match cli.command {
        Cmd::Migrate => {
            run_migrations(&pool).await.context("migrate")?;
            println!("Migrations applied.");
        }
        Cmd::User(UserCmd::List) => {
            let repo = SqliteUserRepository::new(pool.clone());
            for u in repo.list().await? {
                println!(
                    "{:<24}  {:<10}  {}  totp={}",
                    u.username,
                    u.role.as_str(),
                    u.email.as_deref().unwrap_or(""),
                    u.totp_enabled
                );
            }
        }
        Cmd::User(UserCmd::Create {
            username,
            role,
            password_stdin,
        }) => {
            let role: Role = role.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let password = if password_stdin {
                read_password_stdin()?
            } else {
                rpassword::prompt_password("Password: ")?
            };
            if password.len() < 12 {
                bail!("password must be at least 12 characters");
            }
            let repo = Arc::new(SqliteUserRepository::new(pool.clone()));
            let svc = AuthService::new(repo);
            let user = svc.create_user(&username, &password, None, role).await?;
            println!("Created user {} (id={})", user.username, user.id);
        }
        Cmd::User(UserCmd::ResetPassword { username }) => {
            let repo = SqliteUserRepository::new(pool.clone());
            let user = repo
                .find_by_username(&username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user not found"))?;
            let password = rpassword::prompt_password("New password: ")?;
            if password.len() < 12 {
                bail!("password must be at least 12 characters");
            }
            let hash = wireforge_core::crypto::hash_password(&password)?;
            repo.update_password(user.id, &hash).await?;
            println!("Password updated for {}.", username);
        }
        Cmd::User(UserCmd::DisableTotp { username }) => {
            let repo = SqliteUserRepository::new(pool.clone());
            let user = repo
                .find_by_username(&username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user not found"))?;
            repo.update_totp(user.id, false, None).await?;
            println!("TOTP disabled for {}.", username);
        }
        Cmd::Peer(PeerCmd::List) => {
            let peers = SqlitePeerRepository::new(pool.clone()).list_all().await?;
            for p in peers {
                println!(
                    "{}  {:<24}  iface={}  enabled={}  ips={}",
                    p.id,
                    p.name,
                    p.interface_id,
                    p.enabled,
                    p.allowed_ips
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
        }
        Cmd::Interface(IfaceCmd::List) => {
            let ifaces = SqliteInterfaceRepository::new(pool.clone()).list().await?;
            for i in ifaces {
                println!(
                    "{}  {:<10}  port={}  status={}",
                    i.id,
                    i.name,
                    i.listen_port,
                    i.status.as_str()
                );
            }
        }
        Cmd::Audit { limit } => {
            let events = SqliteAuditRepository::new(pool.clone()).list(limit).await?;
            for e in events {
                println!(
                    "{}  {:<22}  actor={}  ip={}  res={}:{}",
                    e.created_at.to_rfc3339(),
                    e.action.as_str(),
                    e.actor_user_id.map(|i| i.to_string()).unwrap_or_default(),
                    e.actor_ip.as_deref().unwrap_or(""),
                    e.resource_type.as_deref().unwrap_or(""),
                    e.resource_id.as_deref().unwrap_or(""),
                );
            }
        }
        Cmd::Backup(BackupCmd::Create { output }) => {
            let key = SealKey::from_passphrase(cfg.security.master_key.clone());
            backup::create(&pool, &output, &key).await?;
            println!("Backup written to {}", output.display());
        }
        Cmd::Backup(BackupCmd::Restore { input }) => {
            let key = SealKey::from_passphrase(cfg.security.master_key.clone());
            backup::restore(&pool, &cfg.database.path, &input, &key).await?;
            println!("Backup restored from {}", input.display());
        }
        // Already handled above.
        Cmd::Version | Cmd::Init { .. } => unreachable!(),
    }

    Ok(())
}

fn load_config(path: &str) -> Result<CliConfig> {
    let p = std::path::Path::new(path);
    let mut fig = Figment::new();
    if p.exists() {
        fig = fig.merge(Toml::file(p));
    }
    fig = fig.merge(Env::prefixed("WIREFORGE_").split("__"));
    fig.extract().context("parse config")
}

fn read_password_stdin() -> Result<String> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

// Keep `seal`/`unseal` reachable so future subcommands can re-seal secrets.
#[allow(dead_code)]
fn _crypto_passthrough(b: &[u8], k: &SealKey) -> anyhow::Result<Vec<u8>> {
    let sealed = seal(b, k)?;
    Ok(unseal(&sealed, k)?)
}

// Keep pool generic across subcommands.
#[allow(dead_code)]
fn _pool_marker(_: &SqlitePool) {}
