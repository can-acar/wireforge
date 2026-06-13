//! Encrypted SQLite backups using `VACUUM INTO` for atomicity + `age` for
//! confidentiality. The backup is portable across hosts that share the same
//! master key.

use std::path::Path;

use anyhow::{bail, Context, Result};
use sqlx::SqlitePool;
use wireforge_core::crypto::{seal, unseal, SealKey};

/// Atomically snapshot the database to `output_path` as an age-encrypted
/// blob. Uses `VACUUM INTO` which is safe to run while the server is running
/// (it acquires a read transaction).
pub async fn create(pool: &SqlitePool, output_path: &Path, key: &SealKey) -> Result<()> {
    let tmp = tempfile::NamedTempFile::new().context("temp file")?;
    let tmp_path = tmp.path().to_path_buf();
    drop(tmp); // we just want a unique path

    let _ = std::fs::remove_file(&tmp_path); // VACUUM INTO requires no existing file
    let target = tmp_path.to_string_lossy().replace('\'', "''");

    sqlx::query(&format!("VACUUM INTO '{target}'"))
        .execute(pool)
        .await
        .context("vacuum into")?;

    let bytes = std::fs::read(&tmp_path).context("read vacuum output")?;
    let _ = std::fs::remove_file(&tmp_path);

    let sealed = seal(&bytes, key).context("seal backup")?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::write(output_path, sealed).context("write backup")?;
    Ok(())
}

/// Restore an age-encrypted backup over the live database. Closes the pool's
/// connections via a `PRAGMA journal_mode = DELETE; VACUUM;` to free WAL
/// files, then atomically replaces the file. The server must be restarted
/// after restore.
pub async fn restore(
    pool: &SqlitePool,
    live_path: &str,
    input_path: &Path,
    key: &SealKey,
) -> Result<()> {
    let sealed = std::fs::read(input_path).context("read backup")?;
    let plain = unseal(&sealed, key).context("unseal backup (wrong master key?)")?;

    // Quick sanity check — SQLite files start with the magic string
    // "SQLite format 3\0".
    if plain.len() < 16 || &plain[..15] != b"SQLite format 3" {
        bail!("backup does not look like a SQLite file");
    }

    // Close the live pool's connections gracefully by issuing a checkpoint
    // first; this also reduces residual WAL/SHM.
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await;

    let live = Path::new(live_path);
    // Write to a sibling tmp file, then rename for atomicity.
    let tmp = live.with_extension("restore.tmp");
    std::fs::write(&tmp, &plain).context("write restored db")?;
    std::fs::rename(&tmp, live).context("rename restored db")?;

    // Remove any leftover WAL/SHM that referenced the old DB.
    let _ = std::fs::remove_file(format!("{live_path}-wal"));
    let _ = std::fs::remove_file(format!("{live_path}-shm"));
    Ok(())
}
