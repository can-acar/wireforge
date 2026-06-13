use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::Value as Json;

use crate::application::ports::SettingsRepository;
use crate::domain::user::UserMarker;
use crate::domain::{Id, RuntimeSettings};
use crate::CoreResult;

/// Owns the live `RuntimeSettings` view and the persistence backend.
/// All writes go through `set()` so the in-memory copy and the DB stay
/// consistent.
pub struct SettingsService<R: SettingsRepository> {
    repo: Arc<R>,
    state: Arc<RwLock<RuntimeSettings>>,
}

impl<R: SettingsRepository> SettingsService<R> {
    pub fn new(repo: Arc<R>, state: Arc<RwLock<RuntimeSettings>>) -> Self {
        Self { repo, state }
    }

    /// Hydrate the supplied `RuntimeSettings` baseline (typically the TOML
    /// defaults) with any persisted overrides. Returns the merged snapshot.
    pub async fn load(
        repo: &R,
        mut baseline: RuntimeSettings,
    ) -> CoreResult<RuntimeSettings> {
        let overrides = repo.all().await?;
        baseline.apply_overrides(&overrides);
        Ok(baseline)
    }

    pub fn snapshot(&self) -> RuntimeSettings {
        self.state.read().clone()
    }

    /// Persist a single key + refresh the in-memory copy. `value` is the
    /// JSON-encoded scalar (so a string becomes `"hello"`, a number `3`).
    pub async fn set(
        &self,
        key: &str,
        value: Json,
        actor: Option<Id<UserMarker>>,
    ) -> CoreResult<()> {
        let raw = value.to_string();
        self.repo.upsert(key, &raw, actor).await?;
        // Re-apply just this key on top of the existing state.
        let mut overrides = HashMap::new();
        overrides.insert(key.to_string(), raw);
        let mut guard = self.state.write();
        guard.apply_overrides(&overrides);
        Ok(())
    }

    /// Apply many changes atomically (best-effort: each write is its own
    /// SQL statement; a failure mid-way leaves earlier writes in place).
    pub async fn set_many(
        &self,
        values: Vec<(&str, Json)>,
        actor: Option<Id<UserMarker>>,
    ) -> CoreResult<()> {
        let mut overrides = HashMap::new();
        for (k, v) in values {
            let raw = v.to_string();
            self.repo.upsert(k, &raw, actor).await?;
            overrides.insert(k.to_string(), raw);
        }
        let mut guard = self.state.write();
        guard.apply_overrides(&overrides);
        Ok(())
    }
}
