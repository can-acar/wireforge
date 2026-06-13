//! Lightweight flash messages backed by `tower-sessions`.
//!
//! Handlers `set_flash(...)` before returning a redirect; the next page
//! reads it once via `take_flash(...)`.

use serde::{Deserialize, Serialize};
use tower_sessions::Session;

const FLASH_KEY: &str = "_flash";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FlashKind {
    Success,
    Error,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flash {
    pub kind: FlashKind,
    pub message: String,
}

impl Flash {
    pub fn success(msg: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Success,
            message: msg.into(),
        }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            kind: FlashKind::Error,
            message: msg.into(),
        }
    }
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            FlashKind::Success => "success",
            FlashKind::Error => "error",
            FlashKind::Info => "info",
        }
    }
}

pub async fn set_flash(session: &Session, flash: Flash) {
    let _ = session.insert(FLASH_KEY, flash).await;
}

pub async fn take_flash(session: &Session) -> Option<Flash> {
    let flash = session.get::<Flash>(FLASH_KEY).await.ok().flatten();
    if flash.is_some() {
        let _ = session.remove::<Flash>(FLASH_KEY).await;
    }
    flash
}
