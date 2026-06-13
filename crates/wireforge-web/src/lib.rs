//! Wireforge web layer: Axum routes, Askama templates, HTMX-friendly handlers.

pub mod app_state;
pub mod audit;
pub mod error;
pub mod extractors;
pub mod flash;
pub mod i18n;
pub mod middleware;
pub mod routes;
pub mod templates;
pub mod webhook_dispatcher;

pub use app_state::AppState;
pub use error::WebError;
pub use routes::{build_session_layer, router};
