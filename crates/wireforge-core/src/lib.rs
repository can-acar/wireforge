//! Wireforge core: domain entities, application services and ports.
//!
//! This crate is framework-agnostic — it depends on no web/database adapter.
//! All I/O is performed through ports (traits) implemented by `wireforge-infra`.

pub mod application;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod peer_conf;

pub use error::{CoreError, CoreResult};
