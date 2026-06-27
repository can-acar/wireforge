use std::str::FromStr;

use axum::http::StatusCode;
use axum::Json;
use ipnet::IpNet;
use uuid::Uuid;
use wireforge_core::domain::Id;

use dto::{bad_request, not_found, ApiError};

pub mod dto;
pub mod health;
pub mod interfaces;
pub mod peers;
pub mod tokens;

/// Parse a path UUID into a typed `Id<M>`, mapping a bad value to 404.
pub fn parse_id<M>(s: &str) -> Result<Id<M>, (StatusCode, Json<ApiError>)> {
    Uuid::parse_str(s)
        .map(Id::<M>::from_uuid)
        .map_err(|_| not_found())
}

/// Parse an optional CIDR string. Empty/`None` → `None`; bad value → 400.
pub fn parse_cidr_opt(
    s: Option<String>,
    label: &str,
) -> Result<Option<IpNet>, (StatusCode, Json<ApiError>)> {
    match s.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) => IpNet::from_str(v)
            .map(Some)
            .map_err(|_| bad_request(format!("invalid {label}"))),
    }
}

/// Parse a list of CIDR strings; bad value → 400.
pub fn parse_cidrs(
    items: Vec<String>,
    label: &str,
) -> Result<Vec<IpNet>, (StatusCode, Json<ApiError>)> {
    items
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| IpNet::from_str(s).map_err(|_| bad_request(format!("invalid {label}"))))
        .collect()
}

/// Trim a value and collapse the empty string to `None`.
pub fn blank_to_none(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}
