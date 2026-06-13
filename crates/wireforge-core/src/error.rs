use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    Conflict(String),

    #[error("invalid input: {0}")]
    Validation(String),

    #[error("permission denied: {0}")]
    Forbidden(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("two-factor required")]
    TwoFactorRequired,

    #[error("two-factor invalid")]
    TwoFactorInvalid,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("ip pool exhausted for {0}")]
    IpPoolExhausted(String),

    #[error("wireguard error: {0}")]
    WireGuard(String),

    #[error("persistence error: {0}")]
    Persistence(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl CoreError {
    /// Convenience helper to wrap any error type into `CoreError::Internal`.
    pub fn internal(e: impl std::fmt::Display) -> Self {
        CoreError::Internal(e.to_string())
    }
}
