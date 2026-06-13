use totp_rs::{Algorithm, Secret, TOTP};

use crate::CoreError;

const DIGITS: usize = 6;
const SKEW: u8 = 1;
const STEP: u64 = 30;

pub struct TotpSecret {
    pub base32: String,
    pub uri: String,
    pub qr_png: Vec<u8>,
}

/// Generate a fresh TOTP secret and a provisioning URI + QR code PNG.
pub fn generate_totp_secret(issuer: &str, account: &str) -> Result<TotpSecret, CoreError> {
    let secret = Secret::generate_secret();
    let totp = TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP,
        secret.to_bytes().map_err(|e| CoreError::Crypto(format!("totp secret: {e}")))?,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| CoreError::Crypto(format!("totp init: {e}")))?;

    let uri = totp.get_url();
    let qr_png = totp
        .get_qr_png()
        .map_err(|e| CoreError::Crypto(format!("totp qr: {e}")))?;

    Ok(TotpSecret {
        base32: secret.to_string(),
        uri,
        qr_png,
    })
}

/// Verify a 6-digit TOTP code against a stored base32 secret.
pub fn verify_totp(base32_secret: &str, code: &str, issuer: &str, account: &str) -> bool {
    let bytes = match Secret::Encoded(base32_secret.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP,
        bytes,
        Some(issuer.to_string()),
        account.to_string(),
    ) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}
