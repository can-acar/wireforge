//! WireGuard keypair generation (Curve25519). Pure-Rust, no shell-out.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::domain::{PresharedKey, WgPrivateKey, WgPublicKey};
use crate::CoreError;

/// Generate a Curve25519 keypair for WireGuard.
///
/// Note: We rely on `defguard_wireguard_rs` for the actual cryptographic
/// derivation in production; this helper exists so the core crate can stay
/// framework-agnostic for tests. The real adapter overrides this with the
/// kernel-blessed key derivation when available.
pub fn generate_keypair() -> Result<(WgPrivateKey, WgPublicKey), CoreError> {
    // Generate 32 random bytes via OsRng (CSPRNG, getrandom under the hood).
    let mut priv_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut priv_bytes);

    // Clamp per RFC 7748 §5.
    priv_bytes[0] &= 248;
    priv_bytes[31] &= 127;
    priv_bytes[31] |= 64;

    let priv_b64 = STANDARD.encode(priv_bytes);
    let private_key = WgPrivateKey::from_base64(priv_b64)?;

    // Defer the public-key derivation to the adapter (kernel `wg` or
    // `defguard_wireguard_rs`) so we don't ship an x25519 implementation
    // here. The adapter calls `derive_public_key`.
    let public_key = derive_public_key(&private_key)?;
    Ok((private_key, public_key))
}

/// Derive the WireGuard public key from a private key.
///
/// In Faz 1 this will delegate to `defguard_wireguard_rs::Key` which uses the
/// x25519-dalek implementation. For now this is a stub returning an error so
/// the core crate compiles without a curve25519 dependency.
pub fn derive_public_key(_private: &WgPrivateKey) -> Result<WgPublicKey, CoreError> {
    Err(CoreError::Crypto(
        "derive_public_key is provided by the WireGuard adapter".into(),
    ))
}

pub fn generate_preshared_key() -> Result<PresharedKey, CoreError> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    PresharedKey::from_base64(STANDARD.encode(bytes))
}
