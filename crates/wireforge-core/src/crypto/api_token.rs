//! API token generation + hashing.
//!
//! Tokens are opaque, high-entropy personal access tokens of the form
//! `wf_<base64url(32 random bytes)>`. Because the secret already carries 256
//! bits of entropy, a fast deterministic SHA-256 is used for the at-rest hash
//! (so it can be looked up via a UNIQUE index) — unlike user passwords, which
//! require a slow salted KDF (argon2). This mirrors the PAT model used by
//! GitHub and others.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Prefix identifying a Wireforge API token (helps secret scanners).
pub const API_TOKEN_PREFIX: &str = "wf_";

/// Generate a fresh API token. Returns `(plaintext, hash)`. The plaintext is
/// returned to the caller exactly once; only the hash is ever persisted.
pub fn generate_api_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let plaintext = format!("{API_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_api_token(&plaintext);
    (plaintext, hash)
}

/// Deterministic SHA-256 (hex) of a plaintext token — used for both storage
/// and constant-shape lookup.
pub fn hash_api_token(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_prefixed_and_hash_matches() {
        let (plaintext, hash) = generate_api_token();
        assert!(plaintext.starts_with(API_TOKEN_PREFIX));
        assert_eq!(hash, hash_api_token(&plaintext));
        assert_eq!(hash.len(), 64); // sha256 hex
    }

    #[test]
    fn tokens_are_unique() {
        let (a, _) = generate_api_token();
        let (b, _) = generate_api_token();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_api_token("wf_abc"), hash_api_token("wf_abc"));
        assert_ne!(hash_api_token("wf_abc"), hash_api_token("wf_abd"));
    }
}
