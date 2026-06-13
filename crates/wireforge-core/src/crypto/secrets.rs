//! Symmetric encryption-at-rest using `age` (XChaCha20-Poly1305).
//!
//! Used to seal sensitive fields like WireGuard private keys and TOTP secrets
//! before persisting them. The `SealKey` is derived from the operator-supplied
//! `master_key` (or generated and persisted on first run).

use std::io::{Read, Write};

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor};

use crate::CoreError;

#[derive(Clone)]
pub struct SealKey {
    passphrase: SecretString,
}

impl SealKey {
    pub fn from_passphrase(s: impl Into<String>) -> Self {
        Self {
            passphrase: SecretString::new(s.into()),
        }
    }
}

pub fn seal(plaintext: &[u8], key: &SealKey) -> Result<Vec<u8>, CoreError> {
    let encryptor = Encryptor::with_user_passphrase(key.passphrase.clone());

    let mut encrypted = Vec::with_capacity(plaintext.len() + 256);
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CoreError::Crypto(format!("age wrap: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CoreError::Crypto(format!("age write: {e}")))?;
    writer
        .finish()
        .map_err(|e| CoreError::Crypto(format!("age finish: {e}")))?;
    Ok(encrypted)
}

pub fn unseal(ciphertext: &[u8], key: &SealKey) -> Result<Vec<u8>, CoreError> {
    let decryptor = match Decryptor::new(ciphertext)
        .map_err(|e| CoreError::Crypto(format!("age decryptor: {e}")))?
    {
        Decryptor::Passphrase(d) => d,
        Decryptor::Recipients(_) => {
            return Err(CoreError::Crypto(
                "recipient-encrypted blob unsupported".into(),
            ))
        }
    };

    let mut reader = decryptor
        .decrypt(&key.passphrase, None)
        .map_err(|e| CoreError::Crypto(format!("age decrypt: {e}")))?;

    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| CoreError::Crypto(format!("age read: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let key = SealKey::from_passphrase("test-master-key");
        let plain = b"super secret private key bytes";
        let sealed = seal(plain, &key).unwrap();
        assert_ne!(sealed.as_slice(), plain);
        let out = unseal(&sealed, &key).unwrap();
        assert_eq!(out.as_slice(), plain);
    }

    #[test]
    fn wrong_key_fails() {
        let key = SealKey::from_passphrase("right");
        let bad = SealKey::from_passphrase("wrong");
        let sealed = seal(b"data", &key).unwrap();
        assert!(unseal(&sealed, &bad).is_err());
    }
}
