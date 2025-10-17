//! Cryptographic utilities for Wormhole file encryption/decryption
//!
//! Implements HKDF key derivation and AES-GCM encryption as specified by
//! the Wormhole protocol and RFC 8188.

use aes_gcm::{
    AesGcm,
    aead::consts::U16,
    aead::{Aead, KeyInit, generic_array::GenericArray},
    aes::Aes128,
};
use anyhow::Result;
use ring::hkdf::{HKDF_SHA256, Salt};

type Aes128GcmU16 = AesGcm<Aes128, U16>;

/// Length of encryption keys in bytes
pub const KEY_LENGTH: usize = 16;

/// Length of nonces in bytes
pub const NONCE_LENGTH: usize = 12;

/// Derive authentication token using HKDF
///
/// Matches the keychain.js authToken() function
pub fn derive_auth_token(master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    derive_key(master_key, salt, b"authentication")
}

/// Derive metadata encryption key using HKDF
///
/// Matches the keychain.js metaKey function
pub fn derive_meta_key(master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    derive_key(master_key, salt, b"metadata")
}

/// Derive content encryption key for RFC 8188
pub fn derive_content_key(master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    derive_key(master_key, salt, b"Content-Encoding: aes128gcm\0")
}

/// Derive nonce base for RFC 8188
pub fn derive_nonce_base(master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    hkdf_derive(master_key, salt, b"Content-Encoding: nonce\0", NONCE_LENGTH)
}

/// Generic HKDF key derivation
fn derive_key(master_key: &[u8], salt: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    hkdf_derive(master_key, salt, info, KEY_LENGTH)
}

/// Internal HKDF derivation helper
fn hkdf_derive(master_key: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(master_key);

    let info_array = [info];
    let mut output = vec![0u8; length];
    let okm = prk
        .expand(&info_array, HkdfLength(length))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    okm.fill(&mut output)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;

    Ok(output)
}

/// Custom KeyType for variable-length HKDF output
struct HkdfLength(usize);

impl ring::hkdf::KeyType for HkdfLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// Generate nonce for a specific record sequence number
///
/// XORs the sequence number with the last 4 bytes of the nonce base
pub fn generate_nonce(nonce_base: &[u8], seq: u32) -> Result<Vec<u8>> {
    if nonce_base.len() != NONCE_LENGTH {
        anyhow::bail!("nonce base must be {} bytes", NONCE_LENGTH);
    }

    let mut nonce = nonce_base.to_vec();
    let len = nonce.len();

    // Extract existing value from last 4 bytes
    let existing = u32::from_be_bytes(nonce[len - 4..].try_into().unwrap());

    // XOR with sequence number
    let xor_value = existing ^ seq;
    let bytes = xor_value.to_be_bytes();

    nonce[len - 4..].copy_from_slice(&bytes);

    Ok(nonce)
}

/// Decrypt metadata (torrent file) using AES-GCM
///
/// Matches keychain.js decryptMeta() function
pub fn decrypt_metadata(encrypted_meta: &[u8], meta_key: &[u8]) -> Result<Vec<u8>> {
    if encrypted_meta.len() < KEY_LENGTH {
        anyhow::bail!("encrypted metadata too short");
    }

    let iv = &encrypted_meta[..KEY_LENGTH];
    let ciphertext = &encrypted_meta[KEY_LENGTH..];

    let cipher = Aes128GcmU16::new_from_slice(meta_key)
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;

    let nonce = GenericArray::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce_base = vec![0u8; NONCE_LENGTH];
        let nonce = generate_nonce(&nonce_base, 0).unwrap();
        assert_eq!(nonce.len(), NONCE_LENGTH);

        let nonce = generate_nonce(&nonce_base, 1).unwrap();
        assert_eq!(nonce.len(), NONCE_LENGTH);
    }
}
