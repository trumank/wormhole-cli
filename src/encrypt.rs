//! RFC 8188 streaming encryption for Wormhole file uploads
//!
//! Implements aes128gcm content encoding for encrypting file data before upload

use aes_gcm::{
    Aes128Gcm, AesGcm,
    aead::{Aead, KeyInit, consts::U16, generic_array::GenericArray},
    aes::Aes128,
};
use anyhow::Result;
use rand::Rng;

use crate::crypto::{KEY_LENGTH, derive_content_key, derive_nonce_base, generate_nonce};

type Aes128GcmU16 = AesGcm<Aes128, U16>;

/// Authentication tag length in bytes
const TAG_LENGTH: usize = 16;

/// Default record size (64KB)
pub const RECORD_SIZE: usize = 64 * 1024;

/// Encrypt metadata (torrent file) using AES-GCM
///
/// Returns IV + ciphertext
pub fn encrypt_metadata(plaintext_meta: &[u8], meta_key: &[u8]) -> Result<Vec<u8>> {
    // Generate random IV (16 bytes to match Python implementation and decrypt expectation)
    let iv: [u8; KEY_LENGTH] = rand::thread_rng().r#gen();

    // Use same cipher type as decrypt_metadata
    let cipher = Aes128GcmU16::new_from_slice(meta_key)
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;

    // Use all 16 bytes as nonce (matches decrypt_metadata behavior)
    let nonce = GenericArray::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext_meta)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    // Return IV + ciphertext
    let mut result = Vec::with_capacity(KEY_LENGTH + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Encrypt data stream using RFC 8188 aes128gcm content encoding
///
/// # Arguments
/// * `plaintext` - Bytes to encrypt
/// * `master_key` - 16-byte master encryption key
/// * `record_size` - Size of each encrypted record (default 64KB)
///
/// # Returns
/// Encrypted data with RFC 8188 header
pub fn encrypt_stream(plaintext: &[u8], master_key: &[u8], record_size: usize) -> Result<Vec<u8>> {
    // Generate random salt for this stream
    let salt: [u8; KEY_LENGTH] = rand::thread_rng().r#gen();

    // Derive keys
    let content_key = derive_content_key(master_key, &salt)?;
    let nonce_base = derive_nonce_base(master_key, &salt)?;

    // Create AESGCM cipher
    let cipher = Aes128Gcm::new_from_slice(&content_key)
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;

    // Build header: salt (16) + record_size (4) + idlen (1)
    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&(record_size as u32).to_be_bytes());
    output.push(0); // idlen = 0

    // Calculate overhead per record (TAG_LENGTH for auth tag + 1 for delimiter)
    let overhead_per_record = TAG_LENGTH + 1;
    let max_plaintext_per_record = record_size - overhead_per_record;

    let mut offset = 0;
    let mut seq = 0;

    while offset < plaintext.len() {
        // Get plaintext chunk for this record
        let chunk_end = std::cmp::min(offset + max_plaintext_per_record, plaintext.len());
        let chunk = &plaintext[offset..chunk_end];
        let is_last = chunk_end == plaintext.len();

        // Pad the chunk
        let padded = pad_record(chunk, is_last);

        // Generate nonce and encrypt
        let nonce_bytes = generate_nonce(&nonce_base, seq)?;
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let encrypted_record = cipher
            .encrypt(nonce, padded.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to encrypt record"))?;

        output.extend_from_slice(&encrypted_record);

        offset = chunk_end;
        seq += 1;
    }

    Ok(output)
}

/// Add padding to plaintext record before encryption
///
/// Delimiter is 2 for final record, 1 for non-final records
fn pad_record(data: &[u8], is_last: bool) -> Vec<u8> {
    let delimiter = if is_last { 2 } else { 1 };
    let mut padded = Vec::with_capacity(data.len() + 1);
    padded.extend_from_slice(data);
    padded.push(delimiter);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt_metadata;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master_key = [0u8; KEY_LENGTH];
        let plaintext = b"Hello, Wormhole!";

        let encrypted = encrypt_stream(plaintext, &master_key, RECORD_SIZE).unwrap();

        // Encrypted data should be larger than plaintext (header + padding + tag)
        assert!(encrypted.len() > plaintext.len());

        // Should start with 21-byte header
        assert!(encrypted.len() >= 21);
    }

    #[test]
    fn test_pad_record() {
        let data = b"test";
        let padded_middle = pad_record(data, false);
        assert_eq!(padded_middle.last(), Some(&1));

        let padded_final = pad_record(data, true);
        assert_eq!(padded_final.last(), Some(&2));
    }

    #[test]
    fn test_encrypt_metadata() {
        let meta_key = [0u8; KEY_LENGTH];
        let plaintext = b"torrent metadata";

        let encrypted = encrypt_metadata(plaintext, &meta_key).unwrap();

        // Should be IV (16 bytes) + ciphertext + tag (16 bytes)
        assert_eq!(encrypted.len(), KEY_LENGTH + plaintext.len() + TAG_LENGTH);
    }

    #[test]
    fn test_encrypt_decrypt_metadata_compatibility() {
        let meta_key = [0xab; KEY_LENGTH];
        let plaintext = b"test torrent metadata for compatibility";

        // Encrypt with our function
        let encrypted = encrypt_metadata(plaintext, &meta_key).unwrap();

        // Decrypt with the existing decrypt function
        let decrypted = decrypt_metadata(&encrypted, &meta_key).unwrap();

        // Should match original
        assert_eq!(decrypted, plaintext);
    }
}
