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

/// Streaming encryptor for RFC 8188 aes128gcm content encoding
///
/// Encrypts data incrementally without loading entire file into memory
pub struct StreamEncryptor {
    cipher: Aes128Gcm,
    nonce_base: Vec<u8>,
    record_size: usize,
    max_plaintext_per_record: usize,
    seq: u32,
    buffer: Vec<u8>,
    header_emitted: bool,
    finished: bool,
    salt: [u8; KEY_LENGTH],
}

impl StreamEncryptor {
    /// Create a new streaming encryptor
    ///
    /// # Arguments
    /// * `master_key` - 16-byte master encryption key
    /// * `record_size` - Size of each encrypted record (default 64KB)
    pub fn new(master_key: &[u8], record_size: usize) -> Result<Self> {
        // Generate random salt for this stream
        let salt: [u8; KEY_LENGTH] = rand::thread_rng().r#gen();
        Self::new_with_salt(master_key, record_size, salt)
    }

    /// Create a new streaming encryptor with a specific salt
    ///
    /// This is useful for deterministic encryption when you need to encrypt the same data multiple times
    pub fn new_with_salt(
        master_key: &[u8],
        record_size: usize,
        salt: [u8; KEY_LENGTH],
    ) -> Result<Self> {
        // Derive keys
        let content_key = derive_content_key(master_key, &salt)?;
        let nonce_base = derive_nonce_base(master_key, &salt)?;

        // Create AESGCM cipher
        let cipher = Aes128Gcm::new_from_slice(&content_key)
            .map_err(|_| anyhow::anyhow!("invalid key length"))?;

        // Calculate overhead per record (TAG_LENGTH for auth tag + 1 for delimiter)
        let overhead_per_record = TAG_LENGTH + 1;
        let max_plaintext_per_record = record_size - overhead_per_record;

        Ok(Self {
            cipher,
            nonce_base,
            record_size,
            max_plaintext_per_record,
            seq: 0,
            buffer: Vec::new(),
            header_emitted: false,
            finished: false,
            salt,
        })
    }

    /// Get the salt used by this encryptor
    pub fn salt(&self) -> [u8; KEY_LENGTH] {
        self.salt
    }

    /// Get the RFC 8188 header
    fn get_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(21);
        header.extend_from_slice(&self.salt);
        header.extend_from_slice(&(self.record_size as u32).to_be_bytes());
        header.push(0); // idlen = 0
        header
    }

    /// Process a chunk of plaintext data
    ///
    /// Returns encrypted records that are ready to be written
    /// May return empty vec if buffering data for next record
    pub fn update(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            anyhow::bail!("StreamEncryptor already finalized");
        }

        let mut output = Vec::new();

        // Emit header on first call
        if !self.header_emitted {
            output.extend_from_slice(&self.get_header());
            self.header_emitted = true;
        }

        // Add new data to buffer
        self.buffer.extend_from_slice(chunk);

        // Process complete records from buffer
        while self.buffer.len() >= self.max_plaintext_per_record {
            let plaintext_chunk = self
                .buffer
                .drain(..self.max_plaintext_per_record)
                .collect::<Vec<u8>>();
            let encrypted_record = self.encrypt_record(&plaintext_chunk, false)?;
            output.extend_from_slice(&encrypted_record);
        }

        Ok(output)
    }

    /// Finalize the stream and encrypt any remaining buffered data
    ///
    /// Must be called after all data has been passed to update()
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        if self.finished {
            anyhow::bail!("StreamEncryptor already finalized");
        }

        let mut output = Vec::new();

        // Emit header if not yet emitted (edge case: no data was ever passed to update)
        if !self.header_emitted {
            output.extend_from_slice(&self.get_header());
            self.header_emitted = true;
        }

        // Encrypt final record with remaining buffer data
        if !self.buffer.is_empty() || self.seq == 0 {
            // Always emit at least one record, even if empty
            let plaintext_chunk = self.buffer.drain(..).collect::<Vec<u8>>();
            let encrypted_record = self.encrypt_record(&plaintext_chunk, true)?;
            output.extend_from_slice(&encrypted_record);
        }

        self.finished = true;
        Ok(output)
    }

    /// Encrypt a single record
    fn encrypt_record(&mut self, plaintext: &[u8], is_last: bool) -> Result<Vec<u8>> {
        // Pad the plaintext
        let padded = pad_record(plaintext, is_last);

        // Generate nonce and encrypt
        let nonce_bytes = generate_nonce(&self.nonce_base, self.seq)?;
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let encrypted_record = self
            .cipher
            .encrypt(nonce, padded.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to encrypt record"))?;

        self.seq += 1;
        Ok(encrypted_record)
    }
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

    /// Encrypt data stream using RFC 8188 aes128gcm content encoding
    ///
    /// # Arguments
    /// * `plaintext` - Bytes to encrypt
    /// * `master_key` - 16-byte master encryption key
    /// * `record_size` - Size of each encrypted record (default 64KB)
    ///
    /// # Returns
    /// Encrypted data with RFC 8188 header
    pub fn encrypt_stream(
        plaintext: &[u8],
        master_key: &[u8],
        record_size: usize,
    ) -> Result<Vec<u8>> {
        // Use the streaming encryptor for compatibility
        let mut encryptor = StreamEncryptor::new(master_key, record_size)?;
        let mut output = encryptor.update(plaintext)?;
        output.extend_from_slice(&encryptor.finalize()?);
        Ok(output)
    }

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
