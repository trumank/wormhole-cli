//! RFC 8188 AES-GCM encrypted stream decryption

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result};
use std::io::Write;

/// A writer that discards all data (like /dev/null)
struct NullWriter;

impl Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writer that can be either a file or a null sink
enum FileOrNull {
    File(std::fs::File),
    Null(NullWriter),
}

impl Write for FileOrNull {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            FileOrNull::File(f) => f.write(buf),
            FileOrNull::Null(n) => n.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            FileOrNull::File(f) => f.flush(),
            FileOrNull::Null(n) => n.flush(),
        }
    }
}

use crate::crypto::{KEY_LENGTH, derive_content_key, derive_nonce_base, generate_nonce};

/// Header length (salt + record_size + idlen)
pub const HEADER_LENGTH: usize = KEY_LENGTH + 4 + 1;

/// RFC 8188 header
#[derive(Debug)]
struct Header {
    salt: Vec<u8>,
    record_size: usize,
    #[allow(unused)]
    idlen: u8,
}

impl Header {
    /// Parse RFC 8188 header from bytes
    fn parse(header_bytes: &[u8]) -> Result<Self> {
        if header_bytes.len() < HEADER_LENGTH {
            anyhow::bail!("header must be at least {} bytes", HEADER_LENGTH);
        }

        let salt = header_bytes[..KEY_LENGTH].to_vec();

        let record_size =
            u32::from_be_bytes(header_bytes[KEY_LENGTH..KEY_LENGTH + 4].try_into().unwrap())
                as usize;

        let idlen = header_bytes[KEY_LENGTH + 4];

        if idlen != 0 {
            anyhow::bail!("implementation does not support non-zero idlen");
        }

        Ok(Self {
            salt,
            record_size,
            idlen,
        })
    }
}

/// Remove padding from decrypted record
fn unpad(data: &[u8], is_last: bool) -> Result<Vec<u8>> {
    // Find the last non-zero byte
    for i in (0..data.len()).rev() {
        if data[i] != 0 {
            let delimiter = data[i];

            if is_last {
                if delimiter != 2 {
                    anyhow::bail!("delimiter of final record is not 2, got {}", delimiter);
                }
            } else if delimiter != 1 {
                anyhow::bail!("delimiter of non-final record is not 1, got {}", delimiter);
            }

            return Ok(data[..i].to_vec());
        }
    }

    anyhow::bail!("no delimiter found")
}

/// Streaming decryptor for RFC 8188 encrypted data
///
/// Processes chunks incrementally and writes decrypted data to the output as it becomes available.
pub struct StreamingDecryptor<W: Write> {
    writer: W,
    cipher: Option<Aes128Gcm>,
    nonce_base: Option<Vec<u8>>,
    record_size: Option<usize>,
    buffer: Vec<u8>,
    seq: u32,
    finalized: bool,
    bytes_written: usize,
}

impl<W: Write> StreamingDecryptor<W> {
    /// Create a new streaming decryptor
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            cipher: None,
            nonce_base: None,
            record_size: None,
            buffer: Vec::new(),
            seq: 0,
            finalized: false,
            bytes_written: 0,
        }
    }

    /// Decrypt and write a single record
    fn decrypt_and_write_record(&mut self, encrypted_record: Vec<u8>, is_last: bool) -> Result<()> {
        // Generate nonce
        let nonce_bytes = generate_nonce(self.nonce_base.as_ref().unwrap(), self.seq)?;
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Decrypt
        let padded_record = self
            .cipher
            .as_ref()
            .unwrap()
            .decrypt(nonce, encrypted_record.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to decrypt record"))?;

        // Remove padding
        let plaintext = unpad(&padded_record, is_last)?;

        // Write to output
        self.writer.write_all(&plaintext)?;
        self.bytes_written += plaintext.len();

        Ok(())
    }

    /// Process a chunk of encrypted data
    pub fn process_chunk(&mut self, chunk: &[u8], master_key: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(chunk);

        // If we haven't parsed the header yet, try to do so
        if self.cipher.is_none() && self.buffer.len() >= HEADER_LENGTH {
            let header = Header::parse(&self.buffer[..HEADER_LENGTH])?;

            // Derive keys
            let content_key = derive_content_key(master_key, &header.salt)?;
            let nonce_base = derive_nonce_base(master_key, &header.salt)?;

            // Create cipher
            let cipher = Aes128Gcm::new_from_slice(&content_key)
                .map_err(|_| anyhow::anyhow!("invalid content key length"))?;

            self.cipher = Some(cipher);
            self.nonce_base = Some(nonce_base);
            self.record_size = Some(header.record_size);

            // Remove header from buffer
            self.buffer.drain(..HEADER_LENGTH);
        }

        if let Some(rs) = self.record_size {
            // Process complete records
            while self.buffer.len() >= rs {
                let encrypted_record = self.buffer.drain(..rs).collect();

                // Non-final records always have delimiter 1
                self.decrypt_and_write_record(encrypted_record, false)?;

                // Update state
                self.seq += 1;
            }
        }

        Ok(())
    }

    /// Finalize decryption and process any remaining data
    /// Returns the writer and the total number of bytes written
    pub fn finalize(mut self) -> Result<(W, usize)> {
        if self.finalized {
            return Ok((self.writer, self.bytes_written));
        }

        // Process the last record if there's remaining data
        if !self.buffer.is_empty() {
            let encrypted_record = std::mem::take(&mut self.buffer);
            self.decrypt_and_write_record(encrypted_record, true)?;
        }

        self.writer.flush()?;
        self.finalized = true;
        Ok((self.writer, self.bytes_written))
    }
}

/// Multi-file streaming decryptor
///
/// Routes encrypted data to multiple files based on their offsets.
/// Each file is encrypted separately with its own RFC 8188 stream.
pub struct MultiFileDecryptor {
    files: Vec<crate::bencode::FileInfo>,
    current_file_index: usize,
    current_file_decryptor: Option<StreamingDecryptor<FileOrNull>>,
    bytes_fed_to_current_file: usize,
    total_bytes_processed: usize,
    base_path: std::path::PathBuf,
    master_key: Vec<u8>,
    files_to_download: std::collections::HashSet<usize>,
}

impl MultiFileDecryptor {
    /// Create a new multi-file decryptor
    pub fn new(
        files: Vec<crate::bencode::FileInfo>,
        base_path: std::path::PathBuf,
        master_key: Vec<u8>,
        files_to_download: std::collections::HashSet<usize>,
    ) -> Self {
        Self {
            files,
            current_file_index: 0,
            current_file_decryptor: None,
            bytes_fed_to_current_file: 0,
            total_bytes_processed: 0,
            base_path,
            master_key,
            files_to_download,
        }
    }

    /// Process a chunk of encrypted data
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let mut chunk_offset = 0;

        while chunk_offset < chunk.len() {
            // If we don't have a current decryptor, create one for the next file
            if self.current_file_decryptor.is_none() {
                if self.current_file_index >= self.files.len() {
                    anyhow::bail!("received more data than expected for all files");
                }

                let file_info = &self.files[self.current_file_index];

                // Check if we should download this file
                let writer = if self.files_to_download.contains(&self.current_file_index) {
                    let file_path = self.base_path.join(&file_info.path);
                    let file = std::fs::File::create(&file_path)
                        .context(format!("failed to create file: {}", file_path.display()))?;
                    FileOrNull::File(file)
                } else {
                    FileOrNull::Null(NullWriter)
                };

                self.current_file_decryptor = Some(StreamingDecryptor::new(writer));
                self.bytes_fed_to_current_file = 0;
            }

            let file_info = &self.files[self.current_file_index];
            let bytes_remaining_in_file =
                file_info.encrypted_length - self.bytes_fed_to_current_file;
            let bytes_remaining_in_chunk = chunk.len() - chunk_offset;
            let bytes_to_feed = bytes_remaining_in_file.min(bytes_remaining_in_chunk);

            // Feed data to current file's decryptor
            let chunk_slice = &chunk[chunk_offset..chunk_offset + bytes_to_feed];
            if let Some(ref mut decryptor) = self.current_file_decryptor {
                decryptor.process_chunk(chunk_slice, &self.master_key)?;
            }

            chunk_offset += bytes_to_feed;
            self.bytes_fed_to_current_file += bytes_to_feed;
            self.total_bytes_processed += bytes_to_feed;

            // Check if we've finished the current file
            if self.bytes_fed_to_current_file >= file_info.encrypted_length {
                // Finalize the current file and store decrypted size
                if let Some(decryptor) = self.current_file_decryptor.take() {
                    let (_writer, decrypted_size) = decryptor.finalize()?;
                    self.files[self.current_file_index].decrypted_length = Some(decrypted_size);
                }

                // Move to next file
                self.current_file_index += 1;
                self.bytes_fed_to_current_file = 0;
            }
        }

        Ok(())
    }

    /// Finalize all files and return file info with decrypted sizes
    pub fn finalize(mut self) -> Result<Vec<crate::bencode::FileInfo>> {
        // Finalize the current file if there is one
        if let Some(decryptor) = self.current_file_decryptor.take() {
            let (_writer, decrypted_size) = decryptor.finalize()?;
            if self.current_file_index < self.files.len() {
                self.files[self.current_file_index].decrypted_length = Some(decrypted_size);
            }
        }

        Ok(self.files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpad_last() {
        let data = vec![1, 2, 3, 0, 0, 2];
        let result = unpad(&data, true).unwrap();
        assert_eq!(result, vec![1, 2, 3, 0, 0]);
    }

    #[test]
    fn test_unpad_non_last() {
        let data = vec![1, 2, 3, 0, 0, 1];
        let result = unpad(&data, false).unwrap();
        assert_eq!(result, vec![1, 2, 3, 0, 0]);
    }

    #[test]
    fn test_unpad_wrong_delimiter() {
        let data = vec![1, 2, 3, 0, 0, 3];
        assert!(unpad(&data, true).is_err());
    }
}
