//! Torrent file creation and bencode encoding for Wormhole uploads

use anyhow::Result;
use rand::Rng;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;

/// Streaming piece hasher for calculating torrent piece hashes without holding all data in memory
pub struct PieceHasher {
    piece_length: usize,
    buffer: Vec<u8>,
    piece_hashes: Vec<Vec<u8>>,
    current_hasher: Sha1,
}

impl PieceHasher {
    /// Create a new piece hasher
    pub fn new(piece_length: usize) -> Self {
        Self {
            piece_length,
            buffer: Vec::new(),
            piece_hashes: Vec::new(),
            current_hasher: Sha1::new(),
        }
    }

    /// Add data to the hasher
    ///
    /// Processes complete pieces and hashes them
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);

        // Process complete pieces
        while self.buffer.len() >= self.piece_length {
            let piece = self.buffer.drain(..self.piece_length).collect::<Vec<u8>>();
            self.current_hasher.update(&piece);
            let hash = self.current_hasher.finalize_reset();
            self.piece_hashes.push(hash.to_vec());
        }
    }

    /// Finalize and return all piece hashes
    ///
    /// Call this after all data has been passed to update()
    pub fn finalize(mut self) -> Vec<Vec<u8>> {
        // Hash final piece if any data remains
        if !self.buffer.is_empty() {
            self.current_hasher.update(&self.buffer);
            let hash = self.current_hasher.finalize();
            self.piece_hashes.push(hash.to_vec());
        } else if self.piece_hashes.is_empty() {
            // Handle empty file case - need at least one hash
            let hash = self.current_hasher.finalize();
            self.piece_hashes.push(hash.to_vec());
        }

        self.piece_hashes
    }
}

/// Calculate dynamic piece length based on torrent size
///
/// This matches the WebTorrent implementation:
/// - Uses a logarithmic calculation based on file size
/// - Minimum of 16 KiB, rounds up to nearest 16 KiB multiple
/// - Has a minimum threshold of 5MB (or total size if smaller)
pub fn calculate_piece_length(encrypted_torrent_length: usize) -> usize {
    // Base calculation: max(16384, 2^(log2(bytes/1024) + 0.5))
    let base_piece_length = if encrypted_torrent_length < 1024 {
        16384
    } else {
        let kb = encrypted_torrent_length as f64 / 1024.0;
        let exponent = (kb.log2() + 0.5).floor() as u32;
        let calculated = 1_usize << exponent;
        calculated.max(16384)
    };

    // Use 5MB as minimum unless the full torrent size is less than that
    let mut min_piece_length = encrypted_torrent_length.min(5_000_000);

    // Round up to nearest multiple of 16 KiB
    min_piece_length = min_piece_length.div_ceil(16384) * 16384;

    // Return the maximum of the calculated and minimum piece lengths
    base_piece_length.max(min_piece_length)
}

/// Bencode value types
#[derive(Debug, Clone)]
pub enum BencodeValue {
    Integer(i64),
    ByteString(Vec<u8>),
    List(Vec<BencodeValue>),
    Dict(BTreeMap<Vec<u8>, BencodeValue>),
}

/// Encode a BencodeValue to bytes
pub fn bencode_encode(value: &BencodeValue) -> Vec<u8> {
    match value {
        BencodeValue::Integer(n) => format!("i{}e", n).into_bytes(),
        BencodeValue::ByteString(bytes) => {
            let mut result = format!("{}:", bytes.len()).into_bytes();
            result.extend_from_slice(bytes);
            result
        }
        BencodeValue::List(items) => {
            let mut result = vec![b'l'];
            for item in items {
                result.extend_from_slice(&bencode_encode(item));
            }
            result.push(b'e');
            result
        }
        BencodeValue::Dict(dict) => {
            let mut result = vec![b'd'];
            // BTreeMap keeps keys sorted
            for (key, value) in dict {
                // Encode key as bytestring
                result.extend_from_slice(&bencode_encode(&BencodeValue::ByteString(key.clone())));
                // Encode value
                result.extend_from_slice(&bencode_encode(value));
            }
            result.push(b'e');
            result
        }
    }
}

/// File metadata for streaming torrent creation
pub struct FileMetadata {
    pub path: String,            // Relative path with "/" separators
    pub encrypted_length: usize, // Length of encrypted file
}

/// Helper module for hex encoding (simple implementation)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Calculate size in MB with at most two significant figures
/// Matches the JavaScript roundSizeAsMb function
/// Create a torrent file from pre-calculated piece hashes (single file)
///
/// This is used for streaming uploads where we don't want to keep the entire encrypted file in memory
pub fn create_torrent_from_hashes(
    filename: &str,
    encrypted_length: usize,
    piece_length: usize,
    piece_hashes: Vec<Vec<u8>>,
) -> Result<(Vec<u8>, String)> {
    // Flatten piece hashes into single bytes vector
    let mut pieces = Vec::new();
    for hash in piece_hashes {
        pieces.extend_from_slice(&hash);
    }

    // Generate a random 16-byte nonce (as hex string)
    let nonce_bytes: [u8; 16] = rand::thread_rng().r#gen();
    let nonce = hex::encode(&nonce_bytes);

    // Create torrent info dict
    let mut info = BTreeMap::new();
    info.insert(
        b"length".to_vec(),
        BencodeValue::Integer(encrypted_length as i64),
    );
    info.insert(
        b"name".to_vec(),
        BencodeValue::ByteString(filename.as_bytes().to_vec()),
    );
    info.insert(
        b"nonce".to_vec(),
        BencodeValue::ByteString(nonce.as_bytes().to_vec()),
    );
    info.insert(
        b"piece length".to_vec(),
        BencodeValue::Integer(piece_length as i64),
    );
    info.insert(b"pieces".to_vec(), BencodeValue::ByteString(pieces));
    info.insert(b"private".to_vec(), BencodeValue::Integer(1));

    // Calculate info hash
    let info_bencoded = bencode_encode(&BencodeValue::Dict(info.clone()));
    let mut hasher = Sha1::new();
    hasher.update(&info_bencoded);
    let info_hash = hex::encode(&hasher.finalize());

    // Create full torrent
    let announce_url = b"wss://wormhole.app/websocket".to_vec();
    let announce_list = vec![BencodeValue::List(vec![BencodeValue::ByteString(
        announce_url.clone(),
    )])];

    let mut torrent = BTreeMap::new();
    torrent.insert(b"announce".to_vec(), BencodeValue::ByteString(announce_url));
    torrent.insert(b"announce-list".to_vec(), BencodeValue::List(announce_list));
    torrent.insert(
        b"created by".to_vec(),
        BencodeValue::ByteString(b"WebTorrent/0108".to_vec()),
    );
    torrent.insert(
        b"creation date".to_vec(),
        BencodeValue::Integer(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        ),
    );
    torrent.insert(b"info".to_vec(), BencodeValue::Dict(info));
    torrent.insert(b"private".to_vec(), BencodeValue::Integer(1));
    torrent.insert(b"url-list".to_vec(), BencodeValue::List(vec![]));

    let torrent_bencoded = bencode_encode(&BencodeValue::Dict(torrent));

    Ok((torrent_bencoded, info_hash))
}

/// Create a multi-file torrent from pre-calculated piece hashes
///
/// This is used for streaming uploads where we don't want to keep the entire encrypted data in memory
pub fn create_multi_file_torrent_from_hashes(
    directory_name: &str,
    files: &[FileMetadata],
    piece_length: usize,
    piece_hashes: Vec<Vec<u8>>,
) -> Result<(Vec<u8>, String)> {
    // Flatten piece hashes
    let mut pieces = Vec::new();
    for hash in piece_hashes {
        pieces.extend_from_slice(&hash);
    }

    // Generate nonce
    let nonce_bytes: [u8; 16] = rand::thread_rng().r#gen();
    let nonce = hex::encode(&nonce_bytes);

    // Create file list
    let mut file_list = Vec::new();
    for file in files {
        let mut file_dict = BTreeMap::new();
        file_dict.insert(
            b"length".to_vec(),
            BencodeValue::Integer(file.encrypted_length as i64),
        );

        let path_parts: Vec<BencodeValue> = file
            .path
            .split('/')
            .map(|part| BencodeValue::ByteString(part.as_bytes().to_vec()))
            .collect();
        file_dict.insert(b"path".to_vec(), BencodeValue::List(path_parts));

        file_list.push(BencodeValue::Dict(file_dict));
    }

    // Create info dict
    let mut info = BTreeMap::new();
    info.insert(b"files".to_vec(), BencodeValue::List(file_list));
    info.insert(
        b"name".to_vec(),
        BencodeValue::ByteString(directory_name.as_bytes().to_vec()),
    );
    info.insert(
        b"nonce".to_vec(),
        BencodeValue::ByteString(nonce.as_bytes().to_vec()),
    );
    info.insert(
        b"piece length".to_vec(),
        BencodeValue::Integer(piece_length as i64),
    );
    info.insert(b"pieces".to_vec(), BencodeValue::ByteString(pieces));
    info.insert(b"private".to_vec(), BencodeValue::Integer(1));

    // Calculate info hash
    let info_bencoded = bencode_encode(&BencodeValue::Dict(info.clone()));
    let mut hasher = Sha1::new();
    hasher.update(&info_bencoded);
    let info_hash = hex::encode(&hasher.finalize());

    // Create full torrent
    let announce_url = b"wss://wormhole.app/websocket".to_vec();
    let announce_list = vec![BencodeValue::List(vec![BencodeValue::ByteString(
        announce_url.clone(),
    )])];

    let mut torrent = BTreeMap::new();
    torrent.insert(b"announce".to_vec(), BencodeValue::ByteString(announce_url));
    torrent.insert(b"announce-list".to_vec(), BencodeValue::List(announce_list));
    torrent.insert(
        b"created by".to_vec(),
        BencodeValue::ByteString(b"WebTorrent/0108".to_vec()),
    );
    torrent.insert(
        b"creation date".to_vec(),
        BencodeValue::Integer(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        ),
    );
    torrent.insert(b"info".to_vec(), BencodeValue::Dict(info));
    torrent.insert(b"private".to_vec(), BencodeValue::Integer(1));
    torrent.insert(b"url-list".to_vec(), BencodeValue::List(vec![]));

    let torrent_bencoded = bencode_encode(&BencodeValue::Dict(torrent));

    Ok((torrent_bencoded, info_hash))
}

pub fn round_size_as_mb(size: usize) -> usize {
    let raw_size_mb = size as f64 / 1_000_000.0;

    let mut scaling_factor = 1;
    let mut quantity = raw_size_mb.round() as usize;

    while quantity > 100 {
        scaling_factor *= 10;
        quantity = (raw_size_mb / scaling_factor as f64).round() as usize;
    }

    quantity * scaling_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bencode_integer() {
        let value = BencodeValue::Integer(42);
        assert_eq!(bencode_encode(&value), b"i42e");
    }

    #[test]
    fn test_bencode_bytestring() {
        let value = BencodeValue::ByteString(b"hello".to_vec());
        assert_eq!(bencode_encode(&value), b"5:hello");
    }

    #[test]
    fn test_bencode_list() {
        let value = BencodeValue::List(vec![BencodeValue::Integer(1), BencodeValue::Integer(2)]);
        assert_eq!(bencode_encode(&value), b"li1ei2ee");
    }

    #[test]
    fn test_bencode_dict() {
        let mut dict = BTreeMap::new();
        dict.insert(b"key".to_vec(), BencodeValue::Integer(42));
        let value = BencodeValue::Dict(dict);
        assert_eq!(bencode_encode(&value), b"d3:keyi42ee");
    }

    #[test]
    fn test_round_size_as_mb() {
        assert_eq!(round_size_as_mb(1), 0);
        assert_eq!(round_size_as_mb(2_600_000), 3);
        assert_eq!(round_size_as_mb(17_200_000), 17);
        assert_eq!(round_size_as_mb(121_000_000), 120);
        assert_eq!(round_size_as_mb(990_000_000), 990);
        assert_eq!(round_size_as_mb(996_000_000), 1000);
        assert_eq!(round_size_as_mb(2_430_000_000), 2400);
    }

    #[test]
    fn test_calculate_piece_length() {
        // Very small files should get minimum 16 KiB
        assert_eq!(calculate_piece_length(100), 16384);
        assert_eq!(calculate_piece_length(1000), 16384);

        // 1 MB file
        let one_mb = 1_000_000;
        let piece_len_1mb = calculate_piece_length(one_mb);
        assert!(piece_len_1mb >= 16384);
        assert_eq!(piece_len_1mb % 16384, 0); // Should be multiple of 16 KiB

        // 10 MB file should get at least 5 MB piece length rounded to 16 KiB
        let ten_mb = 10_000_000;
        let piece_len_10mb = calculate_piece_length(ten_mb);
        assert!(piece_len_10mb >= 5_000_000);
        assert_eq!(piece_len_10mb % 16384, 0);

        // 20 MB file
        let twenty_mb = 20_000_000;
        let piece_len_20mb = calculate_piece_length(twenty_mb);
        assert!(piece_len_20mb >= 5_000_000);
        assert_eq!(piece_len_20mb % 16384, 0);
    }
}
