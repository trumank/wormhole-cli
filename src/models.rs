//! Data models for Wormhole API and protocol

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Response from /api/room/{id}/salt endpoint
#[derive(Debug, Deserialize)]
pub struct SaltResponse {
    pub salt: String,
}

/// Response from /api/room/{id} endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomResponse {
    pub cloud_state: Option<String>,
    pub multi_file: Option<bool>,
    pub remaining_downloads: Option<i32>,
    pub encrypted_torrent_file: String,
}

/// Response from /api/room/{id}/b2/auth-download endpoint
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct B2AuthResponse {
    pub download_url: String,
    pub authorization_token: String,
}

/// Response from POST /api/room (room creation)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomCreateResponse {
    pub id: String,
    pub writer_token: String,
    pub expires_at_timestamp_ms: Option<i64>,
    pub max_downloads: Option<i32>,
    pub lifetime: Option<i64>,
}

/// Upload authorization token from /api/room/{id}/b2/auth-upload
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct B2UploadToken {
    pub upload_url: String,
    pub authorization_token: String,
}

/// Request payload for creating a room
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoomRequest {
    pub reader_token: String,
    pub salt: String,
}

/// Request payload for updating room metadata
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRoomRequest {
    pub info_hash: String,
    pub encrypted_torrent_file: String,
    pub multi_file: bool,
    pub size_mb: usize,
}

/// Parsed Wormhole URL components
#[derive(Debug, Clone)]
pub struct WormholeUrl {
    pub room_id: String,
    pub key: Vec<u8>,
}

impl WormholeUrl {
    /// Parse a Wormhole URL
    ///
    /// Expected format: https://wormhole.app/{roomId}#{key}
    pub fn parse(url: &str) -> Result<Self> {
        let Some((url, hash)) = url.split_once('#') else {
            anyhow::bail!("URL must contain # with encryption key");
        };

        let room_id = url
            .split('/')
            .next_back()
            .context("invalid URL format")?
            .to_string();

        let key = base64_url_decode(hash)?;

        Ok(Self { room_id, key })
    }
}

/// Decode base64url string to bytes
fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(s)
        .context("failed to decode base64url")
}

/// Encode bytes to standard base64 string
pub fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

/// Encode bytes to base64url string (URL-safe, no padding)
pub fn base64url_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let url = "https://wormhole.app/vbrQp4#D3r_nHhqnxiCgKE4pZTtOw";
        let parsed = WormholeUrl::parse(url).unwrap();
        assert_eq!(parsed.room_id, "vbrQp4");
        assert!(!parsed.key.is_empty());
    }

    #[test]
    fn test_parse_url_without_hash() {
        let url = "https://wormhole.app/vbrQp4";
        assert!(WormholeUrl::parse(url).is_err());
    }
}
