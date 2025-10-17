//! Wormhole API client

use anyhow::{Context, Result};
use reqwest::Client;

use crate::crypto::{decrypt_metadata, derive_meta_key};
use crate::models::{B2AuthResponse, RoomResponse, SaltResponse, base64_encode};

const API_BASE: &str = "https://wormhole.app/api";
const B2_BUCKET_NAME: &str = "socket-dev-prod";

#[derive(Clone)]
pub struct WormholeClient {
    client: Client,
    room_id: String,
    master_key: Vec<u8>,
}

impl WormholeClient {
    pub fn new(room_id: String, master_key: Vec<u8>) -> Self {
        Self {
            client: Client::new(),
            room_id,
            master_key,
        }
    }

    pub async fn get_salt(&self) -> Result<Vec<u8>> {
        let url = format!("{}/room/{}/salt", API_BASE, self.room_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("failed to fetch salt")?
            .error_for_status()
            .context("salt request failed")?;

        let salt_response: SaltResponse = response
            .json()
            .await
            .context("failed to parse salt response")?;

        base64::decode(&salt_response.salt).context("failed to decode salt")
    }

    pub async fn get_room(&self, auth_token: &[u8]) -> Result<RoomResponse> {
        let url = format!("{}/room/{}", API_BASE, self.room_id);
        let auth_header = format!("Bearer sync-v1 {}", base64_encode(auth_token));

        let response = self
            .client
            .get(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .context("failed to fetch room data")?
            .error_for_status()
            .context("room request failed")?;

        response
            .json()
            .await
            .context("failed to parse room response")
    }

    pub async fn get_b2_auth(&self, auth_token: &[u8]) -> Result<B2AuthResponse> {
        let url = format!("{}/room/{}/b2/auth-download", API_BASE, self.room_id);
        let auth_header = format!("Bearer sync-v1 {}", base64_encode(auth_token));

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .context("failed to fetch B2 auth")?
            .error_for_status()
            .context("B2 auth request failed")?;

        response
            .json()
            .await
            .context("failed to parse B2 auth response")
    }

    pub async fn download_chunk<F>(
        &self,
        chunk_index: usize,
        b2_auth: &B2AuthResponse,
        mut on_progress: Option<F>,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(usize),
    {
        use futures::StreamExt;

        let chunk_path = format!("{}/{}", self.room_id, chunk_index);
        let url = format!(
            "{}/file/{}/{}?Authorization={}",
            b2_auth.download_url, B2_BUCKET_NAME, chunk_path, b2_auth.authorization_token
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .context("chunk download failed")?;

        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.context("failed to read chunk bytes")?;
            let chunk_len = chunk.len();
            buffer.extend_from_slice(&chunk);

            if let Some(ref mut callback) = on_progress {
                callback(chunk_len);
            }
        }

        Ok(buffer)
    }

    pub fn decrypt_torrent(&self, encrypted_torrent_b64: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let encrypted_torrent =
            base64::decode(encrypted_torrent_b64).context("failed to decode encrypted torrent")?;

        let meta_key = derive_meta_key(&self.master_key, salt)?;
        decrypt_metadata(&encrypted_torrent, &meta_key)
    }
}

/// Base64 decode module-level helper
mod base64 {
    use anyhow::{Context, Result};

    pub fn decode(s: &str) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .context("base64 decode failed")
    }
}
