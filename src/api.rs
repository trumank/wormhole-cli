//! Wormhole API client

use anyhow::{Context, Result};
use reqwest::Client;

use crate::crypto::{decrypt_metadata, derive_meta_key};
use crate::models::{
    B2AuthResponse, B2UploadToken, CreateRoomRequest, RoomCreateResponse, RoomResponse,
    SaltResponse, UpdateRoomRequest, base64_encode,
};

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

    // ========== Upload Methods ==========

    /// Create a new room for file upload
    pub async fn create_room(
        &self,
        reader_token_b64: &str,
        salt_b64: &str,
    ) -> Result<RoomCreateResponse> {
        let url = format!("{}/room", API_BASE);

        let request = CreateRoomRequest {
            reader_token: reader_token_b64.to_string(),
            salt: salt_b64.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Wormhole-CLI/1.0")
            .json(&request)
            .send()
            .await
            .context("failed to create room")?
            .error_for_status()
            .context("room creation failed")?;

        response
            .json()
            .await
            .context("failed to parse room creation response")
    }

    /// Mark uploader as online
    pub async fn mark_uploader_online(&self, room_id: &str, auth_token: &[u8]) -> Result<()> {
        let url = format!("{}/room/{}/uploader-online", API_BASE, room_id);
        let auth_header = format!("Bearer sync-v1 {}", base64_encode(auth_token));

        self.client
            .patch(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Wormhole-CLI/1.0")
            .send()
            .await
            .context("failed to mark uploader online")?
            .error_for_status()
            .context("mark uploader online failed")?;

        Ok(())
    }

    /// Update room with torrent metadata
    pub async fn update_room_metadata(
        &self,
        room_id: &str,
        auth_token: &[u8],
        update_request: UpdateRoomRequest,
    ) -> Result<RoomResponse> {
        let url = format!("{}/room/{}", API_BASE, room_id);
        let auth_header = format!("Bearer sync-v1 {}", base64_encode(auth_token));

        let response = self
            .client
            .patch(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Origin", "https://wormhole.app")
            .header("Referer", "https://wormhole.app/")
            .header("User-Agent", "Wormhole-CLI/1.0")
            .json(&update_request)
            .send()
            .await
            .context("failed to update room metadata")?
            .error_for_status()
            .context("room metadata update failed")?;

        response
            .json()
            .await
            .context("failed to parse room update response")
    }

    /// Get B2 upload authorization tokens
    pub async fn get_b2_upload_auth(
        &self,
        room_id: &str,
        auth_token: &[u8],
        num_tokens: usize,
    ) -> Result<Vec<B2UploadToken>> {
        let url = format!("{}/room/{}/b2/auth-upload", API_BASE, room_id);
        let auth_header = format!("Bearer sync-v1 {}", base64_encode(auth_token));

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Wormhole-CLI/1.0")
            .json(&serde_json::json!({ "numTokens": num_tokens }))
            .send()
            .await
            .context("failed to get B2 upload auth")?
            .error_for_status()
            .context("B2 upload auth request failed")?;

        response
            .json()
            .await
            .context("failed to parse B2 upload auth response")
    }

    /// Upload encrypted data to B2
    pub async fn upload_to_b2<F>(
        &self,
        upload_token: &B2UploadToken,
        room_id: &str,
        chunk_index: usize,
        data: Vec<u8>,
        on_progress: Option<F>,
    ) -> Result<()>
    where
        F: Fn(usize) + Send + 'static,
    {
        use futures::stream::{self, StreamExt};
        use sha1::{Digest, Sha1};

        let data_len = data.len();

        // Calculate SHA1 of data
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let content_sha1 = format!("{:x}", hasher.finalize());

        // Create the request body with progress reporting
        let body = if let Some(callback) = on_progress {
            const STREAM_CHUNK_SIZE: usize = 8 * 1024;

            // Create a stream that breaks data into chunks and reports progress
            let stream = stream::iter(
                data.chunks(STREAM_CHUNK_SIZE)
                    .map(|chunk| chunk.to_vec())
                    .collect::<Vec<_>>(),
            )
            .map(move |chunk| {
                callback(chunk.len());
                Ok::<_, std::io::Error>(chunk)
            });

            reqwest::Body::wrap_stream(stream)
        } else {
            // No progress reporting, just use the data as-is
            reqwest::Body::from(data)
        };

        let response = self
            .client
            .post(&upload_token.upload_url)
            .header("Authorization", &upload_token.authorization_token)
            .header("X-Bz-File-Name", format!("{}/{}", room_id, chunk_index))
            .header("X-Bz-Content-Sha1", content_sha1)
            .header("Content-Length", data_len)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "Wormhole-CLI/1.0")
            .body(body)
            .send()
            .await
            .context("failed to upload to B2")?
            .error_for_status()
            .context("B2 upload failed")?;

        // Consume response
        let _ = response.bytes().await?;

        Ok(())
    }

    /// Finalize upload
    pub async fn finish_upload(&self, room_id: &str, auth_token: &[u8]) -> Result<()> {
        let url = format!("{}/room/{}/b2/finish-upload", API_BASE, room_id);
        let auth_header = format!("Bearer sync-v1 {}", base64_encode(auth_token));

        self.client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Wormhole-CLI/1.0")
            .json(&serde_json::json!({ "success": true }))
            .send()
            .await
            .context("failed to finish upload")?
            .error_for_status()
            .context("finish upload failed")?;

        Ok(())
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
