//! Wormhole CLI
//!
//! Download and upload files to wormhole.app

mod api;
mod bencode;
mod crypto;
mod decrypt;
mod encrypt;
mod models;
mod torrent;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};

use api::WormholeClient;
use bencode::parse_torrent;
use crypto::derive_auth_token;
use decrypt::MultiFileDecryptor;
use models::WormholeUrl;

/// Wormhole CLI - Download and upload files to wormhole.app
#[derive(Parser, Debug)]
#[command(name = "wormhole-cli")]
#[command(about = "Download and upload files to wormhole.app", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Download and decrypt files from a wormhole.app URL
    Download {
        /// Wormhole URL (e.g., https://wormhole.app/vbrQp4#D3r_nHhqnxiCgKE4pZTtOw)
        #[arg()]
        url: String,

        /// Output directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Replace existing files without prompting
        #[arg(short, long)]
        replace: bool,
    },
    /// Upload and encrypt files or directories to wormhole.app
    Upload {
        /// File or directory to upload
        #[arg()]
        path: PathBuf,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show file status and metadata from a wormhole.app URL
    Info {
        /// Wormhole URL (e.g., https://wormhole.app/vbrQp4#D3r_nHhqnxiCgKE4pZTtOw)
        #[arg()]
        url: String,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Download {
            url,
            output,
            verbose,
            replace,
        } => download_file(&url, &output, verbose, replace).await,
        Commands::Upload { path, verbose } => {
            upload_file(&path, verbose).await?;
            Ok(())
        }
        Commands::Info { url, verbose } => info_file(&url, verbose).await,
    }
}

async fn download_file(url: &str, output: &Path, verbose: bool, replace: bool) -> Result<()> {
    let wormhole_url = WormholeUrl::parse(url)?;

    if verbose {
        println!("Room ID: {}", wormhole_url.room_id);
        println!("Master Key: {}", hex_encode(&wormhole_url.key));
    }

    let client = WormholeClient::new(wormhole_url.room_id.clone(), wormhole_url.key.clone());

    let salt = client.get_salt().await?;

    if verbose {
        println!("Salt: {}", hex_encode(&salt));
    }

    let auth_token = derive_auth_token(&wormhole_url.key, &salt)?;

    if verbose {
        println!("Auth Token: {}", models::base64_encode(&auth_token));
    }

    let room_data = client.get_room(&auth_token).await?;

    if verbose {
        println!("Cloud State: {:?}", room_data.cloud_state);
        println!("Multi-File: {:?}", room_data.multi_file);
        println!("Remaining Downloads: {:?}", room_data.remaining_downloads);
    }

    let torrent_data = client.decrypt_torrent(&room_data.encrypted_torrent_file, &salt)?;

    if verbose {
        println!("Torrent size: {} bytes", torrent_data.len());
    }

    // Parse torrent to get number of pieces
    let torrent_info = parse_torrent(&torrent_data)?;

    if verbose {
        println!("Filename: {}", torrent_info.name);
        println!("Number of pieces: {}", torrent_info.num_pieces);
        println!("Piece length: {} bytes", torrent_info.piece_length);
        println!("Total file length: {} bytes", torrent_info.total_length);
        println!("Multi-file: {}", torrent_info.multi_file);
        if torrent_info.multi_file {
            println!("Number of files: {}", torrent_info.files.len());
        }
    }

    let b2_auth = client.get_b2_auth(&auth_token).await?;

    if verbose {
        println!("Download URL: {}", b2_auth.download_url);
    }

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output).context("failed to create output directory")?;

    // Validate all file paths, check for existing files, and create directories upfront
    let files_to_download = validate_and_prepare_paths(&torrent_info.files, output, replace)?;

    if files_to_download.is_empty() {
        println!("No files to download.");
        return Ok(());
    }

    let progress_bar = if !verbose {
        let pb = ProgressBar::new(torrent_info.total_length as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ETA: {eta}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let files_with_sizes = stream_download_multi_file(
        &client,
        &b2_auth,
        &wormhole_url.key,
        &torrent_info,
        output.to_path_buf(),
        progress_bar.as_ref(),
        verbose,
        files_to_download.clone(),
    )
    .await?;

    if let Some(ref pb) = progress_bar {
        pb.finish_with_message(format!(
            "Downloaded and decrypted {} files",
            files_to_download.len()
        ));
    }

    println!(
        "Downloaded {} files to {}:",
        files_to_download.len(),
        output.display()
    );

    // List all files that were actually downloaded with their paths and sizes
    for (index, file_info) in files_with_sizes.iter().enumerate() {
        if files_to_download.contains(&index) {
            let file_path = output.join(&file_info.path);
            let size_formatted = format_size(file_info.decrypted_length.unwrap() as u64);
            println!("  {:>12}  {}", size_formatted, file_path.display());
        }
    }

    if verbose {
        println!("\nTotal chunks: {}", torrent_info.num_pieces);
    }

    Ok(())
}

async fn info_file(url: &str, verbose: bool) -> Result<()> {
    let wormhole_url = WormholeUrl::parse(url)?;

    if verbose {
        println!("Room ID: {}", wormhole_url.room_id);
        println!("Master Key: {}", hex_encode(&wormhole_url.key));
    }

    let client = WormholeClient::new(wormhole_url.room_id.clone(), wormhole_url.key.clone());

    let salt = client.get_salt().await?;

    if verbose {
        println!("Salt: {}", hex_encode(&salt));
    }

    let auth_token = derive_auth_token(&wormhole_url.key, &salt)?;

    if verbose {
        println!("Auth Token: {}", models::base64_encode(&auth_token));
    }

    let room_data = client.get_room(&auth_token).await?;

    let torrent_data = client.decrypt_torrent(&room_data.encrypted_torrent_file, &salt)?;
    let torrent_info = parse_torrent(&torrent_data)?;

    // Display file information
    println!("URL: {}", url);
    println!("Room ID: {}", wormhole_url.room_id);
    println!("\nFile Information:");
    println!("  Name: {}", torrent_info.name);
    println!(
        "  Type: {}",
        if torrent_info.multi_file {
            "Directory"
        } else {
            "File"
        }
    );
    println!(
        "  Total Size: {} ({})",
        format_size(torrent_info.total_length as u64),
        torrent_info.total_length
    );

    if torrent_info.multi_file {
        println!("  Files: {}", torrent_info.files.len());
        println!("\n  Files in archive:");
        for file_info in &torrent_info.files {
            let size = file_info.encrypted_length;
            println!("    {:>12}  {}", format_size(size as u64), file_info.path);
        }
    }

    println!("\nTorrent Information:");
    println!("  Pieces: {}", torrent_info.num_pieces);
    println!(
        "  Piece Length: {} ({})",
        format_size(torrent_info.piece_length as u64),
        torrent_info.piece_length
    );

    println!("\nAvailability:");
    println!(
        "  Status: {}",
        match room_data.cloud_state.as_deref() {
            Some("complete") => "✓ Available",
            Some(state) => state,
            None => "Unknown",
        }
    );

    if let Some(remaining) = room_data.remaining_downloads {
        println!("  Remaining Downloads: {}", remaining);
    }

    if verbose {
        println!("\nVerbose Information:");
        println!("  Cloud State: {:?}", room_data.cloud_state);
        println!("  Multi-File: {:?}", room_data.multi_file);
        println!("  Torrent Size: {} bytes", torrent_data.len());
    }

    println!();
    Ok(())
}

/// Collect all files from a directory recursively
fn collect_files_from_directory(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    use std::fs;

    let mut files = Vec::new();

    fn walk_dir(
        base_dir: &Path,
        current_dir: &Path,
        files: &mut Vec<(PathBuf, String)>,
    ) -> Result<()> {
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                // Calculate relative path from base_dir
                let relative = path
                    .strip_prefix(base_dir)
                    .context("failed to strip prefix")?;
                let relative_str = relative
                    .to_str()
                    .context("path not valid UTF-8")?
                    .replace('\\', "/"); // Normalize to forward slashes

                files.push((path.clone(), relative_str));
            } else if path.is_dir() {
                walk_dir(base_dir, &path, files)?;
            }
        }
        Ok(())
    }

    walk_dir(dir, dir, &mut files)?;

    // Sort for consistent ordering
    files.sort_by(|a, b| a.1.cmp(&b.1));

    if files.is_empty() {
        anyhow::bail!("Directory is empty: {}", dir.display());
    }

    Ok(files)
}

/// Information needed for streaming upload without holding all encrypted data in memory
enum UploadInfo {
    SingleFile {
        path: PathBuf,
        salt: [u8; crypto::KEY_LENGTH],
        size: usize,
    },
    MultiFile {
        files: Vec<PathBuf>,
        salts: Vec<[u8; crypto::KEY_LENGTH]>,
        total_size: usize,
    },
}

async fn upload_file(file: &Path, verbose: bool) -> Result<String> {
    use rand::Rng;
    use std::fs;

    // Check path exists
    if !file.exists() {
        anyhow::bail!("Path not found: {}", file.display());
    }

    let is_directory = file.is_dir();
    let metadata = fs::metadata(file)?;

    let (name, total_size, file_list) = if is_directory {
        // Directory mode
        let files = collect_files_from_directory(file)?;
        let dir_name = file
            .file_name()
            .context("invalid directory name")?
            .to_str()
            .context("directory name not valid UTF-8")?;

        let total: u64 = files
            .iter()
            .map(|(path, _)| fs::metadata(path).map(|m| m.len()).unwrap_or(0))
            .sum();

        (dir_name.to_string(), total, Some(files))
    } else {
        // Single file mode
        let filename = file
            .file_name()
            .context("invalid filename")?
            .to_str()
            .context("filename not valid UTF-8")?;
        (filename.to_string(), metadata.len(), None)
    };

    println!(
        "\n{}: {}",
        if is_directory { "Directory" } else { "File" },
        file.display()
    );
    if let Some(ref files) = file_list {
        println!("Files: {}", files.len());
    }
    println!(
        "Size: {} bytes ({:.2} MB)",
        total_size,
        total_size as f64 / (1024.0 * 1024.0)
    );

    // Generate master key and salt
    let master_key: [u8; crypto::KEY_LENGTH] = rand::thread_rng().r#gen();
    let salt: [u8; crypto::KEY_LENGTH] = rand::thread_rng().r#gen();

    if verbose {
        println!("Master Key: {}", hex_encode(&master_key));
        println!("Salt: {}", hex_encode(&salt));
    }

    // Derive tokens
    let reader_token = crypto::derive_auth_token(&master_key, &salt)?;
    let reader_token_b64 = models::base64_encode(&reader_token);
    let salt_b64 = models::base64_encode(&salt);

    if verbose {
        println!("Reader Token: {}", reader_token_b64);
    }

    // Create room
    if verbose {
        println!("Creating room...");
    }

    // Create a temporary client just for room creation
    let temp_client = WormholeClient::new(String::new(), master_key.to_vec());
    let room_data = temp_client
        .create_room(&reader_token_b64, &salt_b64)
        .await?;

    let room_id = room_data.id.clone();
    let writer_token_b64 = room_data.writer_token.clone();

    if verbose {
        println!("Room ID: {}", room_id);
        println!("Writer Token: {}", writer_token_b64);
    }

    // Decode writer token for auth
    let writer_token = base64::decode(&writer_token_b64)?;

    // Mark uploader as online
    temp_client
        .mark_uploader_online(&room_id, &writer_token)
        .await?;

    if verbose {
        println!("Uploader status: Online");
    }

    // Two-pass approach to minimize memory usage:
    // Pass 1: Calculate hashes and metadata without storing encrypted data
    // Pass 2: Encrypt again for upload
    let (upload_info, torrent_data, info_hash, piece_length) = if let Some(files) = file_list {
        // Multi-file mode
        if verbose {
            println!("Pass 1: Calculating piece hashes...");
        }

        // First pass: calculate total size and get estimated piece length
        let mut total_encrypted_estimate = 0;
        for (file_path, _) in &files {
            let file_size = fs::metadata(file_path)?.len() as usize;
            // Estimate encrypted size (will be slightly larger due to overhead)
            total_encrypted_estimate += file_size + file_size / 10;
        }

        let piece_length = torrent::calculate_piece_length(total_encrypted_estimate);

        if verbose {
            println!(
                "Estimated encrypted size: ~{} bytes",
                total_encrypted_estimate
            );
            println!("Piece length: {} bytes", piece_length);
        }

        // Now do the actual first pass: encrypt each file, hash pieces globally, save salts
        // For multi-file torrents, pieces span across files, so we need a global piece hasher
        let mut piece_hasher = torrent::PieceHasher::new(piece_length);
        let mut file_metadata = Vec::new();
        let mut file_salts = Vec::new(); // Save salts for deterministic re-encryption

        for (file_path, relative_path) in &files {
            if verbose {
                println!("Hashing: {}", relative_path);
            }

            // Encrypt this file and feed it to the global piece hasher
            use std::fs::File;
            use std::io::{BufReader, Read};

            let file_handle = File::open(file_path)?;
            let mut reader = BufReader::new(file_handle);

            let mut encryptor = encrypt::StreamEncryptor::new(&master_key, encrypt::RECORD_SIZE)?;
            let salt = encryptor.salt(); // Save salt for later
            file_salts.push(salt);

            let mut buffer = vec![0u8; 256 * 1024];
            let mut encrypted_size = 0;

            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }

                let encrypted_chunk = encryptor.update(&buffer[..bytes_read])?;
                piece_hasher.update(&encrypted_chunk);
                encrypted_size += encrypted_chunk.len();
            }

            let final_chunk = encryptor.finalize()?;
            piece_hasher.update(&final_chunk);
            encrypted_size += final_chunk.len();

            file_metadata.push(torrent::FileMetadata {
                path: relative_path.clone(),
                encrypted_length: encrypted_size,
            });
        }

        let piece_hashes = piece_hasher.finalize();
        let total_encrypted_size: usize = file_metadata.iter().map(|f| f.encrypted_length).sum();

        if verbose {
            println!("Total encrypted size: {} bytes", total_encrypted_size);
            println!("Number of pieces: {}", piece_hashes.len());
        }

        // Create torrent from hashes
        let (torrent, hash) = torrent::create_multi_file_torrent_from_hashes(
            &name,
            &file_metadata,
            piece_length,
            piece_hashes,
        )?;

        if verbose {
            println!("Torrent size: {} bytes", torrent.len());
            println!("Info hash: {}", hash);
            println!("\nPass 2: Encrypting files for upload...");
        }

        // Store upload info for streaming encryption during upload
        let upload_info = UploadInfo::MultiFile {
            files: files.into_iter().map(|(path, _)| path).collect(),
            salts: file_salts,
            total_size: total_encrypted_size,
        };

        (upload_info, torrent, hash, piece_length)
    } else {
        // Single file mode
        if verbose {
            println!("Pass 1: Calculating piece hashes...");
        }

        // Estimate encrypted size
        let file_size = total_size as usize;
        let estimated_encrypted_size = file_size + file_size / 10;
        let piece_length = torrent::calculate_piece_length(estimated_encrypted_size);

        if verbose {
            println!("Plaintext size: {} bytes", total_size);
            println!("Piece length: {} bytes", piece_length);
        }

        // First pass: encrypt and hash (save salt for deterministic re-encryption)
        use std::fs::File;
        use std::io::{BufReader, Read};

        let file_handle = File::open(file)?;
        let mut reader = BufReader::new(file_handle);

        let mut encryptor = encrypt::StreamEncryptor::new(&master_key, encrypt::RECORD_SIZE)?;
        let file_salt = encryptor.salt(); // Save salt for pass 2

        let mut piece_hasher = torrent::PieceHasher::new(piece_length);
        let mut buffer = vec![0u8; 256 * 1024];
        let mut encrypted_size = 0;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let encrypted_chunk = encryptor.update(&buffer[..bytes_read])?;
            piece_hasher.update(&encrypted_chunk);
            encrypted_size += encrypted_chunk.len();
        }

        let final_chunk = encryptor.finalize()?;
        piece_hasher.update(&final_chunk);
        encrypted_size += final_chunk.len();

        let piece_hashes = piece_hasher.finalize();

        if verbose {
            println!("Encrypted size: {} bytes", encrypted_size);
            println!("Number of pieces: {}", piece_hashes.len());
        }

        // Create torrent from hashes
        let (torrent, hash) =
            torrent::create_torrent_from_hashes(&name, encrypted_size, piece_length, piece_hashes)?;

        if verbose {
            println!("Torrent size: {} bytes", torrent.len());
            println!("Info hash: {}", hash);
        }

        // Store upload info for streaming encryption during upload
        let upload_info = UploadInfo::SingleFile {
            path: file.to_path_buf(),
            salt: file_salt,
            size: encrypted_size,
        };

        (upload_info, torrent, hash, piece_length)
    };

    // Encrypt torrent with meta key
    let meta_key = crypto::derive_meta_key(&master_key, &salt)?;
    let encrypted_torrent = encrypt::encrypt_metadata(&torrent_data, &meta_key)?;
    let encrypted_torrent_b64 = models::base64_encode(&encrypted_torrent);

    // Get total encrypted size from upload_info
    let total_encrypted_size = match &upload_info {
        UploadInfo::SingleFile { size, .. } => *size,
        UploadInfo::MultiFile { total_size, .. } => *total_size,
    };

    // Update room with torrent info
    let size_mb = torrent::round_size_as_mb(total_encrypted_size);

    let update_request = models::UpdateRoomRequest {
        info_hash,
        encrypted_torrent_file: encrypted_torrent_b64,
        multi_file: is_directory,
        size_mb,
    };

    temp_client
        .update_room_metadata(&room_id, &writer_token, update_request)
        .await?;

    // Get B2 upload authorization

    // Calculate number of chunks needed based on piece_length
    let num_chunks = total_encrypted_size.div_ceil(piece_length);
    // Need one token per parallel upload
    let upload_tokens = temp_client
        .get_b2_upload_auth(&room_id, &writer_token, num_chunks.min(10))
        .await?;

    if verbose {
        println!("Number of chunks: {}", num_chunks);
    }

    let progress_bar = if !verbose {
        let pb = ProgressBar::new(total_encrypted_size as u64);
        pb.enable_steady_tick(std::time::Duration::from_millis(10));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ETA: {eta}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    upload_chunks_streaming(
        &temp_client,
        &upload_tokens,
        &room_id,
        upload_info,
        master_key.to_vec(),
        piece_length,
        num_chunks,
        progress_bar.as_ref(),
        verbose,
    )
    .await?;

    if let Some(ref pb) = progress_bar {
        pb.finish_with_message(format!("Uploaded {} chunks", num_chunks));
    }

    // Mark upload as finished
    temp_client.finish_upload(&room_id, &writer_token).await?;

    // Build shareable URL
    let master_key_b64url = models::base64url_encode(&master_key);
    let share_url = format!("https://wormhole.app/{}#{}", room_id, master_key_b64url);

    println!("\nShare URL: {}", share_url);

    if let Some(lifetime) = room_data.lifetime {
        println!("Expires in: {} hours", lifetime / 60 / 60);
    }
    if let Some(max_downloads) = room_data.max_downloads {
        println!("Max downloads: {}", max_downloads);
    }

    Ok(share_url)
}

/// Helper module for base64 decoding
mod base64 {
    use anyhow::{Context, Result};
    use base64::Engine;

    pub fn decode(s: &str) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .context("base64 decode failed")
    }
}

/// Create an async stream that encrypts file(s) on-the-fly
fn create_encrypted_stream(
    upload_info: UploadInfo,
    master_key: Vec<u8>,
) -> impl futures::Stream<Item = Result<Vec<u8>>> {
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, BufReader};

    async_stream::stream! {
        match upload_info {
            UploadInfo::SingleFile { path, salt, .. } => {
                let file = File::open(&path).await?;
                let mut reader = BufReader::new(file);
                let mut encryptor = encrypt::StreamEncryptor::new_with_salt(&master_key, encrypt::RECORD_SIZE, salt)?;

                let mut buffer = vec![0u8; 256 * 1024]; // 256KB read chunks

                loop {
                    let bytes_read = reader.read(&mut buffer).await?;
                    if bytes_read == 0 {
                        break;
                    }

                    let encrypted_chunk = encryptor.update(&buffer[..bytes_read])?;
                    yield Ok(encrypted_chunk);
                }

                // Finalize encryption
                let final_chunk = encryptor.finalize()?;
                yield Ok(final_chunk);
            }
            UploadInfo::MultiFile { files, salts, .. } => {
                for (file_path, salt) in files.iter().zip(salts.iter()) {
                    let file = File::open(file_path).await?;
                    let mut reader = BufReader::new(file);
                    let mut encryptor = encrypt::StreamEncryptor::new_with_salt(&master_key, encrypt::RECORD_SIZE, *salt)?;

                    let mut buffer = vec![0u8; 256 * 1024];

                    loop {
                        let bytes_read = reader.read(&mut buffer).await?;
                        if bytes_read == 0 {
                            break;
                        }

                        let encrypted_chunk = encryptor.update(&buffer[..bytes_read])?;
                        yield Ok(encrypted_chunk);
                    }

                    let final_chunk = encryptor.finalize()?;
                    yield Ok(final_chunk);
                }
            }
        }
    }
}

/// Split a byte stream into fixed-size chunks (pieces)
fn chunk_stream(
    stream: impl futures::Stream<Item = Result<Vec<u8>>>,
    piece_length: usize,
) -> impl futures::Stream<Item = Result<Vec<u8>>> {
    use futures::StreamExt;

    async_stream::stream! {
        let mut buffer = Vec::new();
        tokio::pin!(stream);

        while let Some(result) = stream.next().await {
            let chunk = result?;
            buffer.extend_from_slice(&chunk);

            // Yield complete pieces
            while buffer.len() >= piece_length {
                let piece = buffer.drain(..piece_length).collect();
                yield Ok(piece);
            }
        }

        // Yield final partial piece if any
        if !buffer.is_empty() {
            yield Ok(buffer);
        }
    }
}

/// Upload chunks with streaming encryption - encrypts on-the-fly without holding all data in memory
async fn upload_chunks_streaming(
    client: &WormholeClient,
    upload_tokens: &[models::B2UploadToken],
    room_id: &str,
    upload_info: UploadInfo,
    master_key: Vec<u8>,
    piece_length: usize,
    num_chunks: usize,
    progress_bar: Option<&ProgressBar>,
    verbose: bool,
) -> Result<()> {
    use futures::{StreamExt, TryStreamExt};
    use std::sync::Arc;

    // Clone progress bar into Arc for sharing across async tasks
    let progress_bar_arc = progress_bar.map(|pb| Arc::new(pb.clone()));

    // Create encrypted stream and split into pieces
    let encrypted_stream = create_encrypted_stream(upload_info, master_key);
    let piece_stream = chunk_stream(encrypted_stream, piece_length);

    // Upload pieces in parallel
    piece_stream
        .enumerate()
        .map(|(chunk_index, piece_result)| {
            let pb = progress_bar_arc.clone();
            async move {
                let chunk_data = piece_result?;

                if verbose {
                    println!("Uploading chunk {}/{}...", chunk_index + 1, num_chunks);
                }

                let progress_callback = pb.map(|pb| {
                    move |bytes: usize| {
                        pb.inc(bytes as u64);
                    }
                });

                client
                    .upload_to_b2(
                        &upload_tokens[chunk_index % 10],
                        room_id,
                        chunk_index,
                        chunk_data,
                        progress_callback,
                    )
                    .await
            }
        })
        .buffered(10)
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

/// Stream download and decrypt multi-file torrent
async fn stream_download_multi_file(
    client: &WormholeClient,
    b2_auth: &models::B2AuthResponse,
    master_key: &[u8],
    torrent_info: &bencode::TorrentInfo,
    base_path: PathBuf,
    progress_bar: Option<&ProgressBar>,
    verbose: bool,
    files_to_download: std::collections::HashSet<usize>,
) -> Result<Vec<bencode::FileInfo>> {
    use futures::{StreamExt, TryStreamExt, stream};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Create multi-file decryptor
    let decryptor = Arc::new(Mutex::new(MultiFileDecryptor::new(
        torrent_info.files.clone(),
        base_path,
        master_key.to_vec(),
        files_to_download,
    )));

    // Download and decrypt chunks in order
    {
        let decryptor = decryptor.clone();

        stream::iter(0..torrent_info.num_pieces)
            .map(|chunk_index| async move {
                if verbose {
                    println!("Downloading chunk {}...", chunk_index);
                }

                let progress_callback = progress_bar.cloned().map(|pb| {
                    move |bytes: usize| {
                        pb.inc(bytes as u64);
                    }
                });

                let result = client
                    .download_chunk(chunk_index, b2_auth, progress_callback)
                    .await;

                if verbose && let Ok(ref chunk) = result {
                    println!("Chunk {}: downloaded {} bytes", chunk_index, chunk.len());
                }

                result
            })
            .buffered(10)
            .try_for_each(|chunk| {
                let decryptor = decryptor.clone();

                async move {
                    let mut dec = decryptor.lock().await;
                    dec.process_chunk(&chunk)?;
                    Ok(())
                }
            })
            .await?;
    } // All Arc clones are dropped here

    // Finalize decryption and get file info with sizes
    let decryptor = Arc::try_unwrap(decryptor).ok().unwrap().into_inner();
    let files_with_sizes = decryptor.finalize()?;

    Ok(files_with_sizes)
}

/// Validate file paths and create directories upfront to prevent path traversal
/// Returns a set of file indices to download
fn validate_and_prepare_paths(
    files: &[bencode::FileInfo],
    base_path: &Path,
    replace_all: bool,
) -> Result<std::collections::HashSet<usize>> {
    use std::io::{self, Write};

    let mut files_to_download = std::collections::HashSet::new();
    let mut replace_mode = if replace_all { Some(true) } else { None };

    for (index, file_info) in files.iter().enumerate() {
        let path = std::path::Path::new(&file_info.path);

        // Check for absolute paths
        if path.is_absolute() {
            anyhow::bail!(
                "Path traversal detected: file path '{}' is absolute",
                file_info.path
            );
        }

        // Check for .. components
        for component in path.components() {
            if component == std::path::Component::ParentDir {
                anyhow::bail!(
                    "Path traversal detected: file path '{}' contains '..'",
                    file_info.path
                );
            }
        }

        let file_path = base_path.join(&file_info.path);

        // Check if file exists
        if file_path.exists() {
            let should_replace = match replace_mode {
                Some(true) => true,
                Some(false) => false,
                None => {
                    // Prompt user
                    print!(
                        "File '{}' already exists. Replace? [y/n/a] ",
                        file_info.path
                    );
                    io::stdout().flush()?;

                    let mut response = String::new();
                    io::stdin().read_line(&mut response)?;
                    let response = response.trim().to_lowercase();

                    match response.as_str() {
                        "y" | "yes" => true,
                        "n" | "no" => false,
                        "a" | "all" => {
                            replace_mode = Some(true);
                            true
                        }
                        _ => {
                            println!("Invalid response, skipping file.");
                            false
                        }
                    }
                }
            };

            if !should_replace {
                continue;
            }
        }

        // Create parent directories
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).context(format!(
                "failed to create directory for '{}'",
                file_info.path
            ))?;
        }

        files_to_download.insert(index);
    }

    Ok(files_to_download)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format file size in human-readable format
fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let size = bytes as f64;
    let exp = (size.ln() / 1024_f64.ln()).floor() as usize;
    let exp = exp.min(UNITS.len() - 1);

    let value = size / 1024_f64.powi(exp as i32);

    if exp == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.2} {}", value, UNITS[exp])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
    }

    #[tokio::test]
    async fn test_upload_download_various_sizes() {
        use rand::Rng;

        // Test file sizes from 0 bytes to 20MB
        let test_sizes = vec![
            0,                // Empty file
            1,                // 1 byte
            100,              // 100 bytes
            1024,             // 1 KB
            10 * 1024,        // 10 KB
            100 * 1024,       // 100 KB
            1024 * 1024,      // 1 MB
            5 * 1024 * 1024,  // 5 MB
            10 * 1024 * 1024, // 10 MB
            20 * 1024 * 1024, // 20 MB
        ];

        let temp_dir = std::env::temp_dir().join("wormhole_size_test");
        fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

        for size in test_sizes {
            println!(
                "\n=== Testing file size: {} bytes ({}) ===",
                size,
                format_size(size as u64)
            );

            // Generate random content (or empty for 0 bytes)
            let test_content: Vec<u8> = if size == 0 {
                Vec::new()
            } else {
                (0..size)
                    .map(|_| rand::thread_rng().r#gen::<u8>())
                    .collect()
            };

            // Create test file
            let upload_file_path = temp_dir.join(format!("test_{}_bytes.bin", size));
            fs::write(&upload_file_path, &test_content).expect("failed to write test file");

            // Upload the file
            let share_url = match upload_file(&upload_file_path, false).await {
                Ok(url) => {
                    println!("✓ Upload successful for {} bytes", size);
                    url
                }
                Err(e) => {
                    panic!("Upload failed for size {}: {:?}", size, e);
                }
            };

            // Create unique download directory for this size
            let download_dir = temp_dir.join(format!("download_{}", size));
            fs::create_dir_all(&download_dir).expect("failed to create download dir");

            // Download the file
            let download_result = download_file(&share_url, &download_dir, false, true).await;
            assert!(
                download_result.is_ok(),
                "Download failed for size {}: {:?}",
                size,
                download_result.err()
            );

            println!("✓ Download successful for {} bytes", size);

            // Verify the downloaded file matches the original
            let downloaded_file_path = download_dir.join(format!("test_{}_bytes.bin", size));
            assert!(
                downloaded_file_path.exists(),
                "Downloaded file does not exist for size {}",
                size
            );

            let downloaded_content =
                fs::read(&downloaded_file_path).expect("failed to read downloaded file");

            assert_eq!(
                downloaded_content.len(),
                test_content.len(),
                "Downloaded content size mismatch for size {}",
                size
            );

            assert_eq!(
                downloaded_content, test_content,
                "Downloaded content does not match original for size {}",
                size
            );

            println!("✓ Content verification passed for {} bytes", size);

            // Clean up this test's files
            fs::remove_file(&upload_file_path).ok();
            fs::remove_dir_all(&download_dir).ok();
        }

        println!("\n=== ALL SIZE TESTS PASSED ===\n");

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }
}
