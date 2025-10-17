//! Wormhole File Downloader CLI
//!
//! Downloads and decrypts files from wormhole.app URLs

mod api;
mod bencode;
mod crypto;
mod decrypt;
mod models;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};

use api::WormholeClient;
use bencode::parse_torrent;
use crypto::derive_auth_token;
use decrypt::MultiFileDecryptor;
use models::WormholeUrl;

/// Wormhole File Downloader
#[derive(Parser, Debug)]
#[command(name = "wormhole-cli")]
#[command(about = "Download and decrypt files from wormhole.app", long_about = None)]
struct Args {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    download_file(&Args::parse()).await
}

async fn download_file(args: &Args) -> Result<()> {
    let wormhole_url = WormholeUrl::parse(&args.url)?;

    if args.verbose {
        println!("Room ID: {}", wormhole_url.room_id);
        println!("Master Key: {}", hex_encode(&wormhole_url.key));
    }

    let client = WormholeClient::new(wormhole_url.room_id.clone(), wormhole_url.key.clone());

    let salt = client.get_salt().await?;

    if args.verbose {
        println!("Salt: {}", hex_encode(&salt));
    }

    let auth_token = derive_auth_token(&wormhole_url.key, &salt)?;

    if args.verbose {
        println!("Auth Token: {}", models::base64_encode(&auth_token));
    }

    let room_data = client.get_room(&auth_token).await?;

    if args.verbose {
        println!("Cloud State: {:?}", room_data.cloud_state);
        println!("Multi-File: {:?}", room_data.multi_file);
        println!("Remaining Downloads: {:?}", room_data.remaining_downloads);
    }

    let torrent_data = client.decrypt_torrent(&room_data.encrypted_torrent_file, &salt)?;

    if args.verbose {
        println!("Torrent size: {} bytes", torrent_data.len());
    }

    // Parse torrent to get number of pieces
    let torrent_info = parse_torrent(&torrent_data)?;

    if args.verbose {
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

    if args.verbose {
        println!("Download URL: {}", b2_auth.download_url);
    }

    let output = args.output.clone();

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&output).context("failed to create output directory")?;

    // Validate all file paths, check for existing files, and create directories upfront
    let files_to_download = validate_and_prepare_paths(&torrent_info.files, &output, args.replace)?;

    if files_to_download.is_empty() {
        println!("No files to download.");
        return Ok(());
    }

    let progress_bar = if !args.verbose {
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
        output.clone(),
        progress_bar.as_ref(),
        args.verbose,
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

    if args.verbose {
        println!("\nTotal chunks: {}", torrent_info.num_pieces);
    }

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

                let progress_callback = progress_bar.as_ref().map(|pb| {
                    |bytes: usize| {
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
