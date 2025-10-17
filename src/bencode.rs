//! Bencode parser for torrent files
//!
//! Uses the Bendy crate to extract piece information from torrent metadata.

use anyhow::{Context, Result};
use bendy::decoding::{Error as BendyError, FromBencode, Object};

/// Information about a file in the torrent
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub encrypted_length: usize,
    #[allow(unused)]
    pub offset: usize,
    pub decrypted_length: Option<usize>,
}

/// Information extracted from torrent file
#[derive(Debug)]
pub struct TorrentInfo {
    pub name: String,
    pub piece_length: usize,
    pub num_pieces: usize,
    pub total_length: usize,
    pub multi_file: bool,
    pub files: Vec<FileInfo>,
}

/// Internal representation of torrent metadata
#[derive(Debug)]
struct Torrent {
    info: Info,
}

#[derive(Debug)]
struct Info {
    name: String,
    piece_length: i64,
    pieces: Vec<u8>,
    length: Option<i64>,
    files: Option<Vec<TorrentFileInfo>>,
}

#[derive(Debug)]
struct TorrentFileInfo {
    length: i64,
    path: Vec<Vec<u8>>,
}

impl FromBencode for Torrent {
    const EXPECTED_RECURSION_DEPTH: usize = 10;

    fn decode_bencode_object(object: Object) -> Result<Self, BendyError> {
        let mut info = None;
        let mut dict = object.try_into_dictionary()?;

        while let Some(pair) = dict.next_pair()? {
            if let (b"info", value) = pair {
                info = Some(Info::decode_bencode_object(value)?);
            }
        }

        let info = info.ok_or_else(|| BendyError::missing_field("info"))?;
        Ok(Torrent { info })
    }
}

impl FromBencode for Info {
    const EXPECTED_RECURSION_DEPTH: usize = 7;

    fn decode_bencode_object(object: Object) -> Result<Self, BendyError> {
        let mut name = None;
        let mut piece_length = None;
        let mut pieces = None;
        let mut length = None;
        let mut files = None;

        let mut dict = object.try_into_dictionary()?;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"name", value) => {
                    name = Some(String::from_utf8_lossy(value.try_into_bytes()?).into_owned());
                }
                (b"piece length", value) => {
                    piece_length = Some(i64::decode_bencode_object(value)?);
                }
                (b"pieces", value) => {
                    pieces = Some(value.try_into_bytes()?.to_vec());
                }
                (b"length", value) => {
                    length = Some(i64::decode_bencode_object(value)?);
                }
                (b"files", value) => {
                    let mut file_list = Vec::new();
                    let mut list = value.try_into_list()?;

                    while let Some(file_obj) = list.next_object()? {
                        file_list.push(TorrentFileInfo::decode_bencode_object(file_obj)?);
                    }
                    files = Some(file_list);
                }
                _ => {} // Ignore other fields like private, etc.
            }
        }

        let name = name.ok_or_else(|| BendyError::missing_field("name"))?;
        let piece_length = piece_length.ok_or_else(|| BendyError::missing_field("piece length"))?;
        let pieces = pieces.ok_or_else(|| BendyError::missing_field("pieces"))?;

        Ok(Info {
            name,
            piece_length,
            pieces,
            length,
            files,
        })
    }
}

impl FromBencode for TorrentFileInfo {
    const EXPECTED_RECURSION_DEPTH: usize = 5;

    fn decode_bencode_object(object: Object) -> Result<Self, BendyError> {
        let mut length = None;
        let mut path = None;

        let mut dict = object.try_into_dictionary()?;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"length", value) => {
                    length = Some(i64::decode_bencode_object(value)?);
                }
                (b"path", value) => {
                    let mut path_parts = Vec::new();
                    let mut list = value.try_into_list()?;
                    while let Some(part_obj) = list.next_object()? {
                        path_parts.push(part_obj.try_into_bytes()?.to_vec());
                    }
                    path = Some(path_parts);
                }
                _ => {}
            }
        }

        let length = length.ok_or_else(|| BendyError::missing_field("length"))?;
        let path = path.ok_or_else(|| BendyError::missing_field("path"))?;
        Ok(TorrentFileInfo { length, path })
    }
}

/// Parse torrent file to extract piece information
pub fn parse_torrent(torrent_data: &[u8]) -> Result<TorrentInfo> {
    let torrent =
        Torrent::from_bencode(torrent_data).context("failed to parse bencode torrent file")?;

    let info = torrent.info;

    // SHA1 hashes are 20 bytes each
    let num_pieces = info.pieces.len() / 20;

    // Build file list with offsets
    let (files, total_length, multi_file) = if let Some(torrent_files) = info.files {
        // Multi-file torrent
        let mut files = Vec::new();
        let mut offset = 0;

        for file in torrent_files {
            let encrypted_length = file.length as usize;

            // Convert path parts to a string path
            let path_parts: Vec<String> = file
                .path
                .iter()
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect();
            let path = path_parts.join("/");

            files.push(FileInfo {
                path,
                encrypted_length,
                offset,
                decrypted_length: None,
            });
            offset += encrypted_length;
        }

        (files, offset, true)
    } else if let Some(len) = info.length {
        // Single file torrent
        let files = vec![FileInfo {
            path: info.name.clone(),
            encrypted_length: len as usize,
            offset: 0,
            decrypted_length: None,
        }];
        (files, len as usize, false)
    } else {
        anyhow::bail!("torrent has neither 'length' nor 'files' field");
    };

    Ok(TorrentInfo {
        name: info.name,
        piece_length: info.piece_length as usize,
        num_pieces,
        total_length,
        multi_file,
        files,
    })
}
