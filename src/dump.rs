use aes::Aes128;
use anyhow::{Ok, Result};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyInit};
use serde::{Deserialize, Serialize};

use crate::DumpError;

pub struct Song {
    pub key: Vec<u8>,
    pub meta: Meta,
    pub img: Vec<u8>,
    pub data: Vec<u8>,
}

impl Song {
    pub fn new(buf: &[u8]) -> Result<Song> {
        // check validation
        let (magic, buf) = buf.split_at(8);
        if magic != MAGIC {
            return Err(DumpError::InvalidFile.into());
        }

        // skip 2 bytes
        let (_, buf) = buf.split_at(2);

        let (key, buf) = get_key(buf)?;
        let (meta, buf) = get_meta(buf)?;

        // skip 9 bytes
        let (_, buf) = buf.split_at(9);

        let (img, data) = split(buf)?;
        let img = img.to_vec();

        //get data
        let key_box = build_key_box(&key);
        let data = data
            .chunks(0x8000)
            .flat_map(|i| {
                i.iter().enumerate().map(|(index, item)| {
                    let j = (index + 1) & 0xFF;
                    item ^ key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xFF]) & 0xFF] as u8
                })
            })
            .collect::<Vec<u8>>();

        Ok(Song {
            key,
            meta,
            img,
            data,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Meta {
    /// The name of music
    #[serde(rename = "musicName")]
    pub name: String,
    /// The id of music
    #[serde(rename = "musicId")]
    pub id: u64,
    /// The album of music, it's a url
    pub album: String,
    /// The artist of music, first item is name, second item is id
    pub artist: Vec<(String, u64)>,
    // The bit rate of music
    pub bitrate: u64,
    /// The duration of music
    pub duration: u64,
    /// The format of music, is may be 'mp3' or 'flac'
    pub format: String,
    /// The id of MV
    #[serde(rename = "mvId")]
    pub mv: Option<u64>,
    /// The alias of music
    pub alias: Option<Vec<String>>,
}

const MAGIC: [u8; 8] = [0x43, 0x54, 0x45, 0x4E, 0x46, 0x44, 0x41, 0x4D];

pub const CORE_KEY: [u8; 16] = [
    0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57,
];

pub const META_KEY: [u8; 16] = [
    0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28,
];

fn get_key(buf: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    let (key, buf) = split(buf)?;
    // decrypt
    let key = key.iter().map(|b| b ^ 0x64).collect::<Vec<u8>>();
    let key = decrypt(&key, &CORE_KEY)?;
    let key = key[17..].to_vec();
    Ok((key, buf))
}

fn get_meta(buf: &[u8]) -> Result<(Meta, &[u8])> {
    let (meta, buf) = split(buf)?;
    // decrypt
    let meta = meta.iter().map(|b| b ^ 0x63).collect::<Vec<u8>>();
    let meta = base64::decode(&meta[22..]).map_err(|_| DumpError::InvalidFile)?;
    let meta = decrypt(&meta, &META_KEY)?;
    // deserialize
    let meta = String::from_utf8(meta[6..].to_vec())?;
    let meta = serde_json::from_str(&meta)?;
    Ok((meta, buf))
}

fn split(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, buf) = buf.split_at(4);
    let len = u32::from_ne_bytes(len.try_into()?) as usize;
    Ok(buf.split_at(len))
}

fn decrypt(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    let decryptor = Aes128::new(key.into());
    let result = decryptor.decrypt_padded_vec_mut::<Pkcs7>(data).unwrap();
    Ok(result)
}

fn build_key_box(key: &[u8]) -> Vec<usize> {
    let mut last_byte = 0;
    let mut key_box = (0..256).collect::<Vec<usize>>();
    let mut offsets = (0..key.len()).cycle();
    for i in 0..256 {
        let offset = offsets.next().unwrap();
        let c = (key_box[i] + last_byte + key[offset] as usize) & 0xFF;
        key_box.swap(i, c);
        last_byte = c;
    }
    key_box
}
