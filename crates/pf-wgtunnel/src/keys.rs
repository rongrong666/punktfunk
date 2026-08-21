//! WireGuard key handling: x25519 keypair generation and base64 file storage.

use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};

/// Generate a fresh x25519 keypair, returned as (private, public) base64 strings.
pub fn generate_keypair() -> (String, String) {
    let secret = X25519SecretKey::new();
    let public = secret.public_key();
    (B64.encode(secret.as_bytes()), B64.encode(public.as_bytes()))
}

/// Decode a base64 key into raw 32 bytes.
pub fn decode_key(key_b64: &str) -> io::Result<[u8; 32]> {
    let raw = B64
        .decode(key_b64.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad base64 key: {e}")))?;
    raw.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key must decode to 32 bytes, got {}", raw.len()),
        )
    })
}

/// Parse a base64 (or hex) private key.
pub fn parse_private_key(key: &str) -> io::Result<X25519SecretKey> {
    X25519SecretKey::from_str(key.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad private key: {e}")))
}

/// Parse a base64 public key.
pub fn parse_public_key(key_b64: &str) -> io::Result<X25519PublicKey> {
    let bytes = decode_key(key_b64)?;
    Ok(X25519PublicKey::from(&bytes[..]))
}

/// Load a base64 private key from a file (whitespace tolerated).
pub fn load_private_key(path: &Path) -> io::Result<X25519SecretKey> {
    let text = fs::read_to_string(path)?;
    parse_private_key(&text)
}

/// Load the keypair stored at `path` (a base64 private key), or generate and persist a
/// fresh one. One stable keypair per machine — the WG identity this device presents to
/// every host, so a host admin never has to re-add a changed public key.
/// Returns (private, public) base64.
pub fn load_or_create_keypair(path: &Path) -> io::Result<(String, String)> {
    if let Ok(secret) = load_private_key(path) {
        let public = secret.public_key();
        return Ok((B64.encode(secret.as_bytes()), B64.encode(public.as_bytes())));
    }
    let (private_b64, public_b64) = generate_keypair();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &private_b64)?;
    Ok((private_b64, public_b64))
}

/// Load a peer list file: one base64 public key per line, `#` comments allowed.
pub fn load_peers(path: &Path) -> io::Result<Vec<X25519PublicKey>> {
    let text = fs::read_to_string(path)?;
    let mut peers = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        peers.push(parse_public_key(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {}", path.display(), lineno + 1, e),
            )
        })?);
    }
    if peers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no peer keys found", path.display()),
        ));
    }
    Ok(peers)
}

/// Save a base64 key to a file with a trailing newline.
pub fn save_key(path: &Path, key_b64: &str) -> io::Result<()> {
    fs::write(path, format!("{key_b64}\n"))
}
