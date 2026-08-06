use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn public_id() -> String {
    nanoid::nanoid!(8, &nanoid::alphabet::SAFE)
}

pub fn secret_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_lower(&digest)
}

pub fn sha256_hex_bytes(bytes: &Bytes) -> String {
    sha256_hex(bytes.as_ref())
}

pub fn canonical_blob_hash(hash: &str) -> anyhow::Result<String> {
    if hash.len() != 64 || !hash.chars().all(|character| character.is_ascii_hexdigit()) {
        anyhow::bail!("blob hash must be exactly 64 hexadecimal characters");
    }
    Ok(hash.to_ascii_lowercase())
}

pub fn hash_token(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Hashes a password on the blocking pool.
///
/// Argon2 is deliberately CPU- and memory-hard; a single call is measured in tens of milliseconds.
/// Running it inline would let a burst of sign-ins stall every other request sharing that worker.
pub async fn hash_password(password: &str) -> anyhow::Result<String> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || hash_password_blocking(&password)).await?
}

/// Verifies a password on the blocking pool. Verification costs the same as hashing.
pub async fn verify_password(password: &str, encoded: &str) -> bool {
    let password = password.to_string();
    let encoded = encoded.to_string();
    match tokio::task::spawn_blocking(move || verify_password_blocking(&password, &encoded)).await {
        Ok(verified) => verified,
        Err(err) => {
            // Only reachable if the hashing task panicked. Fail closed.
            tracing::error!(error = %err, "password verification task failed");
            false
        }
    }
}

/// Deliberately private: reaching argon2 from async code must go through the pool above.
fn hash_password_blocking(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("failed to hash password: {err}"))?
        .to_string())
}

fn verify_password_blocking(password: &str, encoded: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

pub fn normalize_extension(filename: Option<&str>, content_type: Option<&str>) -> Option<String> {
    if let Some(filename) = filename
        && let Some(ext) = std::path::Path::new(filename).extension()
    {
        let ext = ext.to_string_lossy().to_lowercase();
        if ext.chars().all(|c| c.is_ascii_alphanumeric()) && ext.len() <= 12 {
            return Some(ext);
        }
    }

    content_type
        .and_then(|mime| mime.parse::<mime::Mime>().ok())
        .and_then(|mime| mime_guess::get_mime_extensions(&mime).and_then(|exts| exts.first()))
        .map(|ext| ext.to_string())
}

pub fn slug_with_extension(public_id: &str, extension: Option<&str>) -> String {
    match extension {
        Some(ext) if !ext.is_empty() => format!("{public_id}.{ext}"),
        _ => public_id.to_string(),
    }
}

pub fn split_slug(slug: &str) -> Option<(&str, Option<&str>)> {
    if slug.is_empty()
        || slug.starts_with('.')
        || slug.contains('/')
        || !slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return None;
    }
    let mut parts = slug.splitn(2, '.');
    let id = parts.next()?;
    Some((id, parts.next()))
}

pub fn human_bytes(bytes: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn image_dimensions(bytes: &[u8]) -> Option<(i64, i64)> {
    png_dimensions(bytes)
        .or_else(|| gif_dimensions(bytes))
        .or_else(|| jpeg_dimensions(bytes))
}

fn png_dimensions(bytes: &[u8]) -> Option<(i64, i64)> {
    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 24 || &bytes[0..8] != PNG_SIGNATURE || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
    let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    valid_dimensions(width, height)
}

fn gif_dimensions(bytes: &[u8]) -> Option<(i64, i64)> {
    if bytes.len() < 10 || (&bytes[0..6] != b"GIF87a" && &bytes[0..6] != b"GIF89a") {
        return None;
    }
    let width = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    let height = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
    valid_dimensions(width as u32, height as u32)
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(i64, i64)> {
    if bytes.len() < 4 || bytes[0] != 0xff || bytes[1] != 0xd8 {
        return None;
    }
    let mut pos = 2;
    while pos + 4 <= bytes.len() {
        while pos < bytes.len() && bytes[pos] == 0xff {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
        let marker = bytes[pos];
        pos += 1;
        if marker == 0xd8 || marker == 0xd9 || marker == 0x01 {
            continue;
        }
        if pos + 2 > bytes.len() {
            return None;
        }
        let segment_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into().ok()?) as usize;
        if segment_len < 2 || pos + segment_len > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if segment_len < 7 {
                return None;
            }
            let height = u16::from_be_bytes(bytes[pos + 3..pos + 5].try_into().ok()?);
            let width = u16::from_be_bytes(bytes[pos + 5..pos + 7].try_into().ok()?);
            return valid_dimensions(width as u32, height as u32);
        }
        pos += segment_len;
    }
    None
}

fn valid_dimensions(width: u32, height: u32) -> Option<(i64, i64)> {
    if width == 0 || height == 0 {
        None
    } else {
        Some((width as i64, height as i64))
    }
}

pub fn parse_expiry(input: Option<&str>) -> anyhow::Result<Option<i64>> {
    let Some(duration) = parse_expiry_duration(input)? else {
        return Ok(None);
    };
    let expires_at = now_ts()
        .checked_add(duration)
        .ok_or_else(|| anyhow::anyhow!("expiry is too far in the future"))?;
    Ok(Some(expires_at))
}

fn parse_expiry_duration(input: Option<&str>) -> anyhow::Result<Option<i64>> {
    let Some(input) = input.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if input.eq_ignore_ascii_case("never") {
        return Ok(None);
    }
    let (number, multiplier) = if let Some(hours) = input.strip_suffix('h') {
        (hours, 60 * 60)
    } else if let Some(days) = input.strip_suffix('d') {
        (days, 60 * 60 * 24)
    } else {
        (input, 60 * 60 * 24)
    };
    let count = number.trim().parse::<i64>()?;
    if count <= 0 {
        anyhow::bail!("expiry must be positive");
    }
    count
        .checked_mul(multiplier)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("expiry duration is too large"))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_catbox_style_slugs() {
        assert_eq!(split_slug("abc123.png"), Some(("abc123", Some("png"))));
        assert_eq!(split_slug("abc123"), Some(("abc123", None)));
        assert_eq!(split_slug("../x"), None);
    }

    #[test]
    fn password_round_trip() {
        let hash = hash_password_blocking("correct horse").unwrap();
        assert!(verify_password_blocking("correct horse", &hash));
        assert!(!verify_password_blocking("wrong", &hash));
    }

    #[tokio::test]
    async fn password_work_yields_instead_of_occupying_the_worker() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // `#[tokio::test]` runs on a current-thread runtime, so a spawned task cannot make any
        // progress until the task below yields. If argon2 ran inline, the flag would still be
        // false once hashing finished.
        let hashed = Arc::new(AtomicBool::new(false));
        let flag = hashed.clone();
        let other = tokio::spawn(async move { flag.store(true, Ordering::SeqCst) });

        let hash = hash_password("correct horse").await.unwrap();
        assert!(
            hashed.load(Ordering::SeqCst),
            "hashing occupied the runtime worker instead of moving to the blocking pool"
        );

        let verified = Arc::new(AtomicBool::new(false));
        let flag = verified.clone();
        let another = tokio::spawn(async move { flag.store(true, Ordering::SeqCst) });

        assert!(verify_password("correct horse", &hash).await);
        assert!(
            verified.load(Ordering::SeqCst),
            "verification occupied the runtime worker instead of moving to the blocking pool"
        );

        assert!(!verify_password("wrong", &hash).await);
        other.await.unwrap();
        another.await.unwrap();
    }

    #[test]
    fn parses_expiry_values() {
        assert!(parse_expiry(None).unwrap().is_none());
        assert!(parse_expiry(Some("never")).unwrap().is_none());
        assert!(parse_expiry(Some("1h")).unwrap().unwrap() > now_ts());
        assert!(parse_expiry(Some("2d")).unwrap().unwrap() > now_ts());
        assert!(parse_expiry(Some("9223372036854775808d")).is_err());
        assert!(parse_expiry(Some("9223372036854775807h")).is_err());
    }

    #[test]
    fn reads_simple_image_dimensions() {
        let png = *b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x20\0\0\0\x10";
        assert_eq!(image_dimensions(&png), Some((32, 16)));

        let gif = *b"GIF89a\x20\0\x10\0";
        assert_eq!(image_dimensions(&gif), Some((32, 16)));

        let jpeg = [
            0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x0a, 0x08, 0x00,
            0x10, 0x00, 0x20, 0x01, 0x01, 0x11,
        ];
        assert_eq!(image_dimensions(&jpeg), Some((32, 16)));

        assert_eq!(image_dimensions(b"not image"), None);
    }
}
