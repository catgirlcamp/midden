use bytes::Bytes;
use std::io::Cursor;

pub fn sniff_mime(bytes: &[u8]) -> Option<&'static str> {
    if let Some(kind) = infer::get(bytes) {
        return Some(kind.mime_type());
    }
    if bytes
        .iter()
        .all(|byte| matches!(*byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
    {
        return Some("text/plain");
    }
    Some("application/octet-stream")
}

pub fn file_metadata_json(
    content_type: &str,
    size_bytes: i64,
    image_dimensions: Option<(i64, i64)>,
    metadata_stripped: bool,
) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "content_type": content_type,
        "size_bytes": size_bytes,
        "image_width": image_dimensions.map(|(width, _)| width),
        "image_height": image_dimensions.map(|(_, height)| height),
        "metadata_stripped": metadata_stripped,
    }))?)
}

pub fn strip_file_metadata(content_type: &str, bytes: Bytes) -> Bytes {
    match content_type {
        "image/jpeg" => strip_jpeg_metadata(bytes.as_ref())
            .map(Bytes::from)
            .unwrap_or(bytes),
        "image/png" => strip_png_metadata(bytes.as_ref())
            .map(Bytes::from)
            .unwrap_or(bytes),
        _ => bytes,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThumbnailLimits {
    pub max_dimension: u32,
    pub source_max_pixels: u32,
    pub source_max_alloc_bytes: u64,
}

impl ThumbnailLimits {
    pub fn from_config(processing: &crate::config::ProcessingConfig) -> Self {
        Self {
            max_dimension: processing.thumbnail_max_dimension,
            source_max_pixels: processing.thumbnail_source_max_pixels,
            source_max_alloc_bytes: processing.thumbnail_source_max_alloc_bytes,
        }
    }
}

/// Renders a downscaled PNG preview, or `None` when the source cannot be decoded within limits.
///
/// This is CPU-bound and allocates proportionally to the *decoded* image, which an attacker
/// controls independently of upload size. Callers must run it off the async runtime.
pub fn thumbnail_derivative(
    content_type: &str,
    bytes: &[u8],
    limits: ThumbnailLimits,
) -> Option<Bytes> {
    if limits.max_dimension == 0 {
        return None;
    }
    let format = match content_type {
        "image/jpeg" => image::ImageFormat::Jpeg,
        "image/png" => image::ImageFormat::Png,
        "image/gif" => image::ImageFormat::Gif,
        _ => return None,
    };
    let thumb = match decode_within_limits(bytes, format, limits) {
        Some(image) => image.thumbnail(limits.max_dimension, limits.max_dimension),
        None => {
            // The header may still be readable even when a full decode is refused, but a
            // placeholder is only worth emitting for images we chose not to decode for other
            // reasons -- never for one that blew the limits.
            let (width, height) = crate::util::image_dimensions(bytes)?;
            if width > i64::from(limits.source_max_pixels)
                || height > i64::from(limits.source_max_pixels)
            {
                return None;
            }
            let scale = (f64::from(limits.max_dimension) / (width.max(height) as f64)).min(1.0);
            let thumb_width = ((width as f64 * scale).round() as u32).max(1);
            let thumb_height = ((height as f64 * scale).round() as u32).max(1);
            image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
                thumb_width,
                thumb_height,
                image::Rgba([0, 0, 0, 0]),
            ))
        }
    };
    let mut out = Cursor::new(Vec::new());
    thumb.write_to(&mut out, image::ImageFormat::Png).ok()?;
    Some(Bytes::from(out.into_inner()))
}

fn decode_within_limits(
    bytes: &[u8],
    format: image::ImageFormat,
    limits: ThumbnailLimits,
) -> Option<image::DynamicImage> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes));
    reader.set_format(format);
    let mut decode_limits = image::Limits::no_limits();
    decode_limits.max_image_width = Some(limits.source_max_pixels);
    decode_limits.max_image_height = Some(limits.source_max_pixels);
    decode_limits.max_alloc = Some(limits.source_max_alloc_bytes);
    reader.limits(decode_limits);
    reader.decode().ok()
}

fn strip_jpeg_metadata(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 4 || bytes[0..2] != [0xff, 0xd8] {
        return None;
    }
    let mut out = bytes[0..2].to_vec();
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] != 0xff {
            out.extend_from_slice(&bytes[offset..]);
            return Some(out);
        }
        let marker = bytes[offset + 1];
        if marker == 0xda || marker == 0xd9 {
            out.extend_from_slice(&bytes[offset..]);
            return Some(out);
        }
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 2 || offset + 2 + length > bytes.len() {
            return None;
        }
        let is_metadata = (0xe0..=0xef).contains(&marker) || marker == 0xfe;
        if !is_metadata {
            out.extend_from_slice(&bytes[offset..offset + 2 + length]);
        }
        offset += 2 + length;
    }
    Some(out)
}

fn strip_png_metadata(bytes: &[u8]) -> Option<Vec<u8>> {
    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 8 || &bytes[0..8] != PNG_SIGNATURE {
        return None;
    }
    let mut out = PNG_SIGNATURE.to_vec();
    let mut offset = 8;
    while offset + 12 <= bytes.len() {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
        let chunk_end = offset + 12 + length;
        if chunk_end > bytes.len() {
            return None;
        }
        let chunk_type = &bytes[offset + 4..offset + 8];
        let is_critical = chunk_type[0].is_ascii_uppercase();
        if is_critical {
            out.extend_from_slice(&bytes[offset..chunk_end]);
        }
        offset = chunk_end;
        if chunk_type == b"IEND" {
            break;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_mime_detects_common_fixture_shapes() {
        assert_eq!(sniff_mime(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff_mime(b"GIF89arest"), Some("image/gif"));
        assert_eq!(sniff_mime(&[0xff, 0xd8, 0xff, 0xe0]), Some("image/jpeg"));
        assert_eq!(
            sniff_mime(b"RIFF\xce\x14\x00\x00WEBPVP8Xrest"),
            Some("image/webp")
        );
        assert_eq!(
            sniff_mime(b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomav01iso2mp41"),
            Some("video/mp4")
        );
        assert_eq!(sniff_mime(b"plain text"), Some("text/plain"));
    }

    /// A 64KiB PNG header declaring 60000x60000 pixels. Decoding it unbounded would try to
    /// allocate about 14GiB before the first row is read.
    fn decompression_bomb() -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&60_000_u32.to_be_bytes());
        ihdr.extend_from_slice(&60_000_u32.to_be_bytes());
        // 8-bit RGBA, no interlace.
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        header.extend_from_slice(&13_u32.to_be_bytes());
        header.extend_from_slice(&ihdr);
        header.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        header
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    fn test_limits() -> ThumbnailLimits {
        ThumbnailLimits::from_config(&crate::config::ProcessingConfig::default())
    }

    #[test]
    fn thumbnail_derivative_refuses_oversized_source_images() {
        assert!(
            thumbnail_derivative("image/png", &decompression_bomb(), test_limits()).is_none(),
            "a small file declaring huge dimensions must not be decoded"
        );
    }

    /// A real, fully decodable PNG. The `sample.png.hex` fixture is only a truncated header, so it
    /// exercises the dimensions-only fallback rather than the decoder.
    fn encoded_png(width: u32, height: u32) -> Vec<u8> {
        let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            width,
            height,
            image::Rgba([1, 2, 3, 255]),
        ));
        let mut out = Cursor::new(Vec::new());
        image.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn thumbnail_derivative_downscales_a_real_image() {
        let thumbnail = thumbnail_derivative(
            "image/png",
            &encoded_png(200, 100),
            ThumbnailLimits {
                max_dimension: 20,
                ..test_limits()
            },
        )
        .unwrap();

        let decoded = image::load_from_memory_with_format(&thumbnail, image::ImageFormat::Png)
            .expect("thumbnails are PNG encoded");
        assert_eq!(
            (
                image::GenericImageView::width(&decoded),
                image::GenericImageView::height(&decoded)
            ),
            (20, 10),
            "aspect ratio should be preserved within the bounding box"
        );
    }

    #[test]
    fn decode_limits_are_wired_into_the_reader() {
        let decoded = encoded_png(32, 16);

        // Same input, same code path: only the configured bound differs, so this cannot pass by
        // way of the header-only fallback.
        assert!(
            decode_within_limits(
                &decoded,
                image::ImageFormat::Png,
                ThumbnailLimits {
                    source_max_pixels: 1,
                    ..test_limits()
                }
            )
            .is_none(),
            "a source wider than source_max_pixels must be refused before decoding"
        );
        assert!(
            decode_within_limits(
                &decoded,
                image::ImageFormat::Png,
                ThumbnailLimits {
                    source_max_alloc_bytes: 16,
                    ..test_limits()
                }
            )
            .is_none(),
            "decoding must respect the allocation ceiling"
        );
        assert!(decode_within_limits(&decoded, image::ImageFormat::Png, test_limits()).is_some());
    }

    fn sample_png() -> Vec<u8> {
        include_str!("../tests/fixtures/sample.png.hex")
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>()
            .as_bytes()
            .chunks(2)
            .map(|chunk| {
                let text = std::str::from_utf8(chunk).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn thumbnail_derivative_resizes_supported_images() {
        let decoded = sample_png();
        let thumbnail = thumbnail_derivative(
            "image/png",
            &decoded,
            ThumbnailLimits {
                max_dimension: 12,
                ..test_limits()
            },
        )
        .unwrap();
        assert_ne!(thumbnail.as_ref(), decoded.as_slice());
        assert_eq!(sniff_mime(&thumbnail), Some("image/png"));
    }
}
