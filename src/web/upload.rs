use super::*;
use std::path::{Path as FsPath, PathBuf};

use bytes::BytesMut;
use futures_util::StreamExt;
use tokio::io::AsyncReadExt;

#[derive(Debug)]
pub(super) struct UploadedFile {
    source: UploadedFileSource,
    pub(super) filename: Option<String>,
    pub(super) content_type: Option<String>,
    size_bytes: i64,
    preview: Bytes,
}

#[derive(Debug)]
enum UploadedFileSource {
    Memory(Bytes),
    TempPath(PathBuf),
}

#[derive(Debug)]
pub(super) struct FetchedUrlUpload {
    pub(super) file: UploadedFile,
}

#[derive(Debug)]
pub(super) struct PersistedUpload {
    pub(super) file: FileItem,
    pub(super) url: String,
    pub(super) raw_url: String,
    pub(super) internal_url: Option<String>,
    pub(super) delete_token: Option<String>,
}

pub(super) struct UploadFormData {
    pub(super) file: UploadedFile,
    pub(super) expires: Option<String>,
    pub(super) visibility: Option<String>,
    pub(super) csrf_token: Option<String>,
}

const UPLOAD_PREVIEW_BYTES: usize = 256 * 1024;

impl UploadedFile {
    #[cfg(test)]
    fn from_bytes(bytes: Bytes, filename: Option<String>, content_type: Option<String>) -> Self {
        let preview_len = bytes.len().min(UPLOAD_PREVIEW_BYTES);
        let size_bytes = bytes.len() as i64;
        Self {
            preview: bytes.slice(0..preview_len),
            source: UploadedFileSource::Memory(bytes),
            filename,
            content_type,
            size_bytes,
        }
    }

    fn from_temp_path(
        path: PathBuf,
        size_bytes: i64,
        preview: Bytes,
        filename: Option<String>,
        content_type: Option<String>,
    ) -> Self {
        Self {
            source: UploadedFileSource::TempPath(path),
            filename,
            content_type,
            size_bytes,
            preview,
        }
    }

    fn source_path(&self) -> Option<&FsPath> {
        match &self.source {
            UploadedFileSource::Memory(_) => None,
            UploadedFileSource::TempPath(path) => Some(path.as_path()),
        }
    }

    fn preview(&self) -> &[u8] {
        &self.preview
    }

    fn size_bytes(&self) -> i64 {
        self.size_bytes
    }

    async fn bytes(&self) -> AppResult<Bytes> {
        match &self.source {
            UploadedFileSource::Memory(bytes) => Ok(bytes.clone()),
            UploadedFileSource::TempPath(path) => Ok(Bytes::from(tokio::fs::read(path).await?)),
        }
    }

    async fn replace_with_bytes(&mut self, bytes: Bytes) {
        if let UploadedFileSource::TempPath(path) =
            std::mem::replace(&mut self.source, UploadedFileSource::Memory(bytes.clone()))
        {
            let _ = tokio::fs::remove_file(path).await;
        }
        self.size_bytes = bytes.len() as i64;
        self.preview = bytes.slice(0..bytes.len().min(UPLOAD_PREVIEW_BYTES));
    }

    async fn replace_with_temp_rewrite(&mut self, rewrite: TempFileRewrite) {
        if let UploadedFileSource::TempPath(path) =
            std::mem::replace(&mut self.source, UploadedFileSource::TempPath(rewrite.path))
        {
            let _ = tokio::fs::remove_file(path).await;
        }
        self.size_bytes = rewrite.size_bytes;
        self.preview = rewrite.preview;
    }

    async fn strip_metadata(
        &mut self,
        content_type: &str,
        temp_dir: Option<&FsPath>,
    ) -> AppResult<()> {
        match &self.source {
            UploadedFileSource::Memory(bytes) => {
                self.replace_with_bytes(processing::strip_file_metadata(
                    content_type,
                    bytes.clone(),
                ))
                .await;
            }
            UploadedFileSource::TempPath(path) => {
                if let Some(rewrite) =
                    strip_temp_file_metadata(content_type, path.as_path(), temp_dir).await?
                {
                    self.replace_with_temp_rewrite(rewrite).await;
                }
            }
        }
        Ok(())
    }

    async fn sha256_hex(&self) -> AppResult<String> {
        let mut hasher = Sha256::new();
        match &self.source {
            UploadedFileSource::Memory(bytes) => hasher.update(bytes),
            UploadedFileSource::TempPath(path) => {
                let mut file = tokio::fs::File::open(path).await?;
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer).await?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

impl Drop for UploadedFile {
    fn drop(&mut self) {
        if let UploadedFileSource::TempPath(path) = &self.source {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(super) async fn fetch_url_upload(
    settings: &RuntimeSettings,
    mut url: url::Url,
) -> AppResult<FetchedUrlUpload> {
    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(
            settings.security.url_upload.connect_timeout_seconds,
        ))
        .timeout(std::time::Duration::from_secs(
            settings.security.url_upload.request_timeout_seconds,
        ));
    if let Some(user_agent) = settings.security.url_upload.user_agent.as_deref() {
        client = client.user_agent(user_agent.to_string());
    }
    let client = client.build()?;
    for redirect_count in 0..=settings.security.url_upload.max_redirects {
        validate_url_upload_target(settings, &url).await?;
        let response = client.get(url.clone()).send().await?;
        reject_url_upload_remote_addr(settings, &response)?;
        if response.status().is_redirection() {
            if redirect_count == settings.security.url_upload.max_redirects {
                return Err(AppError::BadRequest(
                    "URL upload exceeded redirect limit".to_string(),
                ));
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| AppError::BadRequest("redirect missing Location".to_string()))?;
            url = url
                .join(location)
                .map_err(|err| AppError::BadRequest(format!("invalid redirect URL: {err}")))?;
            continue;
        }
        let response = response.error_for_status()?;
        if let Some(length) = response.content_length()
            && (length > settings.limits.max_upload_bytes as u64
                || settings
                    .security
                    .url_upload
                    .max_response_bytes
                    .is_some_and(|limit| length > limit as u64))
        {
            return Err(AppError::PayloadTooLarge);
        }
        let file = read_limited_url_response(settings, response).await?;
        return Ok(FetchedUrlUpload { file });
    }
    Err(AppError::BadRequest("URL upload failed".to_string()))
}

fn reject_url_upload_remote_addr(
    settings: &RuntimeSettings,
    response: &reqwest::Response,
) -> AppResult<()> {
    if settings.security.url_upload.block_private_ips
        && let Some(addr) = response.remote_addr()
    {
        reject_private_ip(addr.ip())?;
    }
    Ok(())
}

async fn read_limited_url_response(
    settings: &RuntimeSettings,
    response: reqwest::Response,
) -> AppResult<UploadedFile> {
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let mut limit = settings.limits.max_upload_bytes;
    if let Some(response_limit) = settings.security.url_upload.max_response_bytes {
        limit = limit.min(response_limit);
    }
    if limit < 0 {
        return Err(AppError::PayloadTooLarge);
    }
    let mut total = 0_i64;
    let (temp_path, mut temp) = create_upload_temp(settings.uploads.temp_dir.as_deref()).await?;
    // Every early return past this point has to clean up after itself, including the `?` on a
    // mid-stream read or write error.
    let scratch = ScratchFile::new(temp_path);
    let mut preview = BytesMut::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total = total.saturating_add(chunk.len() as i64);
        if total > limit {
            return Err(AppError::PayloadTooLarge);
        }
        append_preview(&mut preview, &chunk);
        temp.write_all(&chunk).await?;
    }
    temp.flush().await?;
    drop(temp);
    Ok(UploadedFile::from_temp_path(
        scratch.keep(),
        total,
        preview.freeze(),
        None,
        content_type,
    ))
}

/// Removes a scratch file unless ownership is handed off with [`ScratchFile::keep`].
struct ScratchFile(Option<PathBuf>);

impl ScratchFile {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn keep(mut self) -> PathBuf {
        self.0.take().expect("scratch path is taken only once")
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn validate_url_upload_target(settings: &RuntimeSettings, url: &url::Url) -> AppResult<()> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::BadRequest(
            "only http and https URLs are supported".to_string(),
        ));
    }
    let port = url.port_or_known_default().unwrap_or(80);
    if !settings.security.url_upload.allowed_ports.is_empty()
        && !settings.security.url_upload.allowed_ports.contains(&port)
    {
        return Err(AppError::BadRequest("URL port is not allowed".to_string()));
    }
    if settings.security.url_upload.blocked_ports.contains(&port) {
        return Err(AppError::BadRequest("URL port is blocked".to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("URL host is required".to_string()))?
        .to_ascii_lowercase();
    if settings
        .security
        .url_upload
        .blocked_hosts
        .iter()
        .any(|pattern| host_matches(&host, pattern))
    {
        return Err(AppError::BadRequest("URL host is blocked".to_string()));
    }
    if !settings.security.url_upload.allowed_hosts.is_empty()
        && !settings
            .security
            .url_upload
            .allowed_hosts
            .iter()
            .any(|pattern| host_matches(&host, pattern))
    {
        return Err(AppError::BadRequest("URL host is not allowed".to_string()));
    }
    if settings.security.url_upload.block_private_ips {
        match url.host() {
            Some(url::Host::Ipv4(ip)) => reject_private_ip(IpAddr::V4(ip))?,
            Some(url::Host::Ipv6(ip)) => reject_private_ip(IpAddr::V6(ip))?,
            Some(url::Host::Domain(domain)) => {
                let port = url.port_or_known_default().unwrap_or(80);
                let mut addrs = tokio::net::lookup_host((domain, port)).await?;
                let mut saw_addr = false;
                for addr in addrs.by_ref() {
                    saw_addr = true;
                    reject_private_ip(addr.ip())?;
                }
                if !saw_addr {
                    return Err(AppError::BadRequest("URL host did not resolve".to_string()));
                }
            }
            None => return Err(AppError::BadRequest("URL host is required".to_string())),
        }
    }
    Ok(())
}

fn reject_private_ip(ip: IpAddr) -> AppResult<()> {
    if is_private_upload_ip(ip) {
        Err(AppError::BadRequest(
            "URL resolved to a private or local address".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn is_private_upload_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

fn host_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if pattern.is_empty() {
        return false;
    }
    host == pattern
        || (pattern.starts_with('.') && host.ends_with(&pattern))
        || host.ends_with(&format!(".{pattern}"))
}

fn resolved_content_type(settings: &RuntimeSettings, uploaded: &UploadedFile) -> AppResult<String> {
    let declared = uploaded.content_type.as_deref().and_then(clean_mime);
    let extension_guess = uploaded.filename.as_deref().and_then(|name| {
        mime_guess::from_path(name)
            .first()
            .map(|mime| mime.essence_str().to_string())
    });
    let sniffed = processing::sniff_mime(uploaded.preview()).map(ToOwned::to_owned);

    if settings.security.reject_mime_mismatch {
        if let (Some(sniffed), Some(declared)) = (sniffed.as_deref(), declared.as_deref()) {
            reject_mime_mismatch(sniffed, declared, "declared content type")?;
        }
        if let (Some(sniffed), Some(extension_guess)) =
            (sniffed.as_deref(), extension_guess.as_deref())
        {
            reject_mime_mismatch(sniffed, extension_guess, "filename extension")?;
        }
    }

    let specific_sniffed = sniffed
        .clone()
        .filter(|mime| !is_generic_mime(mime.as_str()));
    Ok(specific_sniffed
        .or(declared)
        .or(extension_guess)
        .or(sniffed)
        .unwrap_or_else(|| "application/octet-stream".to_string()))
}

/// Whether a sniff result means "no idea" rather than a named format.
///
/// `sniff_mime` matches magic bytes and otherwise reports `text/plain` for printable input and
/// `application/octet-stream` for everything else. Neither says anything about SVG, JSON, CSS, JS
/// or most HTML, so neither may override what the upload declared: the stored type is what
/// `forced_attachment_mime_types` and `risky_mime_mode` are matched against.
fn is_generic_mime(value: &str) -> bool {
    matches!(value, "application/octet-stream" | "text/plain")
}

fn clean_mime(value: &str) -> Option<String> {
    value
        .parse::<mime::Mime>()
        .ok()
        .map(|mime| mime.essence_str().to_ascii_lowercase())
}

fn reject_mime_mismatch(sniffed: &str, candidate: &str, source: &str) -> AppResult<()> {
    if is_generic_mime(candidate) || is_generic_mime(sniffed) {
        return Ok(());
    }
    if sniffed != candidate {
        return Err(AppError::BadRequest(format!(
            "detected MIME {sniffed} does not match {source} {candidate}"
        )));
    }
    Ok(())
}

pub(super) async fn read_upload_form(
    settings: &RuntimeSettings,
    mut multipart: Multipart,
    max_bytes: i64,
) -> AppResult<UploadFormData> {
    let mut file = None;
    let mut expires = None;
    let mut visibility = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart body: {err}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        if name == "expires" {
            expires = Some(
                field
                    .text()
                    .await
                    .map_err(|err| AppError::BadRequest(format!("invalid expiry field: {err}")))?,
            );
        } else if name == "visibility" {
            visibility =
                Some(field.text().await.map_err(|err| {
                    AppError::BadRequest(format!("invalid visibility field: {err}"))
                })?);
        } else if name == CSRF_FIELD {
            let token = field
                .text()
                .await
                .map_err(|err| AppError::BadRequest(format!("invalid CSRF field: {err}")))?;
            return read_upload_form_after_csrf(
                settings,
                multipart,
                max_bytes,
                file,
                expires,
                visibility,
                Some(token),
            )
            .await;
        } else if name == "file" {
            file = Some(
                read_upload_field_to_temp(settings.uploads.temp_dir.as_deref(), field, max_bytes)
                    .await?,
            );
        }
    }
    Ok(UploadFormData {
        file: file.ok_or_else(|| AppError::BadRequest("missing file field".to_string()))?,
        expires,
        visibility,
        csrf_token: None,
    })
}

async fn read_upload_form_after_csrf(
    settings: &RuntimeSettings,
    mut multipart: Multipart,
    max_bytes: i64,
    mut file: Option<UploadedFile>,
    mut expires: Option<String>,
    mut visibility: Option<String>,
    csrf_token: Option<String>,
) -> AppResult<UploadFormData> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart body: {err}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        if name == "expires" {
            expires = Some(
                field
                    .text()
                    .await
                    .map_err(|err| AppError::BadRequest(format!("invalid expiry field: {err}")))?,
            );
        } else if name == "visibility" {
            visibility =
                Some(field.text().await.map_err(|err| {
                    AppError::BadRequest(format!("invalid visibility field: {err}"))
                })?);
        } else if name == "file" {
            file = Some(
                read_upload_field_to_temp(settings.uploads.temp_dir.as_deref(), field, max_bytes)
                    .await?,
            );
        }
    }
    Ok(UploadFormData {
        file: file.ok_or_else(|| AppError::BadRequest("missing file field".to_string()))?,
        expires,
        visibility,
        csrf_token,
    })
}

async fn create_upload_temp(temp_dir: Option<&FsPath>) -> AppResult<(PathBuf, tokio::fs::File)> {
    let base_temp = temp_dir
        .map(FsPath::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    tokio::fs::create_dir_all(&base_temp).await?;
    let temp_path = base_temp.join(format!("midden-upload-{}.part", uuid::Uuid::new_v4()));
    let temp = tokio::fs::File::create(&temp_path).await?;
    Ok((temp_path, temp))
}

fn append_preview(preview: &mut BytesMut, chunk: &[u8]) {
    let remaining = UPLOAD_PREVIEW_BYTES.saturating_sub(preview.len());
    if remaining > 0 {
        preview.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
}

struct TempFileRewrite {
    path: PathBuf,
    size_bytes: i64,
    preview: Bytes,
}

async fn strip_temp_file_metadata(
    content_type: &str,
    source_path: &FsPath,
    temp_dir: Option<&FsPath>,
) -> AppResult<Option<TempFileRewrite>> {
    match content_type {
        "image/jpeg" => strip_jpeg_metadata_file(source_path, temp_dir).await,
        "image/png" => strip_png_metadata_file(source_path, temp_dir).await,
        _ => Ok(None),
    }
}

async fn strip_png_metadata_file(
    source_path: &FsPath,
    temp_dir: Option<&FsPath>,
) -> AppResult<Option<TempFileRewrite>> {
    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    let mut input = tokio::fs::File::open(source_path).await?;
    let mut signature = [0_u8; 8];
    if !read_exact_or_none(&mut input, &mut signature).await? || &signature != PNG_SIGNATURE {
        return Ok(None);
    }

    let (output_path, mut output) = create_upload_temp(temp_dir).await?;
    let mut preview = BytesMut::new();
    let mut written = 0_i64;
    write_rewrite_chunk(&mut output, &mut preview, &mut written, &signature).await?;

    loop {
        let mut header = [0_u8; 8];
        if !read_exact_or_none(&mut input, &mut header).await? {
            break;
        }
        let length = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
        let payload_and_crc = length.saturating_add(4);
        let chunk_type = &header[4..8];
        let is_critical = chunk_type[0].is_ascii_uppercase();
        if is_critical {
            write_rewrite_chunk(&mut output, &mut preview, &mut written, &header).await?;
            if !copy_exact_rewrite(
                &mut input,
                &mut output,
                &mut preview,
                &mut written,
                payload_and_crc,
            )
            .await?
            {
                let _ = tokio::fs::remove_file(&output_path).await;
                return Ok(None);
            }
        } else if !skip_exact(&mut input, payload_and_crc).await? {
            let _ = tokio::fs::remove_file(&output_path).await;
            return Ok(None);
        }
        if chunk_type == b"IEND" {
            break;
        }
    }

    output.flush().await?;
    Ok(Some(TempFileRewrite {
        path: output_path,
        size_bytes: written,
        preview: preview.freeze(),
    }))
}

async fn strip_jpeg_metadata_file(
    source_path: &FsPath,
    temp_dir: Option<&FsPath>,
) -> AppResult<Option<TempFileRewrite>> {
    let mut input = tokio::fs::File::open(source_path).await?;
    let mut soi = [0_u8; 2];
    if !read_exact_or_none(&mut input, &mut soi).await? || soi != [0xff, 0xd8] {
        return Ok(None);
    }

    let (output_path, mut output) = create_upload_temp(temp_dir).await?;
    let mut preview = BytesMut::new();
    let mut written = 0_i64;
    write_rewrite_chunk(&mut output, &mut preview, &mut written, &soi).await?;

    loop {
        let mut prefix = [0_u8; 1];
        if !read_exact_or_none(&mut input, &mut prefix).await? {
            break;
        }
        if prefix[0] != 0xff {
            write_rewrite_chunk(&mut output, &mut preview, &mut written, &prefix).await?;
            copy_rest_rewrite(&mut input, &mut output, &mut preview, &mut written).await?;
            break;
        }

        let mut marker = [0_u8; 1];
        if !read_exact_or_none(&mut input, &mut marker).await? {
            let _ = tokio::fs::remove_file(&output_path).await;
            return Ok(None);
        }
        while marker[0] == 0xff {
            if !read_exact_or_none(&mut input, &mut marker).await? {
                let _ = tokio::fs::remove_file(&output_path).await;
                return Ok(None);
            }
        }

        if marker[0] == 0xd9 || marker[0] == 0x01 || (0xd0..=0xd7).contains(&marker[0]) {
            write_rewrite_chunk(&mut output, &mut preview, &mut written, &[0xff, marker[0]])
                .await?;
            if marker[0] == 0xd9 {
                break;
            }
            continue;
        }

        let mut length = [0_u8; 2];
        if !read_exact_or_none(&mut input, &mut length).await? {
            let _ = tokio::fs::remove_file(&output_path).await;
            return Ok(None);
        }
        let segment_len = u16::from_be_bytes(length) as usize;
        if segment_len < 2 {
            let _ = tokio::fs::remove_file(&output_path).await;
            return Ok(None);
        }
        let data_len = segment_len - 2;
        let is_metadata = (0xe0..=0xef).contains(&marker[0]) || marker[0] == 0xfe;
        if !is_metadata {
            write_rewrite_chunk(&mut output, &mut preview, &mut written, &[0xff, marker[0]])
                .await?;
            write_rewrite_chunk(&mut output, &mut preview, &mut written, &length).await?;
            if !copy_exact_rewrite(
                &mut input,
                &mut output,
                &mut preview,
                &mut written,
                data_len,
            )
            .await?
            {
                let _ = tokio::fs::remove_file(&output_path).await;
                return Ok(None);
            }
            if marker[0] == 0xda {
                copy_rest_rewrite(&mut input, &mut output, &mut preview, &mut written).await?;
                break;
            }
        } else if !skip_exact(&mut input, data_len).await? {
            let _ = tokio::fs::remove_file(&output_path).await;
            return Ok(None);
        }
    }

    output.flush().await?;
    Ok(Some(TempFileRewrite {
        path: output_path,
        size_bytes: written,
        preview: preview.freeze(),
    }))
}

async fn read_exact_or_none(input: &mut tokio::fs::File, buffer: &mut [u8]) -> AppResult<bool> {
    match input.read_exact(buffer).await {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => Err(err.into()),
    }
}

async fn write_rewrite_chunk(
    output: &mut tokio::fs::File,
    preview: &mut BytesMut,
    written: &mut i64,
    chunk: &[u8],
) -> AppResult<()> {
    output.write_all(chunk).await?;
    append_preview(preview, chunk);
    *written = written.saturating_add(chunk.len() as i64);
    Ok(())
}

async fn copy_exact_rewrite(
    input: &mut tokio::fs::File,
    output: &mut tokio::fs::File,
    preview: &mut BytesMut,
    written: &mut i64,
    mut remaining: usize,
) -> AppResult<bool> {
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        let read = input.read(&mut buffer[..take]).await?;
        if read == 0 {
            return Ok(false);
        }
        write_rewrite_chunk(output, preview, written, &buffer[..read]).await?;
        remaining -= read;
    }
    Ok(true)
}

async fn copy_rest_rewrite(
    input: &mut tokio::fs::File,
    output: &mut tokio::fs::File,
    preview: &mut BytesMut,
    written: &mut i64,
) -> AppResult<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        write_rewrite_chunk(output, preview, written, &buffer[..read]).await?;
    }
}

async fn skip_exact(input: &mut tokio::fs::File, mut remaining: usize) -> AppResult<bool> {
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        let read = input.read(&mut buffer[..take]).await?;
        if read == 0 {
            return Ok(false);
        }
        remaining -= read;
    }
    Ok(true)
}

async fn read_upload_field_to_temp(
    temp_dir: Option<&std::path::Path>,
    mut field: axum::extract::multipart::Field<'_>,
    max_bytes: i64,
) -> AppResult<UploadedFile> {
    let filename = field.file_name().map(ToOwned::to_owned);
    let content_type = field.content_type().map(ToString::to_string);
    let (temp_path, mut temp) = create_upload_temp(temp_dir).await?;
    let mut size = 0_i64;
    let mut preview = BytesMut::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid upload field: {err}")))?
    {
        size += chunk.len() as i64;
        if size > max_bytes {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(AppError::PayloadTooLarge);
        }
        append_preview(&mut preview, &chunk);
        temp.write_all(&chunk).await?;
    }
    temp.flush().await?;
    drop(temp);
    if size == 0 {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::BadRequest(
            "empty files are not accepted".to_string(),
        ));
    }
    Ok(UploadedFile::from_temp_path(
        temp_path,
        size,
        preview.freeze(),
        filename,
        content_type,
    ))
}

pub(super) async fn persist_file_upload(
    state: &AppState,
    settings: &RuntimeSettings,
    user: Option<&User>,
    mut uploaded: UploadedFile,
    expires_at: Option<i64>,
    visibility: &str,
) -> AppResult<PersistedUpload> {
    let content_type = resolved_content_type(settings, &uploaded)?;
    if let Some(filename) = uploaded.filename.as_deref()
        && filename.len() > settings.security.content_policy.max_filename_bytes
    {
        return Err(AppError::BadRequest("filename is too long".to_string()));
    }
    if !settings
        .security
        .content_policy
        .allowed_mime_types
        .is_empty()
        && !settings
            .security
            .content_policy
            .allowed_mime_types
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&content_type))
    {
        return Err(AppError::BadRequest("file type is not allowed".to_string()));
    }
    if settings.processing.metadata_stripping {
        uploaded
            .strip_metadata(&content_type, settings.uploads.temp_dir.as_deref())
            .await?;
    }
    let size_bytes = uploaded.size_bytes();
    let hash = uploaded.sha256_hex().await?;
    if settings
        .scanning
        .blocked_hashes
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(&hash))
    {
        return Err(AppError::BadRequest("file hash is blocked".to_string()));
    }
    if settings
        .scanning
        .blocked_mime_types
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(&content_type))
    {
        return Err(AppError::BadRequest("file type is blocked".to_string()));
    }
    let image_dimensions = util::image_dimensions(uploaded.preview());
    let metadata_json = if settings.processing.metadata_extraction {
        Some(processing::file_metadata_json(
            &content_type,
            size_bytes,
            image_dimensions,
            settings.processing.metadata_stripping,
        )?)
    } else {
        None
    };
    let extension = util::normalize_extension(uploaded.filename.as_deref(), Some(&content_type));
    let public_id = util::public_id();
    let scan = scanner::scan_upload(
        &settings.scanning,
        ScanInput {
            bytes: match &uploaded.source {
                UploadedFileSource::Memory(bytes) => Some(bytes),
                UploadedFileSource::TempPath(_) => None,
            },
            path: uploaded.source_path(),
            size_bytes,
            filename: uploaded.filename.as_deref(),
            content_type: Some(&content_type),
            hash: &hash,
            public_id: &public_id,
            temp_dir: settings.uploads.temp_dir.as_deref(),
        },
    )
    .await;
    state
        .metrics
        .record_scanner_outcome(&format!("{:?}", scan.decision).to_lowercase());
    if matches!(scan.decision, crate::config::ScanDecision::Reject) {
        return Err(AppError::BadRequest(
            "upload rejected by scanner".to_string(),
        ));
    }
    let file_state = if matches!(scan.decision, crate::config::ScanDecision::Quarantine) {
        "quarantined"
    } else {
        "active"
    };
    let delete_token = anonymous_delete_token(settings, user);
    let delete_token_hash = delete_token.as_deref().map(util::hash_token);
    let quota_guard = state.upload_quota_lock.lock().await;
    quota::enforce_file_upload_quota(&state.db, settings, user, size_bytes).await?;
    let mut blob_mutation = state.db.begin_blob_mutation(&hash).await?;
    blob_mutation
        .create_blob_if_missing(size_bytes, Some(&content_type))
        .await?;
    let object_already_existed = state.storage.exists(&hash).await?;
    if !object_already_existed {
        if let Some(path) = uploaded.source_path() {
            state.storage.put_blob_from_path(&hash, path).await?;
        } else {
            state
                .storage
                .put_blob(&hash, uploaded.bytes().await?)
                .await?;
        }
    }
    let file = match blob_mutation
        .create_file_item(NewFileItem {
            id: &uuid::Uuid::new_v4().to_string(),
            public_id: &public_id,
            blob_hash: &hash,
            original_filename: uploaded.filename.as_deref(),
            extension: extension.as_deref(),
            content_type: Some(&content_type),
            size_bytes,
            image_width: image_dimensions.map(|(width, _)| width),
            image_height: image_dimensions.map(|(_, height)| height),
            owner_user_id: user.map(|user| user.id.as_str()),
            delete_token_hash: delete_token_hash.as_deref(),
            expires_at,
            visibility,
            metadata_json: metadata_json.as_deref(),
            thumbnail_hash: None,
            state: file_state,
        })
        .await
    {
        Ok(file) => file,
        Err(err) => {
            drop(blob_mutation);
            if !object_already_existed {
                crate::commands::cleanup_zero_ref_blob(&state.db, &state.storage, &hash).await;
            }
            return Err(err.into());
        }
    };
    if let Err(err) = blob_mutation.commit().await {
        if !object_already_existed {
            crate::commands::cleanup_zero_ref_blob(&state.db, &state.storage, &hash).await;
        }
        return Err(err.into());
    }
    drop(quota_guard);
    for report in &scan.reports {
        state
            .db
            .record_scan_result(
                "file",
                &file.public_id,
                &report.adapter,
                &format!("{:?}", report.decision).to_lowercase(),
                &report.detail,
            )
            .await?;
    }
    if file_state == "quarantined" {
        return Err(AppError::BadRequest(
            "upload quarantined by scanner".to_string(),
        ));
    }
    state.metrics.uploads.inc();
    state.metrics.upload_bytes.inc_by(size_bytes as u64);
    let internal_url = signed_internal_raw_url(state, settings, &file);
    Ok(PersistedUpload {
        raw_url: raw_file_url(state, settings, &file),
        url: file_url(state, settings, &file),
        internal_url,
        delete_token,
        file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> RuntimeSettings {
        RuntimeSettings::from_config(&crate::config::AppConfig::default())
    }

    #[test]
    fn resolved_content_type_keeps_declared_media_type_when_sniff_is_generic_binary() {
        let uploaded = UploadedFile::from_bytes(
            Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]),
            Some("clip.mp4".to_string()),
            Some("video/mp4".to_string()),
        );

        assert_eq!(
            resolved_content_type(&settings(), &uploaded).unwrap(),
            "video/mp4"
        );
    }

    #[test]
    fn resolved_content_type_uses_filename_type_when_sniff_is_generic_binary() {
        let uploaded = UploadedFile::from_bytes(
            Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]),
            Some("image.webp".to_string()),
            None,
        );

        assert_eq!(
            resolved_content_type(&settings(), &uploaded).unwrap(),
            "image/webp"
        );
    }

    /// `sniff_mime` only knows magic bytes, so every text-based format it cannot name comes back
    /// as `text/plain`. Letting that win would rewrite SVG, JSON, CSS and JS uploads to plain text
    /// and take `forced_attachment_mime_types` out of play, since that list matches on the type
    /// that was stored.
    #[test]
    fn declared_text_formats_survive_a_generic_text_sniff() {
        for (filename, declared, bytes, expected) in [
            (
                "logo.svg",
                Some("image/svg+xml"),
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".as_slice(),
                "image/svg+xml",
            ),
            (
                "page.html",
                Some("text/html"),
                b"<img src=x onerror=alert(1)>".as_slice(),
                "text/html",
            ),
            (
                "app.js",
                Some("application/javascript"),
                b"console.log(1);".as_slice(),
                "application/javascript",
            ),
            (
                "data.json",
                None,
                b"{\"a\":1}".as_slice(),
                "application/json",
            ),
            ("style.css", None, b"body{color:red}".as_slice(), "text/css"),
        ] {
            let uploaded = UploadedFile::from_bytes(
                Bytes::copy_from_slice(bytes),
                Some(filename.to_string()),
                declared.map(ToOwned::to_owned),
            );
            assert_eq!(
                resolved_content_type(&settings(), &uploaded).unwrap(),
                expected,
                "{filename}"
            );
        }
    }

    /// Plain text stays plain text when nothing more specific is on offer.
    #[test]
    fn resolved_content_type_falls_back_to_the_generic_text_sniff() {
        let uploaded = UploadedFile::from_bytes(
            Bytes::from_static(b"just some words"),
            Some("notes".to_string()),
            None,
        );

        assert_eq!(
            resolved_content_type(&settings(), &uploaded).unwrap(),
            "text/plain"
        );
    }

    /// A generic sniff is an absence of evidence, not evidence of a mismatch. Treating it as one
    /// rejects every SVG, JSON, CSS and JS upload the moment the setting is turned on.
    #[test]
    fn mime_mismatch_rejection_ignores_generic_sniff_results() {
        let mut settings = settings();
        settings.security.reject_mime_mismatch = true;
        let uploaded = UploadedFile::from_bytes(
            Bytes::from_static(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
            Some("logo.svg".to_string()),
            Some("image/svg+xml".to_string()),
        );

        assert_eq!(
            resolved_content_type(&settings, &uploaded).unwrap(),
            "image/svg+xml"
        );
    }

    #[test]
    fn mime_mismatch_rejection_still_catches_a_named_disagreement() {
        let mut settings = settings();
        settings.security.reject_mime_mismatch = true;
        let uploaded = UploadedFile::from_bytes(
            Bytes::from_static(b"\x89PNG\r\n\x1a\npixels"),
            Some("clip.mp4".to_string()),
            Some("video/mp4".to_string()),
        );

        assert!(resolved_content_type(&settings, &uploaded).is_err());
    }

    #[tokio::test]
    async fn url_upload_target_validation_blocks_private_hosts_by_default() {
        let err = validate_url_upload_target(
            &settings(),
            &url::Url::parse("http://127.0.0.1/file.txt").unwrap(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            AppError::BadRequest(message)
                if message.contains("private or local")
        ));
    }

    #[test]
    fn private_upload_ip_detection_covers_rebinding_remote_addr_classes() {
        assert!(is_private_upload_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_upload_ip("10.1.2.3".parse().unwrap()));
        assert!(is_private_upload_ip("169.254.1.1".parse().unwrap()));
        assert!(is_private_upload_ip("::1".parse().unwrap()));
        assert!(is_private_upload_ip("fd00::1".parse().unwrap()));
        assert!(!is_private_upload_ip("93.184.216.34".parse().unwrap()));
    }

    #[tokio::test]
    async fn streaming_png_metadata_strip_skips_ancillary_chunks() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.png");
        let png = [
            b"\x89PNG\r\n\x1a\n".as_slice(),
            &[0, 0, 0, 0, b'I', b'H', b'D', b'R', 0, 0, 0, 0],
            &[
                0, 0, 0, 4, b't', b'E', b'X', b't', b'm', b'e', b't', b'a', 0, 0, 0, 0,
            ],
            &[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0, 0, 0, 0],
        ]
        .concat();
        tokio::fs::write(&source, &png).await.unwrap();

        let rewrite = strip_temp_file_metadata("image/png", &source, Some(temp.path()))
            .await
            .unwrap()
            .unwrap();
        let stripped = tokio::fs::read(&rewrite.path).await.unwrap();

        assert!(!stripped.windows(4).any(|window| window == b"tEXt"));
        assert!(stripped.windows(4).any(|window| window == b"IHDR"));
        assert!(stripped.windows(4).any(|window| window == b"IEND"));
    }

    #[tokio::test]
    async fn streaming_jpeg_metadata_strip_skips_app_segments() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.jpg");
        let mut jpeg = Vec::new();
        jpeg.extend_from_slice(&[0xff, 0xd8]);
        jpeg.extend_from_slice(&[0xff, 0xe1, 0, 4, b'm', b'd']);
        jpeg.extend_from_slice(&[0xff, 0xc0, 0, 4, b'i', b'm']);
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        tokio::fs::write(&source, &jpeg).await.unwrap();

        let rewrite = strip_temp_file_metadata("image/jpeg", &source, Some(temp.path()))
            .await
            .unwrap()
            .unwrap();
        let stripped = tokio::fs::read(&rewrite.path).await.unwrap();

        assert!(!stripped.windows(2).any(|window| window == [0xff, 0xe1]));
        assert!(stripped.windows(2).any(|window| window == [0xff, 0xc0]));
        assert!(stripped.ends_with(&[0xff, 0xd9]));
    }

    #[test]
    fn upload_readers_do_not_rehydrate_temp_files_into_memory() {
        let source = include_str!("upload.rs");

        let forbidden = concat!("tokio::fs::", "read(&temp_path)");
        assert!(
            !source.contains(forbidden),
            "multipart uploads must not read accepted temp files back into one Bytes buffer"
        );
        let metadata_forbidden = concat!(
            "settings.processing.metadata_stripping {\n",
            "        let bytes = uploaded.bytes().await?;"
        );
        assert!(
            !source.contains(metadata_forbidden),
            "metadata stripping must not force temp-backed uploads into one Bytes buffer"
        );
    }
}
