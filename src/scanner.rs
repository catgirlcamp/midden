use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};

use crate::{
    config::{ScanDecision, ScannerAdapterConfig, ScanningConfig},
    util,
};

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub adapter: String,
    pub decision: ScanDecision,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub decision: ScanDecision,
    pub reports: Vec<ScanReport>,
}

#[derive(Debug, Clone)]
pub struct ScanInput<'a> {
    pub bytes: Option<&'a Bytes>,
    pub path: Option<&'a Path>,
    pub size_bytes: i64,
    pub filename: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub hash: &'a str,
    pub public_id: &'a str,
    pub temp_dir: Option<&'a Path>,
}

pub async fn scan_upload(config: &ScanningConfig, input: ScanInput<'_>) -> ScanSummary {
    if !config.enabled || config.adapters.is_empty() {
        return ScanSummary {
            decision: ScanDecision::Allow,
            reports: Vec::new(),
        };
    }

    // An adapter runs inline with the upload request, so one that never returns would pin the
    // connection and its temp file open forever.
    let budget = Duration::from_secs(config.timeout_seconds.max(1));
    let mut reports = Vec::new();
    for adapter in &config.adapters {
        let (name, report) = match adapter {
            ScannerAdapterConfig::Command { program, args } => (
                "command",
                timeout(
                    budget,
                    run_command_scanner(program, args, &input, config.default_on_error),
                )
                .await,
            ),
            ScannerAdapterConfig::Webhook { url, secret } => (
                "webhook",
                timeout(
                    budget,
                    run_webhook_scanner(url, secret.as_deref(), &input, config.default_on_error),
                )
                .await,
            ),
            ScannerAdapterConfig::ClamAv { socket } => (
                "clamav",
                timeout(
                    budget,
                    run_clamav_scanner(socket, &input, config.default_on_error),
                )
                .await,
            ),
        };
        reports.push(report.unwrap_or_else(|_| ScanReport {
            adapter: name.to_string(),
            decision: config.default_on_error,
            detail: format!("scanner timed out after {}s", budget.as_secs()),
        }));
    }

    let decision = reports
        .iter()
        .map(|report| report.decision)
        .max_by_key(decision_rank)
        .unwrap_or(ScanDecision::Allow);

    ScanSummary { decision, reports }
}

async fn run_command_scanner(
    program: &str,
    args: &[String],
    input: &ScanInput<'_>,
    default_on_error: ScanDecision,
) -> ScanReport {
    let mut cleanup_path = None;
    let scan_path = match input.path {
        Some(path) => path.to_path_buf(),
        None => {
            let temp_path = scanner_temp_path(input.temp_dir, input.public_id);
            cleanup_path = Some(temp_path.clone());
            temp_path
        }
    };
    let result = async {
        if input.path.is_none() {
            if let Some(parent) = scan_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            write_input_to_path(input, &scan_path).await?;
        }
        let mut command = Command::new(program);
        // Without this a timed-out scan leaves the child running unsupervised.
        command.kill_on_drop(true);
        for arg in args {
            command.arg(expand_arg(arg, input, &scan_path));
        }
        let output = command.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = format!(
            "status={:?}; stdout={}; stderr={}",
            output.status.code(),
            stdout.trim(),
            stderr.trim()
        );
        let decision = match output.status.code() {
            Some(0) => ScanDecision::Allow,
            Some(10) => ScanDecision::Quarantine,
            Some(20) => ScanDecision::Reject,
            _ => default_on_error,
        };
        anyhow::Ok((decision, detail))
    }
    .await;

    if let Some(path) = cleanup_path {
        let _ = tokio::fs::remove_file(path).await;
    }

    match result {
        Ok((decision, detail)) => ScanReport {
            adapter: "command".to_string(),
            decision,
            detail,
        },
        Err(err) => ScanReport {
            adapter: "command".to_string(),
            decision: default_on_error,
            detail: format!("scanner command failed: {err}"),
        },
    }
}

#[derive(Debug, Serialize)]
struct WebhookScanRequest<'a> {
    filename: Option<&'a str>,
    content_type: Option<&'a str>,
    size_bytes: usize,
    sha256: &'a str,
    public_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct WebhookScanResponse {
    decision: ScanDecision,
    detail: Option<String>,
}

async fn run_webhook_scanner(
    url: &str,
    secret: Option<&str>,
    input: &ScanInput<'_>,
    default_on_error: ScanDecision,
) -> ScanReport {
    let client = reqwest::Client::new();
    let mut request = client.post(url).json(&WebhookScanRequest {
        filename: input.filename,
        content_type: input.content_type,
        size_bytes: input.size_bytes.max(0) as usize,
        sha256: input.hash,
        public_id: input.public_id,
    });
    if let Some(secret) = secret {
        request = request.header("x-midden-scanner-secret", secret);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            match response.json::<WebhookScanResponse>().await {
                Ok(decoded) => ScanReport {
                    adapter: "webhook".to_string(),
                    decision: decoded.decision,
                    detail: decoded
                        .detail
                        .unwrap_or_else(|| "webhook completed".to_string()),
                },
                Err(err) => ScanReport {
                    adapter: "webhook".to_string(),
                    decision: default_on_error,
                    detail: format!("invalid webhook response: {err}"),
                },
            }
        }
        Ok(response) => ScanReport {
            adapter: "webhook".to_string(),
            decision: default_on_error,
            detail: format!("webhook returned HTTP {}", response.status()),
        },
        Err(err) => ScanReport {
            adapter: "webhook".to_string(),
            decision: default_on_error,
            detail: format!("webhook failed: {err}"),
        },
    }
}

async fn run_clamav_scanner(
    socket: &str,
    input: &ScanInput<'_>,
    default_on_error: ScanDecision,
) -> ScanReport {
    let result = if socket.contains(':') {
        scan_clamav_tcp(socket, input).await
    } else {
        scan_clamav_unix(socket, input).await
    };

    match result {
        Ok(detail) => {
            let decision = if detail.contains("FOUND") {
                ScanDecision::Reject
            } else if detail.contains("OK") {
                ScanDecision::Allow
            } else {
                default_on_error
            };
            ScanReport {
                adapter: "clamav".to_string(),
                decision,
                detail,
            }
        }
        Err(err) => ScanReport {
            adapter: "clamav".to_string(),
            decision: default_on_error,
            detail: format!("clamav scan failed: {err}"),
        },
    }
}

async fn scan_clamav_tcp(addr: &str, input: &ScanInput<'_>) -> anyhow::Result<String> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    write_clamav_instream(&mut stream, input).await?;
    read_clamav_response(&mut stream).await
}

#[cfg(unix)]
async fn scan_clamav_unix(path: &str, input: &ScanInput<'_>) -> anyhow::Result<String> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    write_clamav_instream(&mut stream, input).await?;
    read_clamav_response(&mut stream).await
}

#[cfg(not(unix))]
async fn scan_clamav_unix(_path: &str, _input: &ScanInput<'_>) -> anyhow::Result<String> {
    anyhow::bail!("unix ClamAV sockets are not supported on this platform")
}

async fn write_input_to_path(input: &ScanInput<'_>, path: &Path) -> anyhow::Result<()> {
    if let Some(bytes) = input.bytes {
        tokio::fs::write(path, bytes).await?;
        return Ok(());
    }
    if let Some(source) = input.path {
        tokio::fs::copy(source, path).await?;
        return Ok(());
    }
    anyhow::bail!("scanner input has no bytes or path")
}

async fn write_clamav_instream<W>(stream: &mut W, input: &ScanInput<'_>) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    stream.write_all(b"zINSTREAM\0").await?;
    if let Some(bytes) = input.bytes {
        for chunk in bytes.chunks(1024 * 1024) {
            write_clamav_chunk(stream, chunk).await?;
        }
    } else if let Some(path) = input.path {
        let mut file = tokio::fs::File::open(path).await?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            write_clamav_chunk(stream, &buffer[..read]).await?;
        }
    } else {
        anyhow::bail!("scanner input has no bytes or path");
    }
    stream.write_all(&0_u32.to_be_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_clamav_chunk<W>(stream: &mut W, chunk: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    stream
        .write_all(&(chunk.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(chunk).await?;
    Ok(())
}

async fn read_clamav_response<R>(stream: &mut R) -> anyhow::Result<String>
where
    R: AsyncReadExt + Unpin,
{
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).trim().to_string())
}

fn scanner_temp_path(temp_dir: Option<&Path>, public_id: &str) -> PathBuf {
    let base = temp_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!("midden-scan-{public_id}-{}", util::public_id()))
}

fn expand_arg(arg: &str, input: &ScanInput<'_>, path: &Path) -> String {
    let values = BTreeMap::from([
        ("path", path.to_string_lossy().to_string()),
        ("filename", input.filename.unwrap_or("").to_string()),
        ("content_type", input.content_type.unwrap_or("").to_string()),
        ("sha256", input.hash.to_string()),
        ("public_id", input.public_id.to_string()),
    ]);
    values.iter().fold(arg.to_string(), |acc, (key, value)| {
        acc.replace(&format!("{{{key}}}"), value)
    })
}

fn decision_rank(decision: &ScanDecision) -> u8 {
    match decision {
        ScanDecision::Allow => 0,
        ScanDecision::Quarantine => 1,
        ScanDecision::Reject => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hung_adapter_falls_back_instead_of_blocking_the_upload() {
        // A TCP listener that accepts and then never answers, standing in for a wedged clamd.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let config = ScanningConfig {
            enabled: true,
            adapters: vec![ScannerAdapterConfig::ClamAv {
                socket: addr.to_string(),
            }],
            default_on_error: ScanDecision::Quarantine,
            timeout_seconds: 1,
            ..ScanningConfig::default()
        };
        let bytes = Bytes::from_static(b"hello");
        let summary = scan_upload(
            &config,
            ScanInput {
                bytes: Some(&bytes),
                path: None,
                size_bytes: bytes.len() as i64,
                filename: Some("hello.txt"),
                content_type: Some("text/plain"),
                hash: "abc",
                public_id: "id",
                temp_dir: None,
            },
        )
        .await;

        assert_eq!(summary.decision, ScanDecision::Quarantine);
        assert!(
            summary.reports[0].detail.contains("timed out"),
            "unexpected detail: {}",
            summary.reports[0].detail
        );
    }

    #[tokio::test]
    async fn disabled_scanning_allows_without_reports() {
        let config = ScanningConfig::default();
        let bytes = Bytes::from_static(b"hello");
        let summary = scan_upload(
            &config,
            ScanInput {
                bytes: Some(&bytes),
                path: None,
                size_bytes: bytes.len() as i64,
                filename: Some("hello.txt"),
                content_type: Some("text/plain"),
                hash: "abc",
                public_id: "id",
                temp_dir: None,
            },
        )
        .await;
        assert_eq!(summary.decision, ScanDecision::Allow);
        assert!(summary.reports.is_empty());
    }
}
