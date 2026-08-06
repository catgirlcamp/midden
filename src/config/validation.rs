use std::net::SocketAddr;

use super::*;

pub(super) fn validate(config: &AppConfig) -> anyhow::Result<()> {
    config
        .server
        .bind
        .parse::<SocketAddr>()
        .map_err(|err| anyhow::anyhow!("server.bind must be a socket address: {err}"))?;
    validate_base_url("server.public_base_url", &config.server.public_base_url)?;
    if config.server.behind_proxy && config.server.trusted_proxy_hops == 0 {
        anyhow::bail!("server.trusted_proxy_hops must be at least 1 when behind_proxy is enabled");
    }

    let database_url = config.database.url.trim().to_ascii_lowercase();
    if !database_url.starts_with("sqlite:")
        && !database_url.starts_with("postgres:")
        && !database_url.starts_with("postgresql:")
    {
        anyhow::bail!("database.url must use sqlite, postgres, or postgresql");
    }
    if config.database.max_connections == 0 {
        anyhow::bail!("database.max_connections must be greater than zero");
    }

    match config.storage.backend {
        StorageBackend::Local => {
            if config.storage.local.path.as_os_str().is_empty() {
                anyhow::bail!("storage.local.path must not be empty");
            }
        }
        StorageBackend::S3 => {
            if config.storage.s3.bucket.trim().is_empty() {
                anyhow::bail!("storage.s3.bucket is required for the s3 backend");
            }
            if let Some(endpoint) = nonempty_option(&config.storage.s3.endpoint) {
                let endpoint = validate_http_url("storage.s3.endpoint", endpoint)?;
                if endpoint.scheme() == "http" && !config.storage.s3.allow_http {
                    anyhow::bail!("storage.s3.allow_http must be true for an http S3 endpoint");
                }
            }
            validate_pair(
                "storage.s3.access_key_id",
                config.storage.s3.access_key_id.as_deref(),
                "storage.s3.secret_access_key",
                config.storage.s3.secret_access_key.as_deref(),
            )?;
        }
    }

    if config.features.accounts
        && !config.features.local_login
        && !(config.features.oidc_login && config.oidc.enabled)
    {
        anyhow::bail!("at least one account sign-in method must be enabled");
    }
    if config.features.oidc_login && !config.oidc.enabled {
        anyhow::bail!("features.oidc_login requires oidc.enabled");
    }

    require_positive("limits.max_upload_bytes", config.limits.max_upload_bytes)?;
    require_positive("limits.max_paste_bytes", config.limits.max_paste_bytes)?;
    validate_optional_nonnegative(
        "limits.anonymous_daily_bytes",
        config.limits.anonymous_daily_bytes,
    )?;
    validate_expiry(
        "limits.default_file_expiry",
        config.limits.default_file_expiry.as_deref(),
        config.limits.expiry.allow_never,
    )?;
    validate_expiry(
        "limits.default_paste_expiry",
        config.limits.default_paste_expiry.as_deref(),
        config.limits.expiry.allow_never,
    )?;
    validate_expiry_guardrails(&config.limits.expiry)?;
    validate_quota("limits.anonymous_quota", &config.limits.anonymous_quota)?;
    for (role, quota) in &config.limits.role_quotas {
        if !matches!(role.as_str(), "user" | "moderator" | "admin" | "owner") {
            anyhow::bail!("limits.role_quotas contains unknown role {role:?}");
        }
        validate_quota(&format!("limits.role_quotas.{role}"), quota)?;
    }

    if !matches!(
        config.branding.dark_mode.as_str(),
        "auto" | "light" | "dark"
    ) {
        anyhow::bail!("branding.dark_mode must be auto, light, or dark");
    }
    validate_css_color("branding.accent_color", &config.branding.accent_color)?;
    if config.security.session_cookie_name.trim().is_empty() {
        anyhow::bail!("security.session_cookie_name must not be empty");
    }
    require_positive(
        "security.session_ttl_seconds",
        config.security.session_ttl_seconds,
    )?;
    if config.security.content_policy.max_filename_bytes == 0 {
        anyhow::bail!("security.content_policy.max_filename_bytes must be greater than zero");
    }
    for value in config
        .security
        .content_policy
        .allowed_mime_types
        .iter()
        .chain(
            config
                .security
                .content_policy
                .forced_attachment_mime_types
                .iter(),
        )
    {
        value.parse::<mime::Mime>().map_err(|err| {
            anyhow::anyhow!("invalid MIME type {value:?} in security.content_policy: {err}")
        })?;
    }
    if config.security.url_upload.connect_timeout_seconds == 0
        || config.security.url_upload.request_timeout_seconds == 0
    {
        anyhow::bail!("URL upload timeouts must be greater than zero");
    }
    validate_optional_positive(
        "security.url_upload.max_response_bytes",
        config.security.url_upload.max_response_bytes,
    )?;
    for (action, limit) in &config.security.rate_limits {
        if action.trim().is_empty() {
            anyhow::bail!("security.rate_limits action names must not be empty");
        }
        if limit.enabled && (limit.requests == 0 || limit.window_seconds == 0) {
            anyhow::bail!(
                "enabled security.rate_limits.{action} requires positive requests and window_seconds"
            );
        }
    }

    if config.delivery.isolated_file_origin
        && nonempty_option(&config.delivery.public_file_base_url).is_none()
    {
        anyhow::bail!("isolated file origin requires a public file base URL");
    }
    if let Some(url) = nonempty_option(&config.delivery.public_file_base_url) {
        validate_base_url("delivery.public_file_base_url", url)?;
    }
    if config.delivery.signed_internal_urls
        && nonempty_option(&config.delivery.internal_url_secret).is_none()
    {
        anyhow::bail!("signed internal URLs require a secret");
    }
    require_positive(
        "delivery.internal_url_ttl_seconds",
        config.delivery.internal_url_ttl_seconds,
    )?;

    validate_smtp(&config.smtp)?;
    validate_oidc(&config.oidc)?;
    validate_scanning(&config.scanning)?;

    if config.processing.thumbnail_max_dimension == 0 {
        anyhow::bail!("processing.thumbnail_max_dimension must be greater than zero");
    }
    if config.processing.thumbnail_source_max_pixels == 0 {
        anyhow::bail!("processing.thumbnail_source_max_pixels must be greater than zero");
    }
    if config.processing.thumbnail_source_max_alloc_bytes == 0 {
        anyhow::bail!("processing.thumbnail_source_max_alloc_bytes must be greater than zero");
    }
    if !(1..=100).contains(&config.processing.thumbnail_jpeg_quality) {
        anyhow::bail!("processing.thumbnail_jpeg_quality must be between 1 and 100");
    }
    if !(1..=1000).contains(&config.discovery.page_size) {
        anyhow::bail!("discovery.page_size must be between 1 and 1000");
    }
    if config.jobs.interval_seconds < 30 {
        anyhow::bail!("jobs.interval_seconds must be at least 30");
    }
    if config.jobs.metadata_limit == 0 || config.jobs.scanner_retry_limit == 0 {
        anyhow::bail!("jobs batch limits must be greater than zero");
    }
    if config.jobs.storage_verify_interval_seconds < 60 {
        anyhow::bail!("jobs.storage_verify_interval_seconds must be at least 60");
    }
    if let Some(path) = &config.uploads.temp_dir
        && path.as_os_str().is_empty()
    {
        anyhow::bail!("uploads.temp_dir must not be empty");
    }
    if config.metrics.enabled
        && matches!(config.metrics.access, MetricsAccessMode::Token)
        && nonempty_option(&config.metrics.bearer_token).is_none()
    {
        anyhow::bail!("token-protected metrics require a bearer token");
    }
    validate_optional_positive(
        "tokens.default_ttl_seconds",
        config.tokens.default_ttl_seconds,
    )?;
    validate_optional_positive("tokens.max_ttl_seconds", config.tokens.max_ttl_seconds)?;
    if let (Some(default), Some(max)) = (
        config.tokens.default_ttl_seconds,
        config.tokens.max_ttl_seconds,
    ) && default > max
    {
        anyhow::bail!("tokens.default_ttl_seconds cannot exceed tokens.max_ttl_seconds");
    }
    if let Some(url) = nonempty_option(&config.moderation.notify_webhook_url) {
        validate_http_url("moderation.notify_webhook_url", url)?;
    }
    Ok(())
}

pub(super) fn validate_runtime_settings(
    config: &AppConfig,
    settings: &RuntimeSettings,
) -> anyhow::Result<()> {
    let mut candidate = config.clone();
    candidate.features = settings.features.clone();
    candidate.limits = settings.limits.clone();
    candidate.branding = settings.branding.clone();
    candidate.policy = settings.policy.clone();
    candidate.security = settings.security.clone();
    candidate.delivery = settings.delivery.clone();
    candidate.scanning = settings.scanning.clone();
    candidate.processing = settings.processing.clone();
    candidate.discovery = settings.discovery.clone();
    candidate.jobs = settings.jobs.clone();
    candidate.uploads = settings.uploads.clone();
    candidate.metrics = settings.metrics.clone();
    candidate.tokens = settings.tokens.clone();
    candidate.moderation = settings.moderation.clone();
    validate(&candidate)
}
fn nonempty_option(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Checks that a value is safe to interpolate into a CSS declaration.
///
/// The accent color lands inside a `<style>` block, where HTML escaping does nothing useful: the
/// CSS parser never decodes entities. Without this, anyone who can reach the admin settings form
/// could close the declaration and append rules that run for every visitor.
fn validate_css_color(label: &str, value: &str) -> anyhow::Result<()> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{label} must not be empty");
    }
    if value.len() > 64 {
        anyhow::bail!("{label} must be at most 64 characters");
    }
    // `/` is permitted for the modern `oklch(l c h / alpha)` form. `*` is not, so `/*` cannot
    // start a comment, and `;`, `{`, `}` cannot end the declaration or open a new rule.
    let allowed = |character: char| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '#' | '(' | ')' | ',' | '.' | '%' | '-' | '+' | '/'
            )
    };
    if let Some(character) = value.chars().find(|character| !allowed(*character)) {
        anyhow::bail!(
            "{label} contains a character that is not valid in a CSS color: {character:?}"
        );
    }
    Ok(())
}

fn validate_http_url(label: &str, value: &str) -> anyhow::Result<url::Url> {
    let parsed = url::Url::parse(value)
        .map_err(|err| anyhow::anyhow!("{label} must be an absolute URL: {err}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        anyhow::bail!("{label} must use http or https and include a host");
    }
    Ok(parsed)
}

fn validate_base_url(label: &str, value: &str) -> anyhow::Result<()> {
    let parsed = validate_http_url(label, value)?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("{label} must not contain a query string or fragment");
    }
    Ok(())
}

fn validate_pair(
    left_label: &str,
    left: Option<&str>,
    right_label: &str,
    right: Option<&str>,
) -> anyhow::Result<()> {
    let left = left.map(str::trim).filter(|value| !value.is_empty());
    let right = right.map(str::trim).filter(|value| !value.is_empty());
    if left.is_some() != right.is_some() {
        anyhow::bail!("{left_label} and {right_label} must be configured together");
    }
    Ok(())
}

fn require_positive(label: &str, value: i64) -> anyhow::Result<()> {
    if value <= 0 {
        anyhow::bail!("{label} must be greater than zero");
    }
    Ok(())
}

fn validate_optional_positive(label: &str, value: Option<i64>) -> anyhow::Result<()> {
    if let Some(value) = value {
        require_positive(label, value)?;
    }
    Ok(())
}

fn validate_optional_nonnegative(label: &str, value: Option<i64>) -> anyhow::Result<()> {
    if value.is_some_and(|value| value < 0) {
        anyhow::bail!("{label} must not be negative");
    }
    Ok(())
}

fn validate_quota(label: &str, quota: &QuotaConfig) -> anyhow::Result<()> {
    validate_optional_nonnegative(&format!("{label}.storage_bytes"), quota.storage_bytes)?;
    validate_optional_nonnegative(
        &format!("{label}.daily_upload_bytes"),
        quota.daily_upload_bytes,
    )?;
    validate_optional_nonnegative(
        &format!("{label}.monthly_upload_bytes"),
        quota.monthly_upload_bytes,
    )?;
    validate_optional_nonnegative(&format!("{label}.item_count"), quota.item_count)
}

fn validate_expiry_guardrails(expiry: &ExpiryGuardrailsConfig) -> anyhow::Result<()> {
    for (label, value) in [
        (
            "limits.expiry.anonymous_max_file_expiry",
            expiry.anonymous_max_file_expiry.as_deref(),
        ),
        (
            "limits.expiry.user_max_file_expiry",
            expiry.user_max_file_expiry.as_deref(),
        ),
        (
            "limits.expiry.anonymous_max_paste_expiry",
            expiry.anonymous_max_paste_expiry.as_deref(),
        ),
        (
            "limits.expiry.user_max_paste_expiry",
            expiry.user_max_paste_expiry.as_deref(),
        ),
    ] {
        validate_expiry(label, value, false)?;
    }
    for preset in &expiry.allowed_presets {
        validate_expiry(
            "limits.expiry.allowed_presets",
            Some(preset),
            expiry.allow_never,
        )?;
    }
    Ok(())
}

fn validate_expiry(label: &str, value: Option<&str>, allow_never: bool) -> anyhow::Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if value.eq_ignore_ascii_case("never") {
        if allow_never {
            return Ok(());
        }
        anyhow::bail!("{label} cannot be never");
    }
    crate::util::parse_expiry(Some(value))
        .map_err(|err| anyhow::anyhow!("{label} has an invalid expiry value: {err}"))?;
    Ok(())
}

fn validate_smtp(smtp: &SmtpConfig) -> anyhow::Result<()> {
    if !smtp.enabled {
        return Ok(());
    }
    let host = nonempty_option(&smtp.host)
        .ok_or_else(|| anyhow::anyhow!("smtp.host is required when SMTP is enabled"))?;
    if host.chars().any(char::is_whitespace) {
        anyhow::bail!("smtp.host must not contain whitespace");
    }
    let _ = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(host)
        .map_err(|err| anyhow::anyhow!("smtp.host is invalid: {err}"))?;
    if smtp.port == Some(0) {
        anyhow::bail!("smtp.port must be greater than zero");
    }
    validate_pair(
        "smtp.username",
        smtp.username.as_deref(),
        "smtp.password",
        smtp.password.as_deref(),
    )?;
    let from = nonempty_option(&smtp.from)
        .ok_or_else(|| anyhow::anyhow!("smtp.from is required when SMTP is enabled"))?;
    from.parse::<lettre::message::Mailbox>()
        .map_err(|err| anyhow::anyhow!("smtp.from is not a valid mailbox: {err}"))?;
    Ok(())
}

fn validate_oidc(oidc: &OidcConfig) -> anyhow::Result<()> {
    if !oidc.enabled {
        return Ok(());
    }
    let issuer = nonempty_option(&oidc.issuer_url)
        .ok_or_else(|| anyhow::anyhow!("oidc.issuer_url is required when OIDC is enabled"))?;
    validate_base_url("oidc.issuer_url", issuer)?;
    if nonempty_option(&oidc.client_id).is_none() {
        anyhow::bail!("oidc.client_id is required when OIDC is enabled");
    }
    if let Some(redirect) = nonempty_option(&oidc.redirect_url) {
        validate_base_url("oidc.redirect_url", redirect)?;
    }
    for role in oidc.role_mappings.values() {
        if !matches!(role.as_str(), "user" | "moderator" | "admin" | "owner") {
            anyhow::bail!("oidc.role_mappings contains invalid role {role:?}");
        }
    }
    Ok(())
}

fn validate_scanning(scanning: &ScanningConfig) -> anyhow::Result<()> {
    if scanning.timeout_seconds == 0 {
        anyhow::bail!("scanning.timeout_seconds must be greater than zero");
    }
    for adapter in &scanning.adapters {
        match adapter {
            ScannerAdapterConfig::ClamAv { socket } if socket.trim().is_empty() => {
                anyhow::bail!("ClamAV scanner socket must not be empty");
            }
            ScannerAdapterConfig::Command { program, .. } if program.trim().is_empty() => {
                anyhow::bail!("command scanner program must not be empty");
            }
            ScannerAdapterConfig::Webhook { url, .. } => {
                validate_http_url("webhook scanner URL", url)?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_colors_accept_the_shapes_the_ui_offers() {
        for value in [
            "oklch(0.44 0.12 235)",
            "oklch(0.44 0.12 235 / 50%)",
            "#4488cc",
            "rebeccapurple",
            "rgb(12, 34, 56)",
        ] {
            validate_css_color("accent", value).unwrap_or_else(|err| panic!("{value:?}: {err}"));
        }
    }

    #[test]
    fn css_colors_reject_attempts_to_escape_the_declaration() {
        for value in [
            "red; } body { display: none",
            "red /* comment */",
            "red\"",
            "url('x')",
            "var(--x); @import 'evil'",
        ] {
            assert!(
                validate_css_color("accent", value).is_err(),
                "{value:?} should not be accepted"
            );
        }
        assert!(validate_css_color("accent", "").is_err());
        assert!(validate_css_color("accent", &"a".repeat(65)).is_err());
    }
}
