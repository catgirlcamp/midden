use super::*;
use crate::db::PageCursor;

#[derive(Debug, Deserialize)]
pub(super) struct BrowseQuery {
    q: Option<String>,
    before_file: Option<String>,
    before_paste: Option<String>,
}

pub(super) async fn public_browse(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<BrowseQuery>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    if !settings.features.public_browse {
        return Err(AppError::NotFound);
    }
    let user = current_user(&state, &jar).await?;
    let limit = settings.discovery.page_size.clamp(1, 100) as i64;
    let q = query.q.as_deref().filter(|q| !q.trim().is_empty());

    // Files and pastes are paged by independent queries, so they need independent cursors. A
    // single shared cursor can only be wrong in one of two ways: advancing to the older boundary
    // skips whatever the denser list still had to show, and advancing to the newer one repeats
    // rows the sparser list already returned.
    let before_file = parse_cursor(query.before_file.as_deref())?;
    let before_paste = parse_cursor(query.before_paste.as_deref())?;
    let files = state
        .db
        .public_files(q, before_file.as_ref(), limit)
        .await?;
    let pastes = state
        .db
        .public_pastes(q, before_paste.as_ref(), limit)
        .await?;

    // An exhausted list keeps its previous cursor, so it stays exhausted rather than restarting
    // from the top and repeating its first page.
    let next_file_cursor = files
        .last()
        .map(|file| PageCursor {
            created_at: file.created_at,
            public_id: file.public_id.clone(),
        })
        .or(before_file);
    let next_paste_cursor = pastes
        .last()
        .map(|paste| PageCursor {
            created_at: paste.created_at,
            public_id: paste.public_id.clone(),
        })
        .or(before_paste);
    let has_more = files.len() as i64 >= limit || pastes.len() as i64 >= limit;
    let older_url =
        has_more.then(|| older_url(q, next_file_cursor.as_ref(), next_paste_cursor.as_ref()));

    render(
        &state,
        if htmx_request(&headers) {
            "browse_results.html"
        } else {
            "browse.html"
        },
        &settings,
        user.as_ref(),
        serde_json::json!({
            "q": query.q.unwrap_or_default(),
            "files": linked_files(&state, &settings, &files)?,
            "pastes": pastes,
            "older_url": older_url,
        }),
    )
}

fn parse_cursor(value: Option<&str>) -> AppResult<Option<PageCursor>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|()| AppError::BadRequest("invalid browse cursor".to_string()))
}

/// Builds the "older items" link. Values go through form encoding so a search term containing
/// `&` or `#` cannot truncate or rewrite the rest of the query string.
fn older_url(
    q: Option<&str>,
    next_file_cursor: Option<&PageCursor>,
    next_paste_cursor: Option<&PageCursor>,
) -> String {
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    if let Some(cursor) = next_file_cursor {
        pairs.append_pair("before_file", &cursor.to_string());
    }
    if let Some(cursor) = next_paste_cursor {
        pairs.append_pair("before_paste", &cursor.to_string());
    }
    if let Some(q) = q {
        pairs.append_pair("q", q);
    }
    format!("/browse?{}", pairs.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(created_at: i64, public_id: &str) -> PageCursor {
        PageCursor {
            created_at,
            public_id: public_id.to_string(),
        }
    }

    #[test]
    fn older_url_encodes_search_terms() {
        let url = older_url(Some("a&b=c#d"), Some(&cursor(10, "abc")), None);
        assert_eq!(url, "/browse?before_file=10.abc&q=a%26b%3Dc%23d");
    }

    #[test]
    fn older_url_omits_cursors_for_exhausted_listings() {
        assert_eq!(
            older_url(None, None, Some(&cursor(7, "xyz"))),
            "/browse?before_paste=7.xyz"
        );
    }

    #[test]
    fn blank_cursors_are_treated_as_absent_and_junk_is_rejected() {
        assert!(parse_cursor(Some("  ")).unwrap().is_none());
        assert!(parse_cursor(None).unwrap().is_none());
        assert_eq!(
            parse_cursor(Some("10.abc")).unwrap(),
            Some(cursor(10, "abc"))
        );
        assert!(parse_cursor(Some("not-a-cursor")).is_err());
    }
}
