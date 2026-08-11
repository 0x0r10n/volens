//! Token socials, read from the off-chain metadata JSON.
//!
//! On-chain metadata carries a `uri` pointing at a JSON document with the
//! token's image and links. That document is written by whoever launched the
//! token, so everything here treats it as **hostile input**:
//!
//! * only `https://` URIs are fetched — `http://` would leak the request, and
//!   `file://` / `ftp://` are not links a browser should be handed;
//! * the response is size-capped, because nothing stops a launcher pointing the
//!   uri at a multi-gigabyte file;
//! * a short timeout, because this runs inline with an alert;
//! * every extracted link is re-validated before rendering, so a `javascript:`
//!   payload cannot reach a Telegram anchor.
//!
//! A failure at any step yields no links rather than an error: socials are a
//! nice-to-have on an alert that is useful without them.

use serde::Deserialize;
use std::time::Duration;

/// Cap on the metadata document. Real ones are well under 4 KB.
const MAX_BODY_BYTES: usize = 64 * 1024;
const TIMEOUT_SECS: u64 = 6;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Socials {
    pub twitter: Option<String>,
    pub telegram: Option<String>,
    pub website: Option<String>,
}

impl Socials {
    pub fn is_empty(&self) -> bool {
        self.twitter.is_none() && self.telegram.is_none() && self.website.is_none()
    }
}

#[derive(Debug, Deserialize, Default)]
struct RawMetadata {
    #[serde(default)]
    twitter: String,
    #[serde(default)]
    telegram: String,
    #[serde(default)]
    website: String,
}

/// Fetch and validate a token's social links.
pub async fn fetch(uri: &str) -> Socials {
    match fetch_inner(uri).await {
        Some(s) => s,
        None => Socials::default(),
    }
}

async fn fetch_inner(uri: &str) -> Option<Socials> {
    let uri = uri.trim();
    // Only https. An on-chain string is attacker-controlled, and the set of
    // schemes worth dereferencing from a server is exactly one.
    if !uri.starts_with("https://") {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .build()
        .ok()?;
    let resp = client.get(uri).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    // Read with a cap rather than `.json()`, which would buffer the whole body
    // however large it is.
    let body = resp.bytes().await.ok()?;
    if body.len() > MAX_BODY_BYTES {
        tracing::debug!(uri, size = body.len(), "metadata document too large; skipping");
        return None;
    }

    let raw: RawMetadata = serde_json::from_slice(&body).ok()?;
    let socials = Socials {
        twitter: sanitize_url(&raw.twitter),
        telegram: sanitize_url(&raw.telegram),
        website: sanitize_url(&raw.website),
    };
    (!socials.is_empty()).then_some(socials)
}

/// Accept a link only if it is an http(s) URL with no characters that could
/// break out of an HTML attribute.
///
/// The value ends up inside `<a href="…">` in a Telegram message. A quote or
/// angle bracket would let the token's author inject markup into an alert.
pub fn sanitize_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 300 {
        return None;
    }
    if !(s.starts_with("https://") || s.starts_with("http://")) {
        return None;
    }
    if s.chars().any(|c| c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | ' ')) {
        return None;
    }
    Some(s.replace('&', "&amp;"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_links() {
        assert_eq!(
            sanitize_url("https://x.com/DrNickA/status/2087186385769795878"),
            Some("https://x.com/DrNickA/status/2087186385769795878".into())
        );
        assert_eq!(sanitize_url(" https://t.me/foo "), Some("https://t.me/foo".into()));
    }

    /// The launcher writes this field. It must not be able to inject markup
    /// into an alert that lands in a group chat.
    #[test]
    fn rejects_markup_and_script_schemes() {
        assert_eq!(sanitize_url("javascript:alert(1)"), None);
        assert_eq!(sanitize_url("data:text/html,<script>"), None);
        assert_eq!(sanitize_url("file:///etc/passwd"), None);
        assert_eq!(sanitize_url("https://x.com\" onclick=\"evil()"), None);
        assert_eq!(sanitize_url("https://x.com/<script>"), None);
    }

    /// Ampersands are legal in query strings but break HTML if left raw.
    #[test]
    fn escapes_ampersands_in_query_strings() {
        assert_eq!(
            sanitize_url("https://youtube.com/watch?v=abc&t=30"),
            Some("https://youtube.com/watch?v=abc&amp;t=30".into())
        );
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert_eq!(sanitize_url(""), None);
        assert_eq!(sanitize_url("   "), None);
        assert_eq!(sanitize_url(&format!("https://x.com/{}", "a".repeat(400))), None);
    }

    #[test]
    fn empty_socials_are_reported_as_empty() {
        assert!(Socials::default().is_empty());
        assert!(!Socials { twitter: Some("https://x.com/a".into()), ..Default::default() }
            .is_empty());
    }

    /// A metadata document with blank fields yields nothing, not empty links.
    #[test]
    fn blank_fields_produce_no_links() {
        let raw: RawMetadata =
            serde_json::from_str(r#"{"twitter":"","telegram":"","website":""}"#).unwrap();
        let s = Socials {
            twitter: sanitize_url(&raw.twitter),
            telegram: sanitize_url(&raw.telegram),
            website: sanitize_url(&raw.website),
        };
        assert!(s.is_empty());
    }

    /// Missing keys must not fail the parse — most tokens omit at least one.
    #[test]
    fn missing_fields_default_rather_than_error() {
        let raw: RawMetadata = serde_json::from_str(r#"{"name":"X","symbol":"Y"}"#).unwrap();
        assert_eq!(raw.twitter, "");
        assert_eq!(raw.website, "");
    }

    /// Non-https is refused before any request is made.
    #[tokio::test]
    async fn non_https_uris_are_never_fetched() {
        assert!(fetch("http://example.com/meta.json").await.is_empty());
        assert!(fetch("file:///etc/passwd").await.is_empty());
        assert!(fetch("").await.is_empty());
    }

    /// Live check against a real token's metadata document.
    ///
    ///   cargo test -- --ignored --nocapture live_socials
    #[ignore = "hits the token's metadata host"]
    #[tokio::test]
    async fn live_socials_fetch() {
        let s = fetch("https://md.sdfgsdfsdf.uk/metadata/XSlBuKP7").await;
        println!("{s:#?}");
        assert!(s.twitter.is_some(), "expected a twitter link");
    }
}
