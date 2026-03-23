//! HTTP/HTTPS origin parser primitives used by CORS allowlist matchers.
//!
//! This crate is intentionally tiny and framework-agnostic.

#![forbid(unsafe_code)]

/// Supported schemas for parsed origins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOriginSchema {
    /// `http://`
    Http,
    /// `https://`
    Https,
}

impl HttpOriginSchema {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http://",
            Self::Https => "https://",
        }
    }
}

/// Parsed components of an HTTP/HTTPS origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedHttpOrigin<'a> {
    /// Parsed schema.
    pub schema: HttpOriginSchema,
    /// Authority component (host or host:port).
    pub authority: &'a str,
}

/// Parse an HTTP/HTTPS origin into schema and authority.
///
/// Accepted form:
/// - `http://<authority>`
/// - `https://<authority>`
///
/// Rejected values include:
/// - Non-HTTP schemas
/// - Missing authority
/// - Path/query/fragment suffixes
/// - Userinfo (`@`)
/// - ASCII whitespace
pub fn parse_http_origin(value: &str) -> Option<ParsedHttpOrigin<'_>> {
    let (schema, authority) =
        if let Some(rest) = value.strip_prefix(HttpOriginSchema::Https.as_str()) {
            (HttpOriginSchema::Https, rest)
        } else if let Some(rest) = value.strip_prefix(HttpOriginSchema::Http.as_str()) {
            (HttpOriginSchema::Http, rest)
        } else {
            return None;
        };

    if authority.is_empty() {
        return None;
    }

    if authority.chars().any(|ch| matches!(ch, '/' | '?' | '#' | '@')) {
        return None;
    }

    if authority.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }

    Some(ParsedHttpOrigin { schema, authority })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_origin() {
        let parsed = parse_http_origin("https://api.example.com").unwrap();
        assert_eq!(parsed.schema, HttpOriginSchema::Https);
        assert_eq!(parsed.authority, "api.example.com");
    }

    #[test]
    fn parses_http_origin_with_port() {
        let parsed = parse_http_origin("http://localhost:8080").unwrap();
        assert_eq!(parsed.schema, HttpOriginSchema::Http);
        assert_eq!(parsed.authority, "localhost:8080");
    }

    #[test]
    fn rejects_non_http_schema() {
        assert_eq!(parse_http_origin("ftp://example.com"), None);
    }

    #[test]
    fn rejects_missing_authority() {
        assert_eq!(parse_http_origin("https://"), None);
    }

    #[test]
    fn rejects_path_query_and_fragment_suffixes() {
        assert_eq!(parse_http_origin("https://api.example.com/path"), None);
        assert_eq!(parse_http_origin("https://api.example.com?debug=true"), None);
        assert_eq!(parse_http_origin("https://api.example.com#section"), None);
    }

    #[test]
    fn rejects_userinfo() {
        assert_eq!(parse_http_origin("https://user@api.example.com"), None);
    }

    #[test]
    fn rejects_whitespace() {
        assert_eq!(parse_http_origin("https://api.example.com "), None);
        assert_eq!(parse_http_origin(" https://api.example.com"), None);
    }
}
