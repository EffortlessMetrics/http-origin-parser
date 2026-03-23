# http-origin-parser

Single-responsibility parser for HTTP/HTTPS origin strings used by origin matching crates.

## Scope

- Parse `http://` and `https://` origins into schema + authority
- Reject malformed values (missing authority, path/query/fragment/userinfo, whitespace)
- Provide deterministic parsing primitives for higher-level rule matchers

## Why this crate exists

Origin matching crates should own matching semantics, not low-level origin string parsing.
This crate isolates strict parsing so wildcard and policy crates can share one audited parser.

## Usage

```rust
use http_origin_parser::{parse_http_origin, HttpOriginSchema};

// Parse a valid HTTPS origin
let parsed = parse_http_origin("https://api.example.com").unwrap();
assert_eq!(parsed.schema, HttpOriginSchema::Https);
assert_eq!(parsed.authority, "api.example.com");

// Parse an HTTP origin with port
let parsed = parse_http_origin("http://localhost:8080").unwrap();
assert_eq!(parsed.schema, HttpOriginSchema::Http);
assert_eq!(parsed.authority, "localhost:8080");

// Rejected: path suffix
assert_eq!(parse_http_origin("https://api.example.com/path"), None);

// Rejected: userinfo
assert_eq!(parse_http_origin("https://user@api.example.com"), None);

// Rejected: non-HTTP schema
assert_eq!(parse_http_origin("ftp://example.com"), None);
```

## Design Philosophy

This crate follows the Single Responsibility Principle:
- **One job**: Parse HTTP/HTTPS origin strings
- **No dependencies**: Zero external dependencies for core parsing
- **Deterministic**: Same input always produces same output
- **Auditable**: Small surface area for security review

## Testing

Includes both unit tests (in `src/lib.rs`) and integration tests (in `tests/`).
For fuzz testing, see the `fuzz/` directory.

## Fuzz Testing

```bash
cd fuzz
cargo fuzz run origin_parser
```
