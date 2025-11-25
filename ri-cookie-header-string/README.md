# ri-cookie-header-string

A Rust library for parsing HTTP Cookie header strings into structured cookie objects.

This crate provides an extension trait for the [`cookie`] crate that enables advanced parsing of cookie header strings (as received in HTTP `Cookie` headers) into a collection of [`Cookie`] objects.

**⚠️ Note**: This is a **non-standard, security-focused parser**. It provides advanced heuristics for handling unquoted cookie values that may contain semicolons, useful for real-world edge cases in non-standard cookie implementations. For standard RFC 6265-compliant parsing, use the built-in `SplitCookies` iterator from the `cookie` crate instead.

## Features

- **Smart semicolon handling**: Distinguishes between semicolons that separate cookies and semicolons that are part of cookie values, providing more accurate parsing than the standard `SplitCookies` iterator
- **Iterator-based parsing**: Lazy parsing that returns an iterator over parsed cookies
- **Error handling**: Returns `Result<Cookie, ParseError>` for each cookie, allowing graceful handling of malformed entries
- **Percent-encoding support**: Recommended to enable the `percent-encode` feature for proper handling of percent-encoded cookie values

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ri-cookie-header-string = "0.1"
cookie = "0.18"
```

It's recommended to enable the `percent-encode` feature:

```toml
[dependencies]
ri-cookie-header-string = { version = "0.1", features = ["percent-encode"] }
cookie = "0.18"
```

## Usage

### Basic Usage

```rust
use ri_cookie_header_string::CookieHeaderStringExt;
use cookie::Cookie;

let cookie_header = "name=value; name2=value2; name3=value3";
let cookies: Vec<_> = Cookie::header_string_parse(cookie_header)
    .filter_map(|result| result.ok())
    .collect();

assert_eq!(cookies.len(), 3);
```

### Handling Semicolons in Cookie Values

The library intelligently handles semicolons that appear within cookie values, providing more accurate parsing than the built-in `SplitCookies` iterator for non-standard cookie implementations:

```rust
use ri_cookie_header_string::CookieHeaderStringExt;
use cookie::Cookie;

// Semicolon inside unquoted value is preserved correctly
let cookie_header = "session=abc;123; other=value";
let cookies: Vec<_> = Cookie::header_string_parse(cookie_header)
    .filter_map(|result| result.ok())
    .collect();

assert_eq!(cookies.len(), 2);
assert_eq!(cookies[0].value(), "abc;123");
assert_eq!(cookies[1].value(), "value");
```

### Error Handling

Since parsing returns `Result<Cookie, ParseError>`, you can handle errors gracefully:

```rust
use ri_cookie_header_string::CookieHeaderStringExt;
use cookie::Cookie;

let cookie_header = "valid=value; invalid";
for result in Cookie::header_string_parse(cookie_header) {
    match result {
        Ok(cookie) => println!("Parsed: {}={}", cookie.name(), cookie.value()),
        Err(e) => eprintln!("Parse error: {:?}", e),
    }
}
```

### Using with Reqwest

When the `reqwest` feature is enabled, you can parse cookies for use with the `reqwest` HTTP client:

```toml
[dependencies]
ri-cookie-header-string = { version = "0.1", features = ["reqwest"] }
reqwest = { version = "0.12", features = ["cookies"] }
```

Usage:

```rust
use ri_cookie_header_string::reqwest_support::parse_for_reqwest;

let cookie_header = "session=abc123; user=john";
let cookies: Vec<_> = parse_for_reqwest(cookie_header)
    .filter_map(|result| result.ok())
    .collect();

// Add cookies to a reqwest cookie jar
let jar = reqwest::cookie::Jar::default();
let url = "https://example.com".parse().unwrap();
for cookie in cookies {
    jar.add_cookie_str(&cookie.to_string(), &url);
}
```

## Running Examples

The library includes examples demonstrating both `cookie` and `reqwest` usage:

```bash
# Basic cookie parsing example
cargo run --example cookie_usage

# Reqwest integration example
cargo run --example reqwest_usage --features reqwest
```
