//! A library for parsing HTTP Cookie header strings into structured cookie objects.
//!
//! This crate provides extension traits for parsing cookie header strings into structured cookie objects.
//! It supports multiple cookie implementations including the [`cookie`] crate and optionally [`reqwest`].
//!
//! **Note**: This is a **non-standard, security-focused parser**. Unlike the standard `SplitCookies` iterator
//! and RFC 6265 compliance, this library provides smarter parsing for unquoted cookie values that may contain
//! semicolons. This is useful for handling cookie values that aren't properly quoted or encoded in non-standard
//! cookie implementations, providing additional safety when parsing untrusted cookie headers.
//!
//! # Features
//!
//! - **Advanced semicolon handling**: Distinguishes between semicolons that are cookie separators
//!   and semicolons that appear within unquoted cookie values
//! - **Iterator-based parsing**: Lazy evaluation returns an iterator over parsed cookies
//! - **Error handling**: Returns `Result<Cookie, ParseError>` for each cookie, allowing
//!   graceful handling of malformed entries
//! - **Percent-encoding support**: Enable the `percent-encode` feature to decode percent-encoded
//!   cookie values (e.g., `%20` for space)
//! - **Multiple cookie implementations**: Support for `cookie` crate and optionally `reqwest` via feature flag
//!
//! # When to Use This Library
//!
//! Use this library when:
//! - Parsing non-standard cookie headers with unquoted values containing semicolons
//! - You need safety when handling untrusted cookie input with unusual formatting
//! - Your application requires advanced heuristics to detect cookie boundaries
//! - You work with different cookie implementations across your project
//!
//! **Note**: For standard RFC 6265-compliant cookie parsing, the built-in `cookie` crate
//! provides `SplitCookies` which is more performant and spec-compliant.
//!
//! # Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ri-cookie-header-string = "0.2"
//! cookie = "0.18"
//! ```
//!
//! It's recommended to enable the `percent-encode` feature:
//!
//! ```toml
//! [dependencies]
//! ri-cookie-header-string = { version = "0.2", features = ["percent-encode"] }
//! cookie = "0.18"
//! ```
//!
//! For reqwest support, enable the `reqwest` feature:
//!
//! ```toml
//! [dependencies]
//! ri-cookie-header-string = { version = "0.2", features = ["reqwest"] }
//! reqwest = { version = "0.12", features = ["cookies"] }
//! ```
//!
//! # Examples
//!
//! Basic usage with `cookie` crate:
//!
//! ```
//! use ri_cookie_header_string::CookieHeaderStringExt;
//! use cookie::Cookie;
//!
//! let cookie_header = "name=value; name2=value2; name3=value3";
//! let cookies: Vec<_> = Cookie::header_string_parse(cookie_header)
//!     .filter_map(|result| result.ok())
//!     .collect();
//!
//! assert_eq!(cookies.len(), 3);
//! ```
//!
//! Handling semicolons in unquoted cookie values:
//!
//! ```
//! use ri_cookie_header_string::CookieHeaderStringExt;
//! use cookie::Cookie;
//!
//! // Semicolon inside unquoted value is preserved correctly
//! let cookie_header = "session=abc;123; other=value";
//! let cookies: Vec<_> = Cookie::header_string_parse(cookie_header)
//!     .filter_map(|result| result.ok())
//!     .collect();
//!
//! assert_eq!(cookies.len(), 2);
//! assert_eq!(cookies[0].value(), "abc;123");
//! assert_eq!(cookies[1].value(), "value");
//! ```

use cookie::{Cookie, ParseError};
use std::borrow::Cow;

/// Internal trait for abstracting cookie construction across different cookie implementations.
///
/// This trait allows the parser to work with different cookie types (e.g., `cookie::Cookie`,
/// `reqwest::cookie::Cookie`) by providing a common interface for creating cookies.
pub trait CookieBuilder: Sized {
    /// Create a new cookie with the given name and value.
    fn new(name: String, value: String) -> Self;

    /// Create a cookie from a percent-encoded string.
    ///
    /// This is only called when the `percent-encode` feature is enabled
    /// and the cookie value contains `%` characters.
    #[cfg(feature = "percent-encode")]
    fn parse_encoded(cookie_str: String) -> Result<Self, ParseError>;
}

/// Iterator over cookies in a header string.
///
/// This iterator provides advanced parsing for non-standard cookie headers with unquoted
/// values that may contain semicolons. It's not strictly RFC 6265 compliant but handles
/// real-world edge cases in cookie parsing.
///
/// Based on the `cookie` crate's `SplitCookies` iterator with enhanced heuristics.
pub struct HeaderStringCookies<'c, C: CookieBuilder> {
    // The source string, which we split and parse.
    string: Cow<'c, str>,
    // The index where we last split off.
    last: usize,
    // Phantom data to hold the cookie builder type
    _phantom: std::marker::PhantomData<C>,
}

/// Helper: check if byte can start a cookie name (alphanumeric or underscore).
///
/// Used for heuristic detection of cookie boundaries when disambiguating
/// whether a semicolon is a separator or part of a value.
#[inline(always)]
fn is_cookie_name_start(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_')
}

impl<'c, C: CookieBuilder> Iterator for HeaderStringCookies<'c, C> {
    type Item = Result<C, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let s = self.string.as_ref();
        let len = s.len();

        while self.last < len {
            let i = self.last;

            let j = s[i..].find(';').map(|k| i + k).unwrap_or(len);

            // Check if this semicolon is actually a separator or part of value
            let end_pos = if j < len {
                // Look ahead to determine if semicolon is separator
                let after = &s[j + 1..];
                let trimmed = after.trim_start();

                // Semicolon is separator if:
                // 1. Followed by whitespace/semicolon only, OR
                // 2. Followed by a valid cookie name (starts with alnum/underscore) and then '='
                if trimmed.is_empty() || trimmed.starts_with(';') {
                    j // Separator
                } else if let Some(first) = trimmed.as_bytes().first().copied() {
                    if is_cookie_name_start(first) {
                        // Check if followed by '=' (indicating new cookie)
                        if let Some(eq_pos) = trimmed.find('=') {
                            let name_part = &trimmed[..eq_pos].trim();
                            // Valid cookie name before '=' means this is a new cookie
                            if !name_part.is_empty()
                                && name_part.chars().all(|c| {
                                    let b = c as u8;
                                    matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'-')
                                })
                            {
                                j // Separator - new cookie starts here
                            } else {
                                // Not a valid cookie, semicolon is part of value - find next real separator
                                self.find_real_separator(j)
                            }
                        } else {
                            // No '=' found, semicolon is part of value
                            self.find_real_separator(j)
                        }
                    } else {
                        // Doesn't start with valid cookie char, semicolon is part of value
                        self.find_real_separator(j)
                    }
                } else {
                    j // End of string
                }
            } else {
                j // No semicolon found, end of string
            };

            self.last = end_pos + 1;

            let cookie_str = s[i..end_pos].trim();

            // Skip empty cookies
            if cookie_str.is_empty() {
                continue;
            }

            // Find '=' separator
            let eq_pos = match cookie_str.find('=') {
                Some(p) => p,
                None => continue,
            };

            let name = cookie_str[..eq_pos].trim();
            let val = cookie_str[eq_pos + 1..].trim();

            if name.is_empty() {
                continue;
            }

            // Create cookie - using owned strings for compatibility across implementations
            let cookie_result = if val.contains('%') {
                #[cfg(feature = "percent-encode")]
                {
                    // Build the cookie string for percent-decoding
                    let mut cookie_str_buf = String::with_capacity(name.len() + val.len() + 1);
                    cookie_str_buf.push_str(name);
                    cookie_str_buf.push('=');
                    cookie_str_buf.push_str(val);
                    C::parse_encoded(cookie_str_buf)
                }
                #[cfg(not(feature = "percent-encode"))]
                {
                    // Without percent-encode feature, treat % as literal character
                    Ok(C::new(name.to_string(), val.to_string()))
                }
            } else {
                Ok(C::new(name.to_string(), val.to_string()))
            };

            return Some(cookie_result);
        }

        None
    }
}

impl<'c, C: CookieBuilder> HeaderStringCookies<'c, C> {
    /// Find the real cookie separator when a semicolon appears within an unquoted value.
    ///
    /// This method uses heuristics to determine if a semicolon is a cookie separator
    /// (indicating the start of a new cookie) or part of the current cookie's value.
    /// It looks ahead for patterns that indicate a new cookie boundary.
    #[inline]
    fn find_real_separator(&self, start: usize) -> usize {
        let s = self.string.as_ref();
        let bytes = s.as_bytes();
        let len = s.len();
        let mut i = start + 1;

        // Skip whitespace
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        // Look for next semicolon that's a real separator
        while i < len {
            if bytes[i] == b';' {
                let mut j = i + 1;
                while j < len && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }

                if j >= len || bytes[j] == b';' {
                    return i; // Real separator
                }

                // Check if followed by new cookie
                if j < len && is_cookie_name_start(bytes[j]) {
                    let mut k = j;
                    while k < len && matches!(bytes[k], b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'-') {
                        k += 1;
                    }
                    if k < len && bytes[k] == b'=' {
                        return i; // Real separator - new cookie found
                    }
                }
            }
            i += 1;
        }

        len // No separator found, end of string
    }
}

pub trait CookieHeaderStringExt<'c, C: CookieBuilder> {
    fn header_string_parse<S>(string: S) -> HeaderStringCookies<'c, C>
    where
        S: Into<Cow<'c, str>>;
}

/// Implementation of CookieBuilder for `cookie::Cookie`
impl CookieBuilder for Cookie<'static> {
    fn new(name: String, value: String) -> Self {
        Cookie::new(name, value)
    }

    #[cfg(feature = "percent-encode")]
    fn parse_encoded(cookie_str: String) -> Result<Self, ParseError> {
        Cookie::parse_encoded(cookie_str)
    }
}

impl<'c> CookieHeaderStringExt<'c, Cookie<'static>> for Cookie<'c> {
    #[inline(always)]
    fn header_string_parse<S>(string: S) -> HeaderStringCookies<'c, Cookie<'static>>
    where
        S: Into<Cow<'c, str>>,
    {
        HeaderStringCookies {
            string: string.into(),
            last: 0,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Optional support for reqwest integration when `reqwest` feature is enabled.
#[cfg(feature = "reqwest")]
pub mod reqwest_support {
    use super::*;

    /// Parse a cookie header string into cookies compatible with reqwest.
    ///
    /// This function parses HTTP Cookie header strings into `cookie::Cookie` objects
    /// that can be used with reqwest. Since `reqwest::cookie::Cookie` is a read-only
    /// wrapper, we work with the underlying `cookie::Cookie` type.
    ///
    /// # Example
    ///
    /// ```text
    /// use ri_cookie_header_string::reqwest_support::parse_for_reqwest;
    /// use url::Url;
    ///
    /// let cookie_header = "session=abc123; user=john";
    /// let cookies: Vec<_> = parse_for_reqwest(cookie_header)
    ///     .filter_map(|result| result.ok())
    ///     .collect();
    ///
    /// // Use with reqwest cookie jar
    /// let jar = reqwest::cookie::Jar::default();
    /// let url: Url = "https://example.com".parse().unwrap();
    /// for cookie in cookies {
    ///     // Cookies can be serialized and added to jar
    ///     jar.add_cookie_str(&cookie.to_string(), &url);
    /// }
    /// ```
    pub fn parse_for_reqwest<'c, S>(string: S) -> HeaderStringCookies<'c, Cookie<'static>>
    where
        S: Into<Cow<'c, str>>,
    {
        HeaderStringCookies {
            string: string.into(),
            last: 0,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_string_parse() {
        let cases = [
            ("", vec![]),
            (";;", vec![]),
            ("name=val;ue", vec![("name", "val;ue")]),
            ("name=val;ue;hello=world", vec![("name", "val;ue"), ("hello", "world")]),
        ];

        for (string, expected) in cases {
            let cookies: Vec<_> = Cookie::header_string_parse(string).filter_map(|parse| parse.ok()).collect();

            let actual: Vec<_> = cookies.iter().map(|c| c.name_value()).collect();

            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn header_string_parse_empty_values() {
        let cookie_header = "name=; other=value";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value(), "");
        assert_eq!(cookies[1].value(), "value");
    }

    #[test]
    fn header_string_parse_whitespace_handling() {
        let cookie_header = "  name  =  value  ;  other  =  val  ";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name_value(), ("name", "value"));
        assert_eq!(cookies[1].name_value(), ("other", "val"));
    }

    #[test]
    fn header_string_parse_multiple_consecutive_semicolons() {
        let cookie_header = "name=;;;value;;;other=val";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        // Multiple semicolons create empty entries which are skipped
        assert!(!cookies.is_empty());
    }

    #[test]
    fn header_string_parse_special_characters() {
        let cookie_header = "session=!@#$%^&*(){}[]; other=value";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value(), "!@#$%^&*(){}[]");
    }

    #[test]
    fn header_string_parse_value_with_equals() {
        let cookie_header = "session=abc=123; other=value";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value(), "abc=123");
    }

    #[test]
    fn header_string_parse_long_values() {
        let long_value = "x".repeat(1000);
        let cookie_header = format!("name={long_value}; other=val");
        let cookies: Vec<_> = Cookie::header_string_parse(&cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value().len(), 1000);
    }

    #[test]
    fn header_string_parse_complex_semicolons() {
        let cookie_header = "session=abc;def;ghi; other=value";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value(), "abc;def;ghi");
        assert_eq!(cookies[1].value(), "value");
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn header_string_parse_percent_encoded() {
        let cookie_header = "name=val%20ue";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name_value(), ("name", "val ue"));
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn header_string_parse_percent_encoded_semicolon() {
        let cookie_header = "name=val%3B123; other=value";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value(), "val;123");
    }

    #[test]
    fn header_string_parse_numeric_names() {
        let cookie_header = "123=value; _456=other";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name(), "123");
    }

    #[test]
    fn header_string_parse_hyphenated_names() {
        let cookie_header = "session-id=value; other-val=data";
        let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|parse| parse.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name(), "session-id");
    }

    #[test]
    #[cfg(feature = "reqwest")]
    fn header_string_parse_reqwest() {
        use crate::reqwest_support::parse_for_reqwest;

        let cookie_header = "session=abc;123; other=value";
        let cookies: Vec<_> = parse_for_reqwest(cookie_header).filter_map(|result| result.ok()).collect();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value(), "abc;123");
        assert_eq!(cookies[1].value(), "value");
    }
}
