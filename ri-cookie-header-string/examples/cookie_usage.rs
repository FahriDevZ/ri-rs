//! Example demonstrating basic cookie parsing with the `cookie` crate.

use cookie::Cookie;
use ri_cookie_header_string::CookieHeaderStringExt;

fn main() {
    // Example 1: Basic cookie parsing
    println!("=== Example 1: Basic Cookie Parsing ===");
    let cookie_header = "name=value; name2=value2; name3=value3";
    let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|result| result.ok()).collect();

    println!("Parsed {} cookies:", cookies.len());
    for cookie in &cookies {
        println!("  {} = {}", cookie.name(), cookie.value());
    }

    // Example 2: Handling semicolons in unquoted cookie values
    println!("\n=== Example 2: Semicolons in Values ===");
    let cookie_header = "session=abc;123; other=value";
    let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|result| result.ok()).collect();

    println!("Parsed {} cookies:", cookies.len());
    for cookie in &cookies {
        println!("  {} = {}", cookie.name(), cookie.value());
    }

    // Example 3: Complex values with special characters
    println!("\n=== Example 3: Special Characters ===");
    let cookie_header = "session=abc;def;ghi; token=!@#$%^&*()";
    let cookies: Vec<_> = Cookie::header_string_parse(cookie_header).filter_map(|result| result.ok()).collect();

    println!("Parsed {} cookies:", cookies.len());
    for cookie in &cookies {
        println!("  {} = {}", cookie.name(), cookie.value());
    }
}
