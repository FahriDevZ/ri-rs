//! Example demonstrating cookie parsing for use with reqwest.
//!
//! Run with: cargo run --example reqwest_usage --features reqwest

#[cfg(feature = "reqwest")]
fn main() {
    use ri_cookie_header_string::reqwest_support::parse_for_reqwest;

    let cookie_header = "session=abc;xyz; user=john; token=abc123";
    let cookies: Vec<_> = parse_for_reqwest(cookie_header).filter_map(|result| result.ok()).collect();

    println!("Parsed {} cookies:", cookies.len());
    for cookie in &cookies {
        println!("  {}: {}", cookie.name(), cookie.value());
    }
}

#[cfg(not(feature = "reqwest"))]
fn main() {
    println!("Please run with --features reqwest");
}
