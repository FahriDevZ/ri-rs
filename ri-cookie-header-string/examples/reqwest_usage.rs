//! Example demonstrating cookie parsing for use with reqwest.
//!
//! Run with: cargo run --example reqwest_usage --features reqwest

#[cfg(feature = "reqwest")]
fn main() {
    use ri_cookie_header_string::reqwest_support::parse_for_reqwest;

    // Example: Parsing cookies for use with reqwest
    println!("=== Cookie Parsing for Reqwest ===");
    let cookie_header = "session=abc;xyz; user=john; token=abc123";

    let cookies: Vec<_> = parse_for_reqwest(cookie_header)
        .filter_map(|result| result.ok())
        .collect();

    println!("Parsed {} cookies:", cookies.len());
    for cookie in &cookies {
        println!("  {} = {}", cookie.name(), cookie.value());
        println!("    String representation: {}", cookie.to_string());
    }

    // These cookies can be added to a reqwest CookieJar
    println!("\n=== Usage with Reqwest CookieJar ===");
    println!("The parsed cookies can be added to reqwest like this:");
    println!();
    println!("    let jar = reqwest::cookie::Jar::default();");
    println!("    let url = \"https://example.com\".parse().unwrap();");
    println!("    for cookie in cookies {{");
    println!("        jar.add_cookie_str(&cookie.to_string(), &url);");
    println!("    }}");
}

#[cfg(not(feature = "reqwest"))]
fn main() {
    println!("Please run with --features reqwest");
    println!("Example: cargo run --example reqwest_usage --features reqwest");
}
