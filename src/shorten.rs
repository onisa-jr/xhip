
/// Attempt to shorten a long URL using fast, reliable public URL shortening services.
/// Returns Some(short_url) on success, or None if services are unreachable or fail.
pub fn shorten_url(long_url: &str) -> Option<String> {
    let encoded = crate::s3::percent_encode_val(long_url);

    // 1. Try da.gd (clean 302 redirect directly to R2 URL, preserves full query params)
    let dagd_url = format!("https://da.gd/s?url={}", encoded);
    if let Ok(mut res) = ureq::get(&dagd_url)
        .header("User-Agent", "xhip/0.1.0")
        .call()
    {
        if res.status().as_u16() == 200 {
            if let Ok(body) = res.body_mut().read_to_string() {
                let trimmed = body.trim();
                if trimmed.starts_with("http") && !trimmed.contains('\n') && !trimmed.contains("error") {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    // 2. Try clck.ru as fallback
    let clck_url = format!("https://clck.ru/--?url={}", encoded);
    if let Ok(mut res) = ureq::get(&clck_url)
        .header("User-Agent", "xhip/0.1.0")
        .call()
    {
        if res.status().as_u16() == 200 {
            if let Ok(body) = res.body_mut().read_to_string() {
                let trimmed = body.trim();
                if trimmed.starts_with("http") && !trimmed.contains('\n') {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    None
}
