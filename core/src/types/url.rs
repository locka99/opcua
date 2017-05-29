use url::Url;

/// Test if the two urls match except for the hostname. Can be used by a server whose endpoint doesn't
/// exactly match the incoming connection, e.g. 127.0.0.1 vs localhost.
pub fn url_matches_except_host(url1: &str, url2: &str) -> Result<bool, ()> {
    if let Ok(mut url1) = Url::parse(url1) {
        if let Ok(mut url2) = Url::parse(url2) {
            if url1.set_host(None).is_ok() && url2.set_host(None).is_ok() {
                return Ok(url1 == url2)
            }
        }
    }
    Err(())
}

pub fn is_opc_ua_binary_url(url: &str) -> bool {
    if let Ok(url) = Url::parse(url) {
        url.scheme() == "opc.tcp"
    } else {
        false
    }
}

#[test]
fn url_scheme() {
    assert!(is_opc_ua_binary_url("opc.tcp://foo/xyz"));
    assert!(!is_opc_ua_binary_url("http://foo/xyz"));
}

#[test]
fn url_matches() {
    assert!(url_matches_except_host("opc.tcp://localhost/xyz", "opc.tcp://127.0.0.1/xyz").unwrap());
    assert!(!url_matches_except_host("opc.tcp://localhost/xyz", "opc.tcp://127.0.0.1/abc").unwrap());
}
