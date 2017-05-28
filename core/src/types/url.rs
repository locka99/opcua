use url::Url;

/// Test if the two urls match except for the hostname. Can be used by a server whose endpoint doesn't
/// exactly match the incoming connection, e.g. 127.0.0.1 vs localhost
pub fn url_matches_except_host(url1: &str, url2: &str) -> Result<bool, ()> {
    if let Ok(mut url1) = Url::parse(url1) {
        if let Ok(mut url2) = Url::parse(url2) {
            url1.set_host(Some("x"));
            url2.set_host(Some("x"));
            Ok(url1 == url2)
        } else {
            Err(())
        }
    } else {
        Err(())
    }
}

#[test]
fn url_matches() {
    assert!(url_matches_except_host("opc.tcp://localhost/xyz", "opc.tcp://127.0.0.1/xyz").unwrap());
    assert!(!url_matches_except_host("opc.tcp://localhost/xyz", "opc.tcp://127.0.0.1/abc").unwrap());
}