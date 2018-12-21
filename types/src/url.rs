//! Provides functions for parsing Urls from strings.

use std;

use ::url::Url;

use crate::constants::DEFAULT_OPC_UA_SERVER_PORT;

pub const OPC_TCP_SCHEME: &str = "opc.tcp";

fn opc_url_from_str(s: &str) -> Result<Url, ()> {
    let url = Url::parse(s);
    if let Ok(mut url) = url {
        if url.port().is_none() {
            // If no port is supplied, then treat it as the default port 4840
            let _ = url.set_port(Some(DEFAULT_OPC_UA_SERVER_PORT));
        }
        Ok(url)
    } else {
        error!("Cannot parse url {}, error = {:?}", s, url.unwrap_err());
        Err(())
    }
}

/// Replace the hostname in the supplied url and return a new url
pub fn url_with_replaced_hostname(url: &str, hostname: &str) -> Result<String, ()> {
    let mut url = opc_url_from_str(url)?;
    let _ = url.set_host(Some(hostname));
    Ok(url.into_string())
}

/// Test if the two urls match exactly. Strings are fed into a url parser and compared to resolve
/// ambiguities like paths, case sensitive portions, encoding etc.
pub fn url_matches(url1: &str, url2: &str) -> bool {
    if let Ok(url1) = opc_url_from_str(url1) {
        if let Ok(url2) = opc_url_from_str(url2) {
            return url1 == url2;
        } else {
            error!("Cannot parse url {}", url2);
        }
    } else {
        error!("Cannot parse url {}", url1);
    }
    false
}

/// Test if the two urls match except for the hostname. Can be used by a server whose endpoint doesn't
/// exactly match the incoming connection, e.g. 127.0.0.1 vs localhost.
pub fn url_matches_except_host(url1: &str, url2: &str) -> bool {
    if let Ok(mut url1) = opc_url_from_str(url1) {
        if let Ok(mut url2) = opc_url_from_str(url2) {
            // Both hostnames are set to xxxx so the comparison should come out as the same url
            // if they actually match one another.
            if url1.set_host(Some("xxxx")).is_ok() && url2.set_host(Some("xxxx")).is_ok() {
                return url1 == url2;
            }
        } else {
            error!("Cannot parse url {}", url2);
        }
    } else {
        error!("Cannot parse url {}", url1);
    }
    false
}

/// Takes an endpoint url and strips off the path and args to leave just the protocol, host & port.
pub fn server_url_from_endpoint_url(endpoint_url: &str) -> std::result::Result<String, ()> {
    if let Ok(mut url) = opc_url_from_str(endpoint_url) {
        url.set_path("");
        url.set_query(None);
        if let Some(port) = url.port() {
            // If the port is the default, strip it so the url string omits it.
            if port == DEFAULT_OPC_UA_SERVER_PORT {
                let _ = url.set_port(None);
            }
        }
        Ok(url.into_string())
    } else {
        Err(())
    }
}

pub fn is_opc_ua_binary_url(url: &str) -> bool {
    if let Ok(url) = opc_url_from_str(url) {
        url.scheme() == OPC_TCP_SCHEME
    } else {
        false
    }
}

pub fn hostname_from_url(url: &str) -> Result<String, ()> {
    // Validate and split out the endpoint we have
    if let Ok(url) = Url::parse(url) {
        if let Some(host) = url.host_str() {
            Ok(host.to_string())
        } else {
            Err(())
        }
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_scheme_test() {
        assert!(is_opc_ua_binary_url("opc.tcp://foo/xyz"));
        assert!(!is_opc_ua_binary_url("http://foo/xyz"));
    }

    #[test]
    fn url_matches_test() {
//        assert!(url_matches("opc.tcp://foo/xyz", "opc.tcp://FOO/xyz"));
//        assert!(url_matches("opc.tcp://foo/", "opc.tcp://FOO"));
        assert!(url_matches("opc.tcp://foo/", "opc.tcp://foo:4840/"));
        assert!(!url_matches("opc.tcp://foo/", "opc.tcp://foo:4841/"));
        assert!(!url_matches("opc.tcp://foo/xyz", "opc.tcp://bar/xyz"));
        assert!(url_matches_except_host("opc.tcp://localhost/xyz", "opc.tcp://127.0.0.1/xyz"));
        assert!(!url_matches_except_host("opc.tcp://localhost/xyz", "opc.tcp://127.0.0.1/abc"));
    }

    #[test]
    fn server_url_from_endpoint_url_test() {
        assert_eq!("opc.tcp://localhost/", server_url_from_endpoint_url("opc.tcp://localhost").unwrap());
        assert_eq!("opc.tcp://localhost/", server_url_from_endpoint_url("opc.tcp://localhost:4840").unwrap());
        assert_eq!("opc.tcp://localhost:4841/", server_url_from_endpoint_url("opc.tcp://localhost:4841").unwrap());
        assert_eq!("opc.tcp://localhost/", server_url_from_endpoint_url("opc.tcp://localhost/xyz/abc?1").unwrap());
        assert_eq!("opc.tcp://localhost:999/", server_url_from_endpoint_url("opc.tcp://localhost:999/xyz/abc?1").unwrap());
    }
}