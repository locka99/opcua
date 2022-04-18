// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::path::PathBuf;

use crate::async_client::{client::Client, config::*};
use crate::core::config::Config;

/// The `ClientBuilder` is a builder for producing a [`Client`]. It is an alternative to constructing
/// a [`ClientConfig`] from file or from scratch.
///
/// # Example
///
/// ```no_run
/// use opcua::client::prelude::*;
///
/// fn main() {
///     let builder = ClientBuilder::new()
///         .application_name("OPC UA Sample Client")
///         .application_uri("urn:SampleClient")
///         .pki_dir("./pki")
///         .endpoints(vec![
///             ("sample_endpoint", ClientEndpoint {
///                 url: String::from("opc.tcp://127.0.0.1:4855/"),
///                 security_policy: String::from(SecurityPolicy::None.to_str()),
///                 security_mode: String::from(MessageSecurityMode::None),
///                 user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
///             }),
///         ])
///         .default_endpoint("sample_endpoint")
///         .create_sample_keypair(true)
///         .trust_server_certs(true)
///         .user_token("sample_user", ClientUserToken::user_pass("sample1", "sample1pwd"));
///     let client = builder.client().unwrap();
/// }
/// ```
///
/// [`Client`]: ../client/struct.Client.html
/// [`ClientConfig`]: ../config/struct.ClientConfig.html
///
pub struct ClientBuilder {
    config: ClientConfig,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder {
            config: ClientConfig::default(),
        }
    }
}

impl ClientBuilder {
    /// Creates a `ClientBuilder`
    pub fn new() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Creates a `ClientBuilder` using a configuration file as the initial state.
    pub fn from_config<T>(path: T) -> Result<ClientBuilder, ()>
    where
        T: Into<PathBuf>,
    {
        Ok(ClientBuilder {
            config: ClientConfig::load(&path.into())?,
        })
    }

    /// Yields a [`Client`] from the values set by the builder. If the builder is not in a valid state
    /// it will return `None`.
    ///
    /// [`Client`]: ../client/struct.Client.html
    pub fn client(self) -> Option<Client> {
        if self.is_valid() {
            Some(Client::new(self.config))
        } else {
            None
        }
    }

    /// Yields a [`ClientConfig`] from the values set by the builder.
    ///
    /// [`ClientConfig`]: ../config/struct.ClientConfig.html
    pub fn config(self) -> ClientConfig {
        self.config
    }

    /// Tests if the builder is in a valid state to be able to yield a `Client`.
    pub fn is_valid(&self) -> bool {
        self.config.is_valid()
    }

    /// Sets the application name.
    pub fn application_name<T>(mut self, application_name: T) -> Self
    where
        T: Into<String>,
    {
        self.config.application_name = application_name.into();
        self
    }

    /// Sets the application uri
    pub fn application_uri<T>(mut self, application_uri: T) -> Self
    where
        T: Into<String>,
    {
        self.config.application_uri = application_uri.into();
        self
    }

    /// Sets the product uri.
    pub fn product_uri<T>(mut self, product_uri: T) -> Self
    where
        T: Into<String>,
    {
        self.config.product_uri = product_uri.into();
        self
    }

    /// Sets whether the client should generate its own key pair if there is none found in the pki
    /// directory.
    pub fn create_sample_keypair(mut self, create_sample_keypair: bool) -> Self {
        self.config.create_sample_keypair = create_sample_keypair;
        self
    }

    /// Sets a custom client certificate path. The path is required to be provided as a partial
    /// path relative to the PKI directory. If set, this path will be used to read the client
    /// certificate from disk. The certificate can be in either the .der or .pem format.
    pub fn certificate_path<T>(mut self, certificate_path: T) -> Self
    where
        T: Into<PathBuf>,
    {
        self.config.certificate_path = Some(certificate_path.into());
        self
    }

    /// Sets a custom private key path. The path is required to be provided as a partial path
    /// relative to the PKI directory. If set, this path will be used to read the private key
    /// from disk.
    pub fn private_key_path<T>(mut self, private_key_path: T) -> Self
    where
        T: Into<PathBuf>,
    {
        self.config.private_key_path = Some(private_key_path.into());
        self
    }

    /// Sets whether the client should automatically trust servers. If this is not set then
    /// the client will reject the server upon first connect and the server's certificate
    /// must be manually moved from pki's `/rejected` folder to the `/trusted` folder. If it is
    /// set, then the server cert will automatically be stored in the `/trusted` folder.
    pub fn trust_server_certs(mut self, trust_server_certs: bool) -> Self {
        self.config.trust_server_certs = trust_server_certs;
        self
    }

    /// Sets whether the client should verify server certificates. Regardless of this setting,
    /// server certificates are always checked to see if they are trusted and have a valid key
    /// length. In addition (if `verify_server_certs` is unset or is set to `true`) it will
    /// verify the hostname, application uri and the not before / after values to ensure validity.
    pub fn verify_server_certs(mut self, verify_server_certs: bool) -> Self {
        self.config.verify_server_certs = verify_server_certs;
        self
    }

    /// Sets the pki directory where client's own key pair is stored and where `/trusted` and
    /// `/rejected` server certificates are stored.
    pub fn pki_dir<T>(mut self, pki_dir: T) -> Self
    where
        T: Into<PathBuf>,
    {
        self.config.pki_dir = pki_dir.into();
        self
    }

    /// Sets the preferred locales of the client. These are passed to the server during session
    /// creation to ensure localized strings are in the preferred language.
    pub fn preferred_locales(mut self, preferred_locales: Vec<String>) -> Self {
        self.config.preferred_locales = preferred_locales;
        self
    }

    /// Sets the id of the default endpoint to connect to.
    pub fn default_endpoint<T>(mut self, endpoint_id: T) -> Self
    where
        T: Into<String>,
    {
        self.config.default_endpoint = endpoint_id.into();
        self
    }

    /// Adds an endpoint to the list of endpoints the client knows of.
    pub fn endpoint<T>(mut self, endpoint_id: T, endpoint: ClientEndpoint) -> Self
    where
        T: Into<String>,
    {
        self.config.endpoints.insert(endpoint_id.into(), endpoint);
        self
    }

    /// Adds multiple endpoints to the list of endpoints the client knows of.
    pub fn endpoints<T>(mut self, endpoints: Vec<(T, ClientEndpoint)>) -> Self
    where
        T: Into<String>,
    {
        for e in endpoints {
            self.config.endpoints.insert(e.0.into(), e.1);
        }
        self
    }

    /// Adds a user token to the list supported by the client.
    pub fn user_token<T>(mut self, user_token_id: T, user_token: ClientUserToken) -> Self
    where
        T: Into<String>,
    {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            panic!("User token id {} is reserved", user_token_id);
        }
        self.config.user_tokens.insert(user_token_id, user_token);
        self
    }

    /// Sets the session retry limit.
    pub fn session_retry_limit(mut self, session_retry_limit: i32) -> Self {
        if session_retry_limit < 0 && session_retry_limit != -1 {
            panic!("Session retry limit must be -1, 0 or a positive number");
        }
        self.config.session_retry_limit = session_retry_limit;
        self
    }

    /// Sets the session retry interval.
    pub fn session_retry_interval(mut self, session_retry_interval: u32) -> Self {
        self.config.session_retry_interval = session_retry_interval;
        self
    }

    /// Sets the session timeout period.
    pub fn session_timeout(mut self, session_timeout: u32) -> Self {
        self.config.session_timeout = session_timeout;
        self
    }

    /// Sets whether the client should ignore clock skew so the client can make a successful
    /// connection to the server, even when the client and server clocks are out of sync.
    pub fn ignore_clock_skew(mut self) -> Self {
        self.config.performance.ignore_clock_skew = true;
        self
    }

    /// Session name - the default name to use for a new session
    pub fn session_name<T>(mut self, session_name: T) -> Self
    where
        T: Into<String>,
    {
        self.config.session_name = session_name.into();
        self
    }
}

#[test]
fn client_builder() {
    use std::str::FromStr;

    // The builder should produce a config that reflects the values that are explicitly set upon it.
    let b = ClientBuilder::new()
        .application_name("appname")
        .application_uri("http://appname")
        .product_uri("http://product")
        .create_sample_keypair(true)
        .certificate_path("certxyz")
        .private_key_path("keyxyz")
        .trust_server_certs(true)
        .verify_server_certs(false)
        .pki_dir("pkixyz")
        .preferred_locales(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        .default_endpoint("http://default")
        .session_retry_interval(1234)
        .session_retry_limit(999)
        .session_timeout(777)
        .ignore_clock_skew()
        .session_name("SessionName")
        // TODO user tokens, endpoints
        ;

    let c = b.config();

    assert_eq!(c.application_name, "appname");
    assert_eq!(c.application_uri, "http://appname");
    assert_eq!(c.product_uri, "http://product");
    assert_eq!(c.create_sample_keypair, true);
    assert_eq!(c.certificate_path, Some(PathBuf::from("certxyz")));
    assert_eq!(c.private_key_path, Some(PathBuf::from("keyxyz")));
    assert_eq!(c.trust_server_certs, true);
    assert_eq!(c.verify_server_certs, false);
    assert_eq!(c.pki_dir, PathBuf::from_str("pkixyz").unwrap());
    assert_eq!(
        c.preferred_locales,
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
    assert_eq!(c.default_endpoint, "http://default");
    assert_eq!(c.session_retry_interval, 1234);
    assert_eq!(c.session_retry_limit, 999);
    assert_eq!(c.session_timeout, 777);
    assert_eq!(c.performance.ignore_clock_skew, true);
    assert_eq!(c.session_name, "SessionName");
}
