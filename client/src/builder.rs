use std::path::PathBuf;

use opcua_core::config::Config;

use client::*;
use config::*;

/// The `ClientBuilder` is a builder for producing a [`Client`]. It is an alternative to constructing
/// a [`ClientConfig`] from file or from scratch.
///
/// # Example
///
/// ```rust,no_run
/// extern crate opcua_client;
/// use opcua_client::prelude::*;
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
///         .user_token("sample_user", ClientUserToken::new("sample", "sample1"));
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

impl ClientBuilder {
    /// Creates a `ClientBuilder`
    pub fn new() -> ClientBuilder {
        ClientBuilder {
            config: ClientConfig::default()
        }
    }

    /// Creates a `ClientBuilder` using a configuration file as the initial state.
    pub fn from_config<T>(path: T) -> Result<ClientBuilder, ()> where T: Into<PathBuf> {
        Ok(ClientBuilder {
            config: ClientConfig::load(&path.into())?
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
    pub fn application_name<T>(mut self, application_name: T) -> Self where T: Into<String> {
        self.config.application_name = application_name.into();
        self
    }

    /// Sets the application uri
    pub fn application_uri<T>(mut self, application_uri: T) -> Self where T: Into<String> {
        self.config.application_uri = application_uri.into();
        self
    }

    /// Sets the product uri.
    pub fn product_uri<T>(mut self, product_uri: T) -> Self where T: Into<String> {
        self.config.product_uri = product_uri.into();
        self
    }

    /// Sets whether the client should generate its own key pair if there is none found in the pki
    /// directory.
    pub fn create_sample_keypair(mut self, create_sample_keypair: bool) -> Self {
        self.config.create_sample_keypair = create_sample_keypair;
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

    /// Sets the pki directory where client's own key pair is stored and where `/trusted` and
    /// `/rejected` server certificates are stored.
    pub fn pki_dir<T>(mut self, pki_dir: T) -> Self where T: Into<PathBuf> {
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
    pub fn default_endpoint<T>(mut self, endpoint_id: T) -> Self where T: Into<String> {
        self.config.default_endpoint = endpoint_id.into();
        self
    }

    /// Adds an endpoint to the list of endpoints the client knows of.
    pub fn endpoint<T>(mut self, endpoint_id: T, endpoint: ClientEndpoint) -> Self where T: Into<String> {
        self.config.endpoints.insert(endpoint_id.into(), endpoint);
        self
    }

    /// Adds multiple endpoints to the list of endpoints the client knows of.
    pub fn endpoints<T>(mut self, endpoints: Vec<(T, ClientEndpoint)>) -> Self where T: Into<String> {
        for e in endpoints {
            self.config.endpoints.insert(e.0.into(), e.1);
        };
        self
    }

    /// Adds a user token to the list supported by the client.
    pub fn user_token<T>(mut self, user_token_id: T, user_token: ClientUserToken) -> Self where T: Into<String> {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            panic!("User token id {} is reserved", user_token_id);
        }
        self.config.user_tokens.insert(user_token_id, user_token);
        self
    }
}