use std::path::PathBuf;

use opcua_core::config::Config;

use config::{ServerConfig, ServerEndpoint, ServerUserToken, ANONYMOUS_USER_TOKEN_ID};
use server::Server;

const DEFAULT_ENDPOINT_PATH: &str = "/";

/// The `ServerBuilder` is a builder for producing a [`Server`]. It is an alternative to constructing
/// a [`ServerConfig`] from file or from scratch.
///
/// [`Server`]: ../client/struct.Server.html
/// [`ServerConfig`]: ../config/struct.ServerConfig.html
pub struct ServerBuilder {
    config: ServerConfig,
}

impl ServerBuilder {
    pub fn new() -> Self {
        ServerBuilder {
            config: ServerConfig::default()
        }
    }

    /// Creates a simple endpoint that accepts anonymous connections
    pub fn new_anonymous<T>(application_name: T) -> Self where T: Into<String> {
        let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID.to_string()];
        ServerBuilder::new()
            .application_name(application_name)
            .endpoint("none", ServerEndpoint::new_none(DEFAULT_ENDPOINT_PATH, &user_token_ids))
    }

    /// Sample mode turns on everything including a hard coded user/pass
    pub fn new_sample() -> ServerBuilder {
        warn!("Sample configuration is for testing purposes only. Use a proper configuration in your production environment");

        let path = DEFAULT_ENDPOINT_PATH;
        let sample_user_id = "sample_user";
        let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID.to_string(), sample_user_id.to_string()];

        ServerBuilder::new()
            .application_name("OPC UA Sample Server")
            .create_sample_keypair(true)
            .user_token("sample_user", ServerUserToken {
                user: "sample".to_string(),
                pass: Some("sample1".to_string()),
            })
            .user_token("unused_user", ServerUserToken {
                user: "unused".to_string(),
                pass: Some("unused1".to_string()),
            })
            .endpoints(vec![
                ("none", ServerEndpoint::new_none(path, &user_token_ids)),
                ("basic128rsa15_sign", ServerEndpoint::new_basic128rsa15_sign(path, &user_token_ids)),
                ("basic128rsa15_sign_encrypt", ServerEndpoint::new_basic128rsa15_sign_encrypt(path, &user_token_ids)),
                ("basic256_sign", ServerEndpoint::new_basic256_sign(path, &user_token_ids)),
                ("basic256_sign_encrypt", ServerEndpoint::new_basic256_sign_encrypt(path, &user_token_ids)),
                ("basic256sha256_sign", ServerEndpoint::new_basic256sha256_sign(path, &user_token_ids)),
                ("basic256sha256_sign_encrypt", ServerEndpoint::new_basic256sha256_sign_encrypt(path, &user_token_ids)),
                ("no_access", ServerEndpoint::new_none("/noaccess", &[]))
            ])
    }

    /// Yields a [`Client`] from the values set by the builder. If the builder is not in a valid state
    /// it will return `None`.
    ///
    /// [`Server`]: ../server/struct.Server.html
    pub fn server(self) -> Option<Server> {
        if self.is_valid() {
            Some(Server::new(self.config))
        } else {
            None
        }
    }

    /// Yields a [`ClientConfig`] from the values set by the builder.
    ///
    /// [`ServerConfig`]: ../config/struct.ServerConfig.html
    pub fn config(self) -> ServerConfig {
        self.config
    }

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

    /// Sets the pki directory where client's own key pair is stored and where `/trusted` and
    /// `/rejected` server certificates are stored.
    pub fn pki_dir<T>(mut self, pki_dir: T) -> Self where T: Into<PathBuf> {
        self.config.pki_dir = pki_dir.into();
        self
    }

    /// Adds an endpoint to the list of endpoints the client knows of.
    pub fn endpoint<T>(mut self, endpoint_id: T, endpoint: ServerEndpoint) -> Self where T: Into<String> {
        self.config.endpoints.insert(endpoint_id.into(), endpoint);
        self
    }

    /// Adds multiple endpoints to the list of endpoints the client knows of.
    pub fn endpoints<T>(mut self, endpoints: Vec<(T, ServerEndpoint)>) -> Self where T: Into<String> {
        for e in endpoints {
            self.config.endpoints.insert(e.0.into(), e.1);
        };
        self
    }

    /// Adds a user token to the server.
    pub fn user_token<T>(mut self, user_token_id: T, user_token: ServerUserToken) -> Self where T: Into<String> {
        self.config.user_tokens.insert(user_token_id.into(), user_token);
        self
    }

    /// Sets the discovery server url that this server shall attempt to register itself with.
    pub fn discovery_server_url(mut self, discovery_server_url: Option<String>) -> Self {
        self.config.discovery_server_url = discovery_server_url;
        self
    }

    /// Sets the hostname and port to listen on
    pub fn host_and_port<T>(mut self, host: T, port: u16) -> Self where T: Into<String> {
        self.config.tcp_config.host = host.into();
        self.config.tcp_config.port = port;
        self
    }

    /// Discovery endpoint url - the url of this server used by clients to get endpoints.
    pub fn discovery_url<T>(mut self, discovery_url: T) -> Self where T: Into<String> {
        self.config.discovery_url = discovery_url.into();
        self
    }

    /// Maximum number of subscriptions in a session
    pub fn max_subscriptions(mut self, max_subscriptions: u32) -> Self {
        self.config.max_subscriptions = max_subscriptions;
        self
    }

    /// Max array length in elements
    pub fn max_array_length(mut self, max_array_length: u32) -> Self {
        self.config.max_array_length = max_array_length;
        self
    }

    /// Max string length in characters
    pub fn max_string_length(mut self, max_string_length: u32) -> Self {
        self.config.max_string_length = max_string_length;
        self
    }

    /// Max bytestring length in bytes
    pub fn max_byte_string_length(mut self, max_byte_string_length: u32) -> Self {
        self.config.max_byte_string_length = max_byte_string_length;
        self
    }
}