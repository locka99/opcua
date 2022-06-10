// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::path::PathBuf;

use crate::core::config::Config;

use super::{
    config::{ServerConfig, ServerEndpoint, ServerUserToken, ANONYMOUS_USER_TOKEN_ID},
    constants,
    server::Server,
};

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
        Self {
            config: ServerConfig::default(),
        }
    }

    /// Reads the config in as a starting point
    pub fn from_config(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Creates a simple endpoint that accepts anonymous connections
    pub fn new_anonymous<T>(application_name: T) -> Self
    where
        T: Into<String>,
    {
        let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID.to_string()];
        Self::new()
            .application_name(application_name)
            .endpoint(
                "none",
                ServerEndpoint::new_none(DEFAULT_ENDPOINT_PATH, &user_token_ids),
            )
            .discovery_urls(vec![DEFAULT_ENDPOINT_PATH.into()])
    }

    /// Creates and yields a builder which is configured with the sample server configuration.
    /// Use this for testing and similar reasons. Do not rely upon this in production code because it could change.
    pub fn new_sample() -> Self {
        warn!("Sample configuration is for testing purposes only. Use a proper configuration in your production environment");

        let path = DEFAULT_ENDPOINT_PATH;

        let user_token_ids = [
            "sample_password_user",
            "sample_x509_user",
            ANONYMOUS_USER_TOKEN_ID,
        ]
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<String>>();

        Self::new()
            .application_name("OPC UA Sample Server")
            .application_uri("urn:OPC UA Sample Server")
            .product_uri("urn:OPC UA Sample Server Testkit")
            .create_sample_keypair(true)
            .certificate_path("own/cert.der")
            .private_key_path("private/private.pem")
            .pki_dir("./pki")
            .discovery_server_url(Some(constants::DEFAULT_DISCOVERY_SERVER_URL.to_string()))
            .user_token(
                "sample_password_user",
                ServerUserToken {
                    user: "sample1".to_string(),
                    pass: Some("sample1pwd".to_string()),
                    x509: None,
                    thumbprint: None,
                },
            )
            .user_token(
                "sample_x509_user",
                ServerUserToken {
                    user: "sample_x509".to_string(),
                    pass: None,
                    x509: Some("./users/sample-x509.der".to_string()),
                    thumbprint: None,
                },
            )
            .user_token(
                "unused_user",
                ServerUserToken {
                    user: "unused".to_string(),
                    pass: Some("unused1".to_string()),
                    x509: None,
                    thumbprint: None,
                },
            )
            .endpoints(vec![
                ("none", ServerEndpoint::new_none(path, &user_token_ids)),
                (
                    "basic128rsa15_sign",
                    ServerEndpoint::new_basic128rsa15_sign(path, &user_token_ids),
                ),
                (
                    "basic128rsa15_sign_encrypt",
                    ServerEndpoint::new_basic128rsa15_sign_encrypt(path, &user_token_ids),
                ),
                (
                    "aes128-sha256-rsaoaep_sign",
                    ServerEndpoint::new_aes128_sha256_rsaoaep_sign(path, &user_token_ids),
                ),
                (
                    "aes128-sha256-rsaoaep_sign_encrypt",
                    ServerEndpoint::new_aes128_sha256_rsaoaep_sign_encrypt(path, &user_token_ids),
                ),
                (
                    "aes256-sha256-rsapss_sign",
                    ServerEndpoint::new_aes256_sha256_rsapss_sign(path, &user_token_ids),
                ),
                (
                    "aes256-sha256-rsapss_sign_encrypt",
                    ServerEndpoint::new_aes256_sha256_rsapss_sign_encrypt(path, &user_token_ids),
                ),
                (
                    "basic256_sign",
                    ServerEndpoint::new_basic256_sign(path, &user_token_ids),
                ),
                (
                    "basic256_sign_encrypt",
                    ServerEndpoint::new_basic256_sign_encrypt(path, &user_token_ids),
                ),
                (
                    "basic256sha256_sign",
                    ServerEndpoint::new_basic256sha256_sign(path, &user_token_ids),
                ),
                (
                    "basic256sha256_sign_encrypt",
                    ServerEndpoint::new_basic256sha256_sign_encrypt(path, &user_token_ids),
                ),
                ("no_access", ServerEndpoint::new_none("/noaccess", &[])),
            ])
            .discovery_urls(vec![DEFAULT_ENDPOINT_PATH.into()])
    }

    /// Yields a [`Client`] from the values set by the builder. If the builder is not in a valid state
    /// it will return `None`.
    ///
    /// [`Server`]: ../server/struct.Server.html
    pub fn server(self) -> Option<Server> {
        if self.is_valid() {
            Some(Server::new(self.config()))
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

    /// Test if the builder can yield a server with the configuration supplied.
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

    /// Sets a custom server certificate path. The path is required to be provided as a partial
    /// path relative to the PKI directory. If set, this path will be used to read the server
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

    /// Sets the pki directory where client's own key pair is stored and where `/trusted` and
    /// `/rejected` server certificates are stored.
    pub fn pki_dir<T>(mut self, pki_dir: T) -> Self
    where
        T: Into<PathBuf>,
    {
        self.config.pki_dir = pki_dir.into();
        self
    }

    /// Adds an endpoint to the list of endpoints the client knows of.
    pub fn endpoint<T>(mut self, endpoint_id: T, endpoint: ServerEndpoint) -> Self
    where
        T: Into<String>,
    {
        self.config.endpoints.insert(endpoint_id.into(), endpoint);
        self
    }

    /// Adds multiple endpoints to the list of endpoints the client knows of.
    pub fn endpoints<T>(mut self, endpoints: Vec<(T, ServerEndpoint)>) -> Self
    where
        T: Into<String>,
    {
        for e in endpoints {
            self.config.endpoints.insert(e.0.into(), e.1);
        }
        self
    }

    /// Adds a user token to the server.
    pub fn user_token<T>(mut self, user_token_id: T, user_token: ServerUserToken) -> Self
    where
        T: Into<String>,
    {
        self.config
            .user_tokens
            .insert(user_token_id.into(), user_token);
        self
    }

    /// Sets the discovery server url that this server shall attempt to register itself with.
    pub fn discovery_server_url(mut self, discovery_server_url: Option<String>) -> Self {
        self.config.discovery_server_url = discovery_server_url;
        self
    }

    /// Sets the hostname and port to listen on
    pub fn host_and_port<T>(mut self, host: T, port: u16) -> Self
    where
        T: Into<String>,
    {
        self.config.tcp_config.host = host.into();
        self.config.tcp_config.port = port;
        self
    }

    /// Discovery endpoint urls - the urls of this server used by clients to get endpoints.
    /// If the url is relative, e.g. "/" then the code will make a url for you using the port/host
    /// settings as they are at the time this function is executed.
    pub fn discovery_urls(mut self, discovery_urls: Vec<String>) -> Self {
        self.config.discovery_urls = discovery_urls
            .iter()
            .map(|discovery_url| {
                if discovery_url.starts_with('/') {
                    // Turn into an opc url
                    format!(
                        "opc.tcp://{}:{}/",
                        self.config.tcp_config.host, self.config.tcp_config.port
                    )
                } else {
                    discovery_url.clone()
                }
            })
            .collect();
        self
    }

    /// Set the maximum number of subscriptions in a session
    pub fn max_subscriptions(mut self, max_subscriptions: usize) -> Self {
        self.config.limits.max_subscriptions = max_subscriptions;
        self
    }

    /// Set the maximum number of monitored items per subscription
    pub fn max_monitored_items_per_sub(mut self, max_monitored_items_per_sub: usize) -> Self {
        self.config.limits.max_monitored_items_per_sub = max_monitored_items_per_sub;
        self
    }

    /// Set the max array length in elements
    pub fn max_array_length(mut self, max_array_length: usize) -> Self {
        self.config.limits.max_array_length = max_array_length;
        self
    }

    /// Set the max string length in characters, i.e. if you set max to 1000 characters, then with
    /// UTF-8 encoding potentially that's 4000 bytes.
    pub fn max_string_length(mut self, max_string_length: usize) -> Self {
        self.config.limits.max_string_length = max_string_length;
        self
    }

    /// Set the max bytestring length in bytes
    pub fn max_byte_string_length(mut self, max_byte_string_length: usize) -> Self {
        self.config.limits.max_byte_string_length = max_byte_string_length;
        self
    }

    /// Set the maximum message size
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.config.limits.max_message_size = max_message_size;
        self
    }

    /// Set the max chunk count
    pub fn max_chunk_count(mut self, max_chunk_count: usize) -> Self {
        self.config.limits.max_chunk_count = max_chunk_count;
        self
    }

    // Set the send buffer size
    pub fn send_buffer_size(mut self, send_buffer_size: usize) -> Self {
        self.config.limits.send_buffer_size = send_buffer_size;
        self
    }

    // Set the receive buffer size
    pub fn receive_buffer_size(mut self, receive_buffer_size: usize) -> Self {
        self.config.limits.receive_buffer_size = receive_buffer_size;
        self
    }

    /// Sets the server to automatically trust client certs. This subverts the
    /// authentication during handshake, so only do this if you understand the risks.
    pub fn trust_client_certs(mut self) -> Self {
        self.config.certificate_validation.trust_client_certs = true;
        self
    }

    /// Set that clients can modify the address space, i.e. they can add or remove nodes through
    /// the node management service. By default, they cannot.
    pub fn clients_can_modify_address_space(mut self) -> Self {
        self.config.limits.clients_can_modify_address_space = true;
        self
    }

    /// Configures the server to use a single-threaded executor. The default executor uses a
    /// thread pool with a worker thread for each CPU core available on the system.
    pub fn single_threaded_executor(mut self) -> Self {
        self.config.performance.single_threaded_executor = true;
        self
    }

    /// Configures the server to use a multi-threaded executor.
    pub fn multi_threaded_executor(mut self) -> Self {
        self.config.performance.single_threaded_executor = false;
        self
    }
}
