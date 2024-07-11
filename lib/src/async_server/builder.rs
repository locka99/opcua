use std::{path::PathBuf, sync::Arc};

use crate::{
    async_server::constants,
    server::prelude::{Config, MessageSecurityMode, SecurityPolicy},
};

use super::{
    authenticator::AuthManager,
    node_manager::{
        memory::{CoreNodeManagerImpl, DiagnosticsNodeManager, InMemoryNodeManager},
        NodeManager,
    },
    Limits, ServerConfig, ServerCore, ServerEndpoint, ServerHandle, ServerUserToken,
    ANONYMOUS_USER_TOKEN_ID,
};

pub struct ServerBuilder {
    pub(crate) config: ServerConfig,
    pub(crate) node_managers: Vec<Arc<dyn NodeManager + Send + Sync + 'static>>,
    pub(crate) authenticator: Option<Arc<dyn AuthManager>>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        let builder = Self {
            config: Default::default(),
            node_managers: Default::default(),
            authenticator: None,
        };
        let core_node_manager = Arc::new(InMemoryNodeManager::new(CoreNodeManagerImpl::new()));
        let diagnostics_node_manager = Arc::new(DiagnosticsNodeManager::new());
        builder
            .with_node_manager(core_node_manager)
            .with_node_manager(diagnostics_node_manager)
    }
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a server builder from a config object.
    pub fn from_config(config: ServerConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Creates a simple endpoint that accepts anonymous connections.
    pub fn new_anonymous(application_name: impl Into<String>) -> Self {
        Self::new()
            .application_name(application_name)
            .add_endpoint(
                "none",
                ServerEndpoint::new_none("/", &[ANONYMOUS_USER_TOKEN_ID.to_string()]),
            )
            .discovery_urls(vec!["/".to_owned()])
    }

    /// Creates and yields a builder which is configured with the sample server configuration.
    /// Use this for testing and similar reasons. Do not rely upon this in production code because it could change.
    pub fn new_sample() -> Self {
        warn!("Sample configuration is for testing purposes only. Use a proper configuration in your production environment");

        let user_token_ids = vec![
            ANONYMOUS_USER_TOKEN_ID,
            "sample_password_user",
            "sample_x509_user",
        ];
        let endpoint_path = "/";
        Self::new()
            .application_name("OPC UA Sample Server")
            .application_uri("urn:OPC UA Sample Server")
            .product_uri("urn:OPC UA Sample Server Testkit")
            .create_sample_keypair(true)
            .certificate_path("own/cert.der")
            .private_key_path("private/private.pem")
            .pki_dir("./pki")
            .discovery_server_url(constants::DEFAULT_DISCOVERY_SERVER_URL)
            .add_user_token(
                "sample_password_user",
                ServerUserToken {
                    user: "sample1".to_string(),
                    pass: Some("sample1pwd".to_string()),
                    ..Default::default()
                },
            )
            .add_user_token(
                "sample_x509_user",
                ServerUserToken {
                    user: "sample_x509".to_string(),
                    x509: Some("./users/sample-x509.der".to_string()),
                    ..Default::default()
                },
            )
            .add_endpoint(
                "none",
                (
                    endpoint_path,
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic128rsa15_sign",
                (
                    endpoint_path,
                    SecurityPolicy::Basic128Rsa15,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic128rsa15_sign_encrypt",
                (
                    endpoint_path,
                    SecurityPolicy::Basic128Rsa15,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic256_sign",
                (
                    endpoint_path,
                    SecurityPolicy::Basic256,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic256_sign_encrypt",
                (
                    endpoint_path,
                    SecurityPolicy::Basic256,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic256sha256_sign",
                (
                    endpoint_path,
                    SecurityPolicy::Basic256Sha256,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic256sha256_sign_encrypt",
                (
                    endpoint_path,
                    SecurityPolicy::Basic256Sha256,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "endpoint_aes128sha256rsaoaep_sign",
                (
                    endpoint_path,
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "endpoint_aes128sha256rsaoaep_sign_encrypt",
                (
                    endpoint_path,
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "endpoint_aes256sha256rsapss_sign",
                (
                    endpoint_path,
                    SecurityPolicy::Aes256Sha256RsaPss,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "endpoint_aes256sha256rsapss_sign_encrypt",
                (
                    endpoint_path,
                    SecurityPolicy::Aes256Sha256RsaPss,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids as &[&str],
                ),
            )
    }

    /// Get the currently configured config.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Load config from a local file.
    /// Will panic if this fails, if you prefer to propagate errors use
    ///
    /// `with_config(ServerConfig::load(&"my_config.conf".into())?)`
    pub fn with_config_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.config = ServerConfig::load(&path.into()).expect("Failed to load config");
        self
    }

    /// Set the entire config object, which may be loaded from somewhere else.
    pub fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// Get a mutable reference to the currently configured config.
    pub fn config_mut(&mut self) -> &mut ServerConfig {
        &mut self.config
    }

    /// Get a mutable reference to the limits object.
    pub fn limits_mut(&mut self) -> &mut Limits {
        &mut self.config.limits
    }

    /// Get the currently configured node managers.
    pub fn node_managers(&self) -> &[Arc<dyn NodeManager + Send + Sync + 'static>] {
        &self.node_managers
    }

    /// Add a node manager to the list of node managers.
    pub fn with_node_manager(
        mut self,
        node_manager: Arc<dyn NodeManager + Send + Sync + 'static>,
    ) -> Self {
        self.node_managers.push(node_manager);
        self
    }

    /// Clear all node managers.
    ///
    /// Warning: your server will not be compliant without presenting the core namespace.
    /// If you remove the core node manager you must implement the core namespace yourself.
    pub fn without_node_managers(mut self) -> Self {
        self.node_managers.clear();
        self
    }

    /// Set a custom authenticator.
    pub fn with_authenticator(mut self, authenticator: Arc<dyn AuthManager>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Server application name.
    pub fn application_name(mut self, application_name: impl Into<String>) -> Self {
        self.config.application_name = application_name.into();
        self
    }

    /// Server application URI.
    pub fn application_uri(mut self, application_uri: impl Into<String>) -> Self {
        self.config.application_uri = application_uri.into();
        self
    }

    /// Server product URI.
    pub fn product_uri(mut self, product_uri: impl Into<String>) -> Self {
        self.config.product_uri = product_uri.into();
        self
    }

    /// Autocreates public / private keypair if they do not exist.
    pub fn create_sample_keypair(mut self, create_sample_keypair: bool) -> Self {
        self.config.create_sample_keypair = create_sample_keypair;
        self
    }

    /// Path to a custom certificate, to be used instead of the default .der certificate
    pub fn certificate_path(mut self, certificate_path: impl Into<PathBuf>) -> Self {
        self.config.certificate_path = Some(certificate_path.into());
        self
    }

    /// Path to a custom private key, used instead of the default private key.
    pub fn private_key_path(mut self, private_key_path: impl Into<PathBuf>) -> Self {
        self.config.private_key_path = Some(private_key_path.into());
        self
    }

    /// Auto trust client certificates. Typically should only be used for testing
    /// or samples, as it is potentially unsafe.
    pub fn trust_client_certs(mut self, trust_client_certs: bool) -> Self {
        self.config.certificate_validation.trust_client_certs = trust_client_certs;
        self
    }

    /// Validate the valid from/to fields of a certificate.
    pub fn check_cert_time(mut self, check_cert_time: bool) -> Self {
        self.config.certificate_validation.check_time = check_cert_time;
        self
    }

    /// PKI folder, either absolute or relative to executable.
    pub fn pki_dir(mut self, pki_dir: impl Into<PathBuf>) -> Self {
        self.config.pki_dir = pki_dir.into();
        self
    }

    /// URL to a discovery server. Adding this makes the server attempt to register
    /// itself with this discovery server.
    pub fn discovery_server_url(mut self, url: impl Into<String>) -> Self {
        self.config.discovery_server_url = Some(url.into());
        self
    }

    /// Timeout for new connections to send a `HELLO` message, in seconds.
    /// After this timeout expires without a valid hello message, the connection
    /// is closed.
    pub fn hello_timeout(mut self, timeout: u32) -> Self {
        self.config.tcp_config.hello_timeout = timeout;
        self
    }

    /// Hostname to listen to incoming TCP connections on.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.tcp_config.host = host.into();
        self
    }

    /// Port number used to listen for incoming TCP connections.
    pub fn port(mut self, port: u16) -> Self {
        self.config.tcp_config.port = port;
        self
    }

    /// General server limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.config.limits = limits;
        self
    }

    /// Supported locale IDs.
    pub fn locale_ids(mut self, locale_ids: Vec<String>) -> Self {
        self.config.locale_ids = locale_ids;
        self
    }

    /// Add a user to the list of known user tokens. Used by the default
    /// authenticator, you can use a custom one instead.
    pub fn add_user_token(mut self, key: impl Into<String>, token: ServerUserToken) -> Self {
        self.config.user_tokens.insert(key.into(), token);
        self
    }

    /// List of discovery endpoint URLs which may or may not be the same as the service
    /// endpoints.
    pub fn discovery_urls(mut self, discovery_urls: Vec<String>) -> Self {
        self.config.discovery_urls = discovery_urls;
        self
    }

    /// Default endpoint ID.
    pub fn default_endpoint(mut self, endpoint_id: impl Into<String>) -> Self {
        self.config.default_endpoint = Some(endpoint_id.into());
        self
    }

    /// Add an endpoint to the list of endpoints supported by the server.
    pub fn add_endpoint(
        mut self,
        id: impl Into<String>,
        endpoint: impl Into<ServerEndpoint>,
    ) -> Self {
        self.config.endpoints.insert(id.into(), endpoint.into());
        self
    }

    /// Interval in milliseconds between each time the subscriptions are polled.
    pub fn subscription_poll_interval_ms(mut self, interval: u64) -> Self {
        self.config.subscription_poll_interval_ms = interval;
        self
    }

    /// Default publish request timeout.
    pub fn publish_timeout_default_ms(mut self, timeout: u64) -> Self {
        self.config.publish_timeout_default_ms = timeout;
        self
    }

    /// Max message timeout for non-publish requests.
    /// Will not be applied for requests that are handled synchronously.
    /// Set to 0 for no timeout, meaning that a timeout will only be applied if
    /// the client requests one.
    /// If this is greater than zero and the client requests a timeout of 0,
    /// this will be used.
    pub fn max_timeout_ms(mut self, timeout: u32) -> Self {
        self.config.max_timeout_ms = timeout;
        self
    }

    /// Maximum lifetime of secure channel tokens. The client will request a number,
    /// this just sets an upper limit on that value.
    /// Note that there is no lower limit, if a client sets an expiry of 0,
    /// we will just instantly time out.
    pub fn max_secure_channel_token_lifetime_ms(mut self, lifetime: u32) -> Self {
        self.config.max_secure_channel_token_lifetime_ms = lifetime;
        self
    }

    /// Try to construct a server from this builder, may fail if the configuration
    /// is invalid.
    pub fn build(self) -> Result<(ServerCore, ServerHandle), String> {
        ServerCore::new_from_builder(self)
    }

    /// Maximum length of arrays when encoding or decoding messages.
    pub fn max_array_length(mut self, max_array_length: usize) -> Self {
        self.config.limits.max_array_length = max_array_length;
        self
    }

    /// Maximum length of strings in bytes when encoding or decoding messages.
    pub fn max_string_length(mut self, max_string_length: usize) -> Self {
        self.config.limits.max_string_length = max_string_length;
        self
    }

    /// Maximum byte string length in bytes when encoding or decoding messages.
    pub fn max_byte_string_length(mut self, max_byte_string_length: usize) -> Self {
        self.config.limits.max_byte_string_length = max_byte_string_length;
        self
    }

    /// Maximum allowed message size in bytes.
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.config.limits.max_message_size = max_message_size;
        self
    }

    /// Maximum allowed chunk count per message.
    pub fn max_chunk_count(mut self, max_chunk_count: usize) -> Self {
        self.config.limits.max_chunk_count = max_chunk_count;
        self
    }

    /// Maximum send buffer size, can be negotiated lower with clients.
    pub fn send_buffer_size(mut self, send_buffer_size: usize) -> Self {
        self.config.limits.send_buffer_size = send_buffer_size;
        self
    }

    /// Maximum receive buffer size, can be negotiated lower with clients.
    pub fn receive_buffer_size(mut self, receive_buffer_size: usize) -> Self {
        self.config.limits.receive_buffer_size = receive_buffer_size;
        self
    }

    /// Maximum number of browse continuation points per session.
    pub fn max_browse_continuation_points(mut self, max_browse_continuation_points: usize) -> Self {
        self.config.limits.max_browse_continuation_points = max_browse_continuation_points;
        self
    }

    /// Maximum number of history continuation points per session.
    pub fn max_history_continuation_points(
        mut self,
        max_history_continuation_points: usize,
    ) -> Self {
        self.config.limits.max_history_continuation_points = max_history_continuation_points;
        self
    }

    /// Maximum number of query continuation points per session.
    pub fn max_query_continuation_points(mut self, max_query_continuation_points: usize) -> Self {
        self.config.limits.max_query_continuation_points = max_query_continuation_points;
        self
    }
}
