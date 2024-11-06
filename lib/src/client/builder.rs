use std::path::PathBuf;

use tokio::time::Duration;

use crate::server::prelude::Config;

use super::{Client, ClientConfig, ClientEndpoint, ClientUserToken, ANONYMOUS_USER_TOKEN_ID};

#[derive(Default)]
pub struct ClientBuilder {
    config: ClientConfig,
}

impl ClientBuilder {
    /// Creates a `ClientBuilder`
    pub fn new() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Creates a `ClientBuilder` using a configuration file as the initial state.
    #[expect(clippy::result_unit_err)]
    pub fn from_config(path: impl Into<PathBuf>) -> Result<ClientBuilder, ()> {
        Ok(ClientBuilder {
            config: ClientConfig::load(&path.into())?,
        })
    }

    /// Yields a [`Client`] from the values set by the builder. If the builder is not in a valid state
    /// it will return `None`.
    ///
    /// [`Client`]: client/struct.Client.html
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
    pub fn application_name(mut self, application_name: impl Into<String>) -> Self {
        self.config.application_name = application_name.into();
        self
    }

    /// Sets the application uri
    pub fn application_uri(mut self, application_uri: impl Into<String>) -> Self {
        self.config.application_uri = application_uri.into();
        self
    }

    /// Sets the product uri.
    pub fn product_uri(mut self, product_uri: impl Into<String>) -> Self {
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
    pub fn certificate_path(mut self, certificate_path: impl Into<PathBuf>) -> Self {
        self.config.certificate_path = Some(certificate_path.into());
        self
    }

    /// Sets a custom private key path. The path is required to be provided as a partial path
    /// relative to the PKI directory. If set, this path will be used to read the private key
    /// from disk.
    pub fn private_key_path(mut self, private_key_path: impl Into<PathBuf>) -> Self {
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
    pub fn pki_dir(mut self, pki_dir: impl Into<PathBuf>) -> Self {
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
    pub fn default_endpoint(mut self, endpoint_id: impl Into<String>) -> Self {
        self.config.default_endpoint = endpoint_id.into();
        self
    }

    /// Adds an endpoint to the list of endpoints the client knows of.
    pub fn endpoint(mut self, endpoint_id: impl Into<String>, endpoint: ClientEndpoint) -> Self {
        self.config.endpoints.insert(endpoint_id.into(), endpoint);
        self
    }

    /// Adds multiple endpoints to the list of endpoints the client knows of.
    pub fn endpoints(mut self, endpoints: Vec<(impl Into<String>, ClientEndpoint)>) -> Self {
        for e in endpoints {
            self.config.endpoints.insert(e.0.into(), e.1);
        }
        self
    }

    /// Adds a user token to the list supported by the client.
    pub fn user_token(
        mut self,
        user_token_id: impl Into<String>,
        user_token: ClientUserToken,
    ) -> Self {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            panic!("User token id {} is reserved", user_token_id);
        }
        self.config.user_tokens.insert(user_token_id, user_token);
        self
    }

    /// Sets the maximum outgoing message size in bytes. 0 means no limit.
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.config.decoding_options.max_message_size = max_message_size;
        self
    }

    /// Sets the maximum number of chunks in an outgoing message. 0 means no limit.
    pub fn max_chunk_count(mut self, max_chunk_count: usize) -> Self {
        self.config.decoding_options.max_chunk_count = max_chunk_count;
        self
    }

    /// Maximum size of each individual outgoing message chunk.
    pub fn max_chunk_size(mut self, max_chunk_size: usize) -> Self {
        self.config.decoding_options.max_chunk_size = max_chunk_size;
        self
    }

    /// Maximum size of each incoming chunk.
    pub fn max_incoming_chunk_size(mut self, max_incoming_chunk_size: usize) -> Self {
        self.config.decoding_options.max_incoming_chunk_size = max_incoming_chunk_size;
        self
    }

    /// Maximum length in bytes of a string. 0 actually means 0, i.e. no string permitted.
    pub fn max_string_length(mut self, max_string_length: usize) -> Self {
        self.config.decoding_options.max_string_length = max_string_length;
        self
    }

    /// Maximum length in bytes of a byte string. 0 actually means 0, i.e. no byte strings permitted.
    pub fn max_byte_string_length(mut self, max_byte_string_length: usize) -> Self {
        self.config.decoding_options.max_byte_string_length = max_byte_string_length;
        self
    }

    /// Maximum number of array elements. 0 actually means 0, i.e. no array permitted
    pub fn max_array_length(mut self, max_array_length: usize) -> Self {
        self.config.decoding_options.max_array_length = max_array_length;
        self
    }

    /// Sets the session retry limit.
    ///
    /// # Panics
    ///
    /// Panics if `session_retry_limit` is less -1.
    pub fn session_retry_limit(mut self, session_retry_limit: i32) -> Self {
        if session_retry_limit < 0 && session_retry_limit != -1 {
            panic!("Session retry limit must be -1, 0 or a positive number");
        }
        self.config.session_retry_limit = session_retry_limit;
        self
    }

    /// Initial time between retries when backing off on session reconnects.
    pub fn session_retry_initial(mut self, session_retry_initial: Duration) -> Self {
        self.config.session_retry_initial = session_retry_initial;
        self
    }

    /// Maximum time between retries when backing off on session reconnects.
    pub fn session_retry_max(mut self, session_retry_max: Duration) -> Self {
        self.config.session_retry_max = session_retry_max;
        self
    }

    /// Time between making simple Read requests to the server to check for liveness
    /// and avoid session timeouts.
    pub fn keep_alive_interval(mut self, keep_alive_interval: Duration) -> Self {
        self.config.keep_alive_interval = keep_alive_interval;
        self
    }

    /// Set the timeout on requests sent to the server.
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.config.request_timeout = request_timeout;
        self
    }

    /// Set the timeout on publish requests sent to the server.
    pub fn publish_timeout(mut self, publish_timeout: Duration) -> Self {
        self.config.publish_timeout = publish_timeout;
        self
    }

    /// Set the lowest allowed publishing interval by the client.
    /// The server may also enforce its own minimum.
    pub fn min_publish_interval(mut self, min_publish_interval: Duration) -> Self {
        self.config.min_publish_interval = min_publish_interval;
        self
    }

    /// Maximum number of pending publish requests.
    pub fn max_inflight_publish(mut self, max_inflight_publish: usize) -> Self {
        self.config.max_inflight_publish = max_inflight_publish;
        self
    }

    /// Sets the session timeout period, in milliseconds.
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

    /// When a session is recreated on the server, the client will attempt to
    /// transfer monitored subscriptions from the old session to the new.
    /// This is the maximum number of monitored items to create per request.
    pub fn recreate_monitored_items_chunk(mut self, recreate_monitored_items_chunk: usize) -> Self {
        self.config.performance.recreate_monitored_items_chunk = recreate_monitored_items_chunk;
        self
    }

    /// Maximum number of inflight messages.
    pub fn max_inflight_messages(mut self, max_inflight_messages: usize) -> Self {
        self.config.performance.max_inflight_messages = max_inflight_messages;
        self
    }

    /// Session name - the default name to use for a new session
    pub fn session_name(mut self, session_name: impl Into<String>) -> Self {
        self.config.session_name = session_name.into();
        self
    }
}
