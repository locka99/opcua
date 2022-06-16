// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides configuration settings for the server including serialization and deserialization from file.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{
    core::{comms::url::url_matches_except_host, config::Config},
    crypto::{CertificateStore, SecurityPolicy, Thumbprint},
    types::{service_types::ApplicationType, DecodingOptions, MessageSecurityMode, UAString},
};

use super::constants;

pub const ANONYMOUS_USER_TOKEN_ID: &str = "ANONYMOUS";

const RECEIVE_BUFFER_SIZE: usize = std::u16::MAX as usize;
const SEND_BUFFER_SIZE: usize = std::u16::MAX as usize;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct TcpConfig {
    /// Timeout for hello on a session in seconds
    pub hello_timeout: u32,
    /// The hostname to supply in the endpoints
    pub host: String,
    /// The port number of the service
    pub port: u16,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerUserToken {
    /// User name
    pub user: String,
    /// Password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    // X509 file path (as a string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509: Option<String>,
    #[serde(skip)]
    pub thumbprint: Option<Thumbprint>,
}

impl ServerUserToken {
    /// Create a user pass token
    pub fn user_pass<T>(user: T, pass: T) -> Self
    where
        T: Into<String>,
    {
        ServerUserToken {
            user: user.into(),
            pass: Some(pass.into()),
            x509: None,
            thumbprint: None,
        }
    }

    /// Create an X509 token.
    pub fn x509<T>(user: T, cert_path: &Path) -> Self
    where
        T: Into<String>,
    {
        ServerUserToken {
            user: user.into(),
            pass: None,
            x509: Some(cert_path.to_string_lossy().to_string()),
            thumbprint: None,
        }
    }

    /// Read an X509 user token's certificate from disk and then hold onto the thumbprint for it.
    pub fn read_thumbprint(&mut self) {
        if self.is_x509() && self.thumbprint.is_none() {
            // As part of validation, we're going to try and load the x509 certificate from disk, and
            // obtain its thumbprint. This will be used when a session is activated.
            if let Some(ref x509_path) = self.x509 {
                let path = PathBuf::from(x509_path);
                if let Ok(x509) = CertificateStore::read_cert(&path) {
                    self.thumbprint = Some(x509.thumbprint());
                }
            }
        }
    }

    /// Test if the token is valid. This does not care for x509 tokens if the cert is present on
    /// the disk or not.
    pub fn is_valid(&self, id: &str) -> bool {
        let mut valid = true;
        if id == ANONYMOUS_USER_TOKEN_ID {
            error!(
                "User token {} is invalid because id is a reserved value, use another value.",
                id
            );
            valid = false;
        }
        if self.user.is_empty() {
            error!("User token {} has an empty user name.", id);
            valid = false;
        }
        if self.pass.is_some() && self.x509.is_some() {
            error!(
                "User token {} holds a password and certificate info - it cannot be both.",
                id
            );
            valid = false;
        } else if self.pass.is_none() && self.x509.is_none() {
            error!(
                "User token {} fails to provide a password or certificate info.",
                id
            );
            valid = false;
        }
        valid
    }

    pub fn is_user_pass(&self) -> bool {
        self.x509.is_none()
    }

    pub fn is_x509(&self) -> bool {
        self.x509.is_some()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Limits {
    /// Indicates if clients are able to modify the address space through the node management service
    /// set. This is a very broad flag and is likely to require more fine grained per user control
    /// in a later revision. By default, this value is `false`
    pub clients_can_modify_address_space: bool,
    /// Maximum number of subscriptions in a session, 0 for no limit
    pub max_subscriptions: usize,
    /// Maximum number of monitored items per subscription, 0 for no limit
    pub max_monitored_items_per_sub: usize,
    /// Maximum number of values in a monitored item queue
    pub max_monitored_item_queue_size: usize,
    /// Max array length in elements
    pub max_array_length: usize,
    /// Max string length in characters
    pub max_string_length: usize,
    /// Max bytestring length in bytes
    pub max_byte_string_length: usize,
    /// Specifies the minimum sampling interval for this server in seconds.
    pub min_sampling_interval: f64,
    /// Specifies the minimum publishing interval for this server in seconds.
    pub min_publishing_interval: f64,
    /// Maximum message length in bytes
    pub max_message_size: usize,
    /// Maximum chunk count
    pub max_chunk_count: usize,
    /// Send buffer size in bytes
    pub send_buffer_size: usize,
    /// Receive buffer size in bytes
    pub receive_buffer_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        let decoding_options = DecodingOptions::default();
        Self {
            max_array_length: decoding_options.max_array_length,
            max_string_length: decoding_options.max_string_length,
            max_byte_string_length: decoding_options.max_byte_string_length,
            max_subscriptions: constants::DEFAULT_MAX_SUBSCRIPTIONS,
            max_monitored_items_per_sub: constants::DEFAULT_MAX_MONITORED_ITEMS_PER_SUB,
            max_monitored_item_queue_size: constants::MAX_DATA_CHANGE_QUEUE_SIZE,
            max_message_size: decoding_options.max_message_size,
            max_chunk_count: decoding_options.max_chunk_count,
            clients_can_modify_address_space: false,
            min_sampling_interval: constants::MIN_SAMPLING_INTERVAL,
            min_publishing_interval: constants::MIN_PUBLISHING_INTERVAL,
            send_buffer_size: SEND_BUFFER_SIZE,
            receive_buffer_size: RECEIVE_BUFFER_SIZE,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct CertificateValidation {
    /// Auto trusts client certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub trust_client_certs: bool,
    /// Check the valid from/to fields of a certificate
    pub check_time: bool,
}

impl Default for CertificateValidation {
    fn default() -> Self {
        Self {
            trust_client_certs: false,
            check_time: true,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerEndpoint {
    /// Endpoint path
    pub path: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// Security level, higher being more secure
    pub security_level: u8,
    /// Password security policy when a client supplies a user name identity token
    pub password_security_policy: Option<String>,
    /// User tokens
    pub user_token_ids: BTreeSet<String>,
}

/// Convenience method to make an endpoint from a tuple
impl<'a> From<(&'a str, SecurityPolicy, MessageSecurityMode, &'a [&'a str])> for ServerEndpoint {
    fn from(v: (&'a str, SecurityPolicy, MessageSecurityMode, &'a [&'a str])) -> ServerEndpoint {
        ServerEndpoint {
            path: v.0.into(),
            security_policy: v.1.to_string(),
            security_mode: v.2.to_string(),
            security_level: Self::security_level(v.1, v.2),
            password_security_policy: None,
            user_token_ids: v.3.iter().map(|id| id.to_string()).collect(),
        }
    }
}

impl ServerEndpoint {
    pub fn new<T>(
        path: T,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_token_ids: &[String],
    ) -> Self
    where
        T: Into<String>,
    {
        ServerEndpoint {
            path: path.into(),
            security_policy: security_policy.to_string(),
            security_mode: security_mode.to_string(),
            security_level: Self::security_level(security_policy, security_mode),
            password_security_policy: None,
            user_token_ids: user_token_ids.iter().cloned().collect(),
        }
    }

    /// Recommends a security level for the supplied security policy
    fn security_level(security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> u8 {
        let security_level = match security_policy {
            SecurityPolicy::Basic128Rsa15 => 1,
            SecurityPolicy::Aes128Sha256RsaOaep => 2,
            SecurityPolicy::Basic256 => 3,
            SecurityPolicy::Basic256Sha256 => 4,
            SecurityPolicy::Aes256Sha256RsaPss => 5,
            _ => 0,
        };
        if security_mode == MessageSecurityMode::SignAndEncrypt {
            security_level + 10
        } else {
            security_level
        }
    }

    pub fn new_none<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::None,
            MessageSecurityMode::None,
            user_token_ids,
        )
    }

    pub fn new_basic128rsa15_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_basic128rsa15_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_basic256_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_basic256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_basic256sha256_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_basic256sha256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_aes128_sha256_rsaoaep_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_aes128_sha256_rsaoaep_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_aes256_sha256_rsapss_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_aes256_sha256_rsapss_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn is_valid(&self, id: &str, user_tokens: &BTreeMap<String, ServerUserToken>) -> bool {
        let mut valid = true;

        // Validate that the user token ids exist
        for id in &self.user_token_ids {
            // Skip anonymous
            if id == ANONYMOUS_USER_TOKEN_ID {
                continue;
            }
            if !user_tokens.contains_key(id) {
                error!("Cannot find user token with id {}", id);
                valid = false;
            }
        }

        if let Some(ref password_security_policy) = self.password_security_policy {
            let password_security_policy =
                SecurityPolicy::from_str(password_security_policy).unwrap();
            if password_security_policy == SecurityPolicy::Unknown {
                error!("Endpoint {} is invalid. Password security policy \"{}\" is invalid. Valid values are None, Basic128Rsa15, Basic256, Basic256Sha256", id, password_security_policy);
                valid = false;
            }
        }

        // Validate the security policy and mode
        let security_policy = SecurityPolicy::from_str(&self.security_policy).unwrap();
        let security_mode = MessageSecurityMode::from(self.security_mode.as_ref());
        if security_policy == SecurityPolicy::Unknown {
            error!("Endpoint {} is invalid. Security policy \"{}\" is invalid. Valid values are None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss,", id, self.security_policy);
            valid = false;
        } else if security_mode == MessageSecurityMode::Invalid {
            error!("Endpoint {} is invalid. Security mode \"{}\" is invalid. Valid values are None, Sign, SignAndEncrypt", id, self.security_mode);
            valid = false;
        } else if (security_policy == SecurityPolicy::None
            && security_mode != MessageSecurityMode::None)
            || (security_policy != SecurityPolicy::None
                && security_mode == MessageSecurityMode::None)
        {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (1).", id);
            valid = false;
        } else if security_policy != SecurityPolicy::None
            && security_mode == MessageSecurityMode::None
        {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (2).", id);
            valid = false;
        }
        valid
    }

    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_str(&self.security_policy).unwrap()
    }

    pub fn message_security_mode(&self) -> MessageSecurityMode {
        MessageSecurityMode::from(self.security_mode.as_ref())
    }

    pub fn endpoint_url(&self, base_endpoint: &str) -> String {
        format!("{}{}", base_endpoint, self.path)
    }

    /// Returns the effective password security policy for the endpoint. This is the explicitly set password
    /// security policy, or just the regular security policy.
    pub fn password_security_policy(&self) -> SecurityPolicy {
        let mut password_security_policy = self.security_policy();
        if let Some(ref security_policy) = self.password_security_policy {
            match SecurityPolicy::from_str(security_policy).unwrap() {
                SecurityPolicy::Unknown => {
                    panic!(
                        "Password security policy {} is unrecognized",
                        security_policy
                    );
                }
                security_policy => {
                    password_security_policy = security_policy;
                }
            }
        }
        password_security_policy
    }

    /// Test if the endpoint supports anonymous users
    pub fn supports_anonymous(&self) -> bool {
        self.supports_user_token_id(ANONYMOUS_USER_TOKEN_ID)
    }

    /// Tests if this endpoint supports user pass tokens. It does this by looking to see
    /// if any of the users allowed to access this endpoint are user pass users.
    pub fn supports_user_pass(&self, server_tokens: &BTreeMap<String, ServerUserToken>) -> bool {
        for user_token_id in &self.user_token_ids {
            if user_token_id != ANONYMOUS_USER_TOKEN_ID {
                if let Some(user_token) = server_tokens.get(user_token_id) {
                    if user_token.is_user_pass() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Tests if this endpoint supports x509 tokens.  It does this by looking to see
    /// if any of the users allowed to access this endpoint are x509 users.
    pub fn supports_x509(&self, server_tokens: &BTreeMap<String, ServerUserToken>) -> bool {
        for user_token_id in &self.user_token_ids {
            if user_token_id != ANONYMOUS_USER_TOKEN_ID {
                if let Some(user_token) = server_tokens.get(user_token_id) {
                    if user_token.is_x509() {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn supports_user_token_id(&self, id: &str) -> bool {
        self.user_token_ids.contains(id)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Performance {
    /// Use a single-threaded executor. The default executor uses a thread pool with a worker
    /// thread for each CPU core available on the system.
    pub single_threaded_executor: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    /// An id for this server
    pub application_name: String,
    /// A description for this server
    pub application_uri: String,
    /// Product url
    pub product_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub create_sample_keypair: bool,
    /// Path to a custom certificate, to be used instead of the default .der certificate
    pub certificate_path: Option<PathBuf>,
    /// Path to a custom private key, to be used instead of the default private key
    pub private_key_path: Option<PathBuf>,
    /// Checks the certificate's time validity
    pub certificate_validation: CertificateValidation,
    /// PKI folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
    /// Url to a discovery server - adding this string causes the server to assume you wish to
    /// register the server with a discovery server.
    pub discovery_server_url: Option<String>,
    /// tcp configuration information
    pub tcp_config: TcpConfig,
    /// Server OPA UA limits
    pub limits: Limits,
    /// Server Performance
    pub performance: Performance,
    /// Supported locale ids
    pub locale_ids: Vec<String>,
    /// User tokens
    pub user_tokens: BTreeMap<String, ServerUserToken>,
    /// discovery endpoint url which may or may not be the same as the service endpoints below.
    pub discovery_urls: Vec<String>,
    /// Default endpoint id
    pub default_endpoint: Option<String>,
    /// Endpoints supported by the server
    pub endpoints: BTreeMap<String, ServerEndpoint>,
}

impl Config for ServerConfig {
    fn is_valid(&self) -> bool {
        let mut valid = true;
        if self.application_name.is_empty() {
            warn!("No application was set");
        }
        if self.application_uri.is_empty() {
            warn!("No application uri was set");
        }
        if self.product_uri.is_empty() {
            warn!("No product uri was set");
        }
        if self.endpoints.is_empty() {
            error!("Server configuration is invalid. It defines no endpoints");
            valid = false;
        }
        for (id, endpoint) in &self.endpoints {
            if !endpoint.is_valid(id, &self.user_tokens) {
                valid = false;
            }
        }
        if let Some(ref default_endpoint) = self.default_endpoint {
            if !self.endpoints.contains_key(default_endpoint) {
                valid = false;
            }
        }
        for (id, user_token) in &self.user_tokens {
            if !user_token.is_valid(id) {
                valid = false;
            }
        }
        if self.limits.max_array_length == 0 {
            error!("Server configuration is invalid. Max array length is invalid");
            valid = false;
        }
        if self.limits.max_string_length == 0 {
            error!("Server configuration is invalid. Max string length is invalid");
            valid = false;
        }
        if self.limits.max_byte_string_length == 0 {
            error!("Server configuration is invalid. Max byte string length is invalid");
            valid = false;
        }
        if self.discovery_urls.is_empty() {
            error!("Server configuration is invalid. Discovery urls not set");
            valid = false;
        }
        valid
    }

    fn application_name(&self) -> UAString {
        UAString::from(&self.application_name)
    }

    fn application_uri(&self) -> UAString {
        UAString::from(&self.application_uri)
    }

    fn product_uri(&self) -> UAString {
        UAString::from(&self.product_uri)
    }

    fn application_type(&self) -> ApplicationType {
        ApplicationType::Server
    }

    fn discovery_urls(&self) -> Option<Vec<UAString>> {
        let discovery_urls: Vec<UAString> =
            self.discovery_urls.iter().map(UAString::from).collect();
        Some(discovery_urls)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push(Self::PKI_DIR);

        ServerConfig {
            application_name: String::new(),
            application_uri: String::new(),
            product_uri: String::new(),
            create_sample_keypair: false,
            certificate_path: None,
            private_key_path: None,
            pki_dir,
            certificate_validation: CertificateValidation::default(),
            discovery_server_url: None,
            tcp_config: TcpConfig {
                host: "127.0.0.1".to_string(),
                port: constants::DEFAULT_RUST_OPC_UA_SERVER_PORT,
                hello_timeout: constants::DEFAULT_HELLO_TIMEOUT_SECONDS,
            },
            limits: Limits::default(),
            user_tokens: BTreeMap::new(),
            locale_ids: vec!["en".to_string()],
            discovery_urls: Vec::new(),
            default_endpoint: None,
            endpoints: BTreeMap::new(),
            performance: Performance {
                single_threaded_executor: false,
            },
        }
    }
}

impl ServerConfig {
    /// The default PKI directory
    pub const PKI_DIR: &'static str = "pki";

    pub fn new<T>(
        application_name: T,
        user_tokens: BTreeMap<String, ServerUserToken>,
        endpoints: BTreeMap<String, ServerEndpoint>,
    ) -> Self
    where
        T: Into<String>,
    {
        let host = "127.0.0.1".to_string();
        let port = constants::DEFAULT_RUST_OPC_UA_SERVER_PORT;

        let application_name = application_name.into();
        let application_uri = format!("urn:{}", application_name);
        let product_uri = format!("urn:{}", application_name);
        let discovery_server_url = Some(constants::DEFAULT_DISCOVERY_SERVER_URL.to_string());
        let discovery_urls = vec![format!("opc.tcp://{}:{}/", host, port)];
        let locale_ids = vec!["en".to_string()];

        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push(Self::PKI_DIR);

        ServerConfig {
            application_name,
            application_uri,
            product_uri,
            create_sample_keypair: false,
            certificate_path: None,
            private_key_path: None,
            certificate_validation: CertificateValidation {
                trust_client_certs: false,
                check_time: true,
            },
            pki_dir,
            discovery_server_url,
            tcp_config: TcpConfig {
                host,
                port,
                hello_timeout: constants::DEFAULT_HELLO_TIMEOUT_SECONDS,
            },
            limits: Limits::default(),
            locale_ids,
            user_tokens,
            discovery_urls,
            default_endpoint: None,
            endpoints,
            performance: Performance {
                single_threaded_executor: false,
            },
        }
    }

    pub fn decoding_options(&self) -> DecodingOptions {
        DecodingOptions {
            client_offset: chrono::Duration::zero(),
            max_message_size: self.limits.max_message_size,
            max_chunk_count: self.limits.max_chunk_count,
            max_string_length: self.limits.max_string_length,
            max_byte_string_length: self.limits.max_byte_string_length,
            max_array_length: self.limits.max_array_length,
            ..Default::default()
        }
    }

    pub fn add_endpoint(&mut self, id: &str, endpoint: ServerEndpoint) {
        self.endpoints.insert(id.to_string(), endpoint);
    }

    pub fn read_x509_thumbprints(&mut self) {
        self.user_tokens
            .iter_mut()
            .for_each(|(_, token)| token.read_thumbprint());
    }

    /// Returns a opc.tcp://server:port url that paths can be appended onto
    pub fn base_endpoint_url(&self) -> String {
        format!(
            "opc.tcp://{}:{}",
            self.tcp_config.host, self.tcp_config.port
        )
    }

    /// Find the default endpoint
    pub fn default_endpoint(&self) -> Option<&ServerEndpoint> {
        if let Some(ref default_endpoint) = self.default_endpoint {
            self.endpoints.get(default_endpoint)
        } else {
            None
        }
    }

    /// Find the first endpoint that matches the specified url, security policy and message
    /// security mode.
    pub fn find_endpoint(
        &self,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> Option<&ServerEndpoint> {
        let base_endpoint_url = self.base_endpoint_url();
        let endpoint = self.endpoints.iter().find(|&(_, e)| {
            // Test end point's security_policy_uri and matching url
            if url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url) {
                if e.security_policy() == security_policy
                    && e.message_security_mode() == security_mode
                {
                    trace!("Found matching endpoint for url {} - {:?}", endpoint_url, e);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        });
        endpoint.map(|endpoint| endpoint.1)
    }
}
