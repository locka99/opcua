//! Provides configuration settings for the server including serialization and deserialization from file.
use std::path::PathBuf;
use std::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use opcua_types::{MessageSecurityMode, UAString, DecodingLimits};
use opcua_types::constants as opcua_types_constants;
use opcua_types::url_matches_except_host;

use opcua_core::crypto::SecurityPolicy;
use opcua_core::config::Config;

use crate::constants;

pub const ANONYMOUS_USER_TOKEN_ID: &str = "ANONYMOUS";

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
    // X509 file path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509: Option<PathBuf>,
}


impl ServerUserToken {
    pub fn new_user_pass<T>(user: T, pass: T) -> Self where T: Into<String> {
        ServerUserToken {
            user: user.into(),
            pass: Some(pass.into()),
            x509: None,
        }
    }

    pub fn is_valid(&self, id: &str) -> bool {
        let mut valid = true;
        if id == ANONYMOUS_USER_TOKEN_ID {
            error!("User token {} uses the reserved name \"anonymous\"", id);
            valid = false;
        }
        if self.user.is_empty() {
            error!("User token {} has an empty user name", id);
            valid = false;
        }
        if self.pass.is_some() && self.x509.is_some() {
            error!("User token {} has a password and a path to an x509 cert", id);
            valid = false;
        }
        if let Some(ref path) = self.x509 {
            if !path.exists() || !path.is_file() {
                error!("User token {} x509 cert does not exist", id);
                valid = false;
            }
        }
        valid
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
            security_level: Self::security_level(v.1),
            user_token_ids: v.3.iter().map(|id| id.to_string()).collect(),
        }
    }
}

impl ServerEndpoint {
    pub fn new<T>(path: T, security_policy: SecurityPolicy, security_mode: MessageSecurityMode, user_token_ids: &[String]) -> Self where T: Into<String> {
        ServerEndpoint {
            path: path.into(),
            security_policy: security_policy.to_string(),
            security_mode: security_mode.to_string(),
            security_level: Self::security_level(security_policy),
            user_token_ids: user_token_ids.iter().map(|id| id.clone()).collect(),
        }
    }

    /// Recommends a security level for the supplied security policy
    pub fn security_level(security_policy: SecurityPolicy) -> u8 {
        match security_policy {
            SecurityPolicy::None => 1,
            SecurityPolicy::Basic128Rsa15 => 2,
            SecurityPolicy::Basic256 => 3,
            SecurityPolicy::Basic256Sha256 => 4,
            _ => 0
        }
    }

    pub fn new_none<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::None, MessageSecurityMode::None, user_token_ids)
    }

    pub fn new_basic128rsa15_sign<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::Sign, user_token_ids)
    }

    pub fn new_basic128rsa15_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt, user_token_ids)
    }

    pub fn new_basic256_sign<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::Basic256, MessageSecurityMode::Sign, user_token_ids)
    }

    pub fn new_basic256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt, user_token_ids)
    }

    pub fn new_basic256sha256_sign<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign, user_token_ids)
    }

    pub fn new_basic256sha256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self where T: Into<String> {
        Self::new(path, SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, user_token_ids)
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

        // Validate the security policy and mode
        let security_policy = SecurityPolicy::from_str(&self.security_policy).unwrap();
        let security_mode = MessageSecurityMode::from(self.security_mode.as_ref());
        if security_policy == SecurityPolicy::Unknown {
            error!("Endpoint {} is invalid. Security policy \"{}\" is invalid. Valid values are None, Basic128Rsa15, Basic256, Basic256Sha256", id, self.security_policy);
            valid = false;
        } else if security_mode == MessageSecurityMode::Invalid {
            error!("Endpoint {} is invalid. Security mode \"{}\" is invalid. Valid values are None, Sign, SignAndEncrypt", id, self.security_mode);
            valid = false;
        } else if (security_policy == SecurityPolicy::None && security_mode != MessageSecurityMode::None) ||
            (security_policy != SecurityPolicy::None && security_mode == MessageSecurityMode::None) {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (1).", id);
            valid = false;
        } else if security_policy != SecurityPolicy::None && security_mode == MessageSecurityMode::None {
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

    /// Test if the endpoint supports anonymous users
    pub fn supports_anonymous(&self) -> bool {
        self.supports_user_token_id(ANONYMOUS_USER_TOKEN_ID)
    }

    pub fn supports_user_token_id(&self, id: &str) -> bool {
        self.user_token_ids.contains(id)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    /// An id for this server
    pub application_name: String,
    /// A description for this server
    pub application_uri: String,
    /// Product url
    pub product_uri: String,
    /// pki folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub create_sample_keypair: bool,
    /// Auto trusts client certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub trust_client_certs: bool,
    /// Url to a discovery server - adding this string causes the server to assume you wish to
    /// register the server with a discovery server.
    pub discovery_server_url: Option<String>,
    /// tcp configuration information
    pub tcp_config: TcpConfig,
    /// User tokens
    pub user_tokens: BTreeMap<String, ServerUserToken>,
    /// discovery endpoint url which may or may not be the same as the service endpoints below.
    pub discovery_urls: Vec<String>,
    /// Endpoints supported by the server
    pub endpoints: BTreeMap<String, ServerEndpoint>,
    /// Maximum number of subscriptions in a session
    pub max_subscriptions: u32,
    /// Max array length in elements
    pub max_array_length: u32,
    /// Max string length in characters
    pub max_string_length: u32,
    /// Max bytestring length in bytes
    pub max_byte_string_length: u32,
    /// Indicates if clients are able to modify the address space through the node management service
    /// set. This is a very broad flag and is likely to require more fine grained per user control
    /// in a later revision. By default, this value is `false`
    pub clients_can_modify_address_space: bool,
}

impl Config for ServerConfig {
    fn is_valid(&self) -> bool {
        let mut valid = true;
        if self.endpoints.is_empty() {
            error!("Server configuration is invalid. It defines no endpoints");
            valid = false;
        }
        for (id, endpoint) in &self.endpoints {
            if !endpoint.is_valid(&id, &self.user_tokens) {
                valid = false;
            }
        }
        for (id, user_token) in &self.user_tokens {
            if !user_token.is_valid(&id) {
                valid = false;
            }
        }
        if self.max_array_length == 0 {
            error!("Server configuration is invalid. Max array length is invalid");
            valid = false;
        }
        if self.max_string_length == 0 {
            error!("Server configuration is invalid. Max string length is invalid");
            valid = false;
        }
        if self.max_byte_string_length == 0 {
            error!("Server configuration is invalid. Max byte string length is invalid");
            valid = false;
        }
        if self.discovery_urls.is_empty() {
            error!("Server configuration is invalid. Discovery urls not set");
            valid = false;
        }
        valid
    }

    fn application_name(&self) -> UAString { UAString::from(self.application_name.as_ref()) }

    fn application_uri(&self) -> UAString { UAString::from(self.application_uri.as_ref()) }

    fn product_uri(&self) -> UAString { UAString::from(self.product_uri.as_ref()) }
}


impl Default for ServerConfig {
    fn default() -> Self {
        let pki_dir = PathBuf::from("./pki");
        ServerConfig {
            application_name: String::new(),
            application_uri: String::new(),
            product_uri: String::new(),
            pki_dir,
            create_sample_keypair: false,
            trust_client_certs: false,
            discovery_server_url: None,
            tcp_config: TcpConfig {
                host: "127.0.0.1".to_string(),
                port: constants::DEFAULT_RUST_OPC_UA_SERVER_PORT,
                hello_timeout: constants::DEFAULT_HELLO_TIMEOUT_SECONDS,
            },
            user_tokens: BTreeMap::new(),
            discovery_urls: Vec::new(),
            endpoints: BTreeMap::new(),
            max_array_length: opcua_types_constants::MAX_ARRAY_LENGTH as u32,
            max_string_length: opcua_types_constants::MAX_STRING_LENGTH as u32,
            max_byte_string_length: opcua_types_constants::MAX_BYTE_STRING_LENGTH as u32,
            max_subscriptions: constants::DEFAULT_MAX_SUBSCRIPTIONS,
            clients_can_modify_address_space: false,
        }
    }
}

impl ServerConfig {
    pub fn new<T>(application_name: T, user_tokens: BTreeMap<String, ServerUserToken>, endpoints: BTreeMap<String, ServerEndpoint>) -> Self where T: Into<String> {
        let host = "127.0.0.1".to_string();
        let port = constants::DEFAULT_RUST_OPC_UA_SERVER_PORT;

        let application_name = application_name.into();
        let application_uri = format!("urn:{}", application_name);
        let product_uri = format!("urn:{}", application_name);
        let pki_dir = PathBuf::from("./pki");
        let discovery_server_url = Some(constants::DEFAULT_DISCOVERY_SERVER_URL.to_string());
        let discovery_urls = vec![format!("opc.tcp://{}:{}/", host, port)];

        ServerConfig {
            application_name,
            application_uri,
            product_uri,
            pki_dir,
            create_sample_keypair: false,
            trust_client_certs: false,
            discovery_server_url,
            tcp_config: TcpConfig {
                host,
                port,
                hello_timeout: constants::DEFAULT_HELLO_TIMEOUT_SECONDS,
            },
            user_tokens,
            discovery_urls,
            endpoints,
            max_array_length: opcua_types_constants::MAX_ARRAY_LENGTH as u32,
            max_string_length: opcua_types_constants::MAX_STRING_LENGTH as u32,
            max_byte_string_length: opcua_types_constants::MAX_BYTE_STRING_LENGTH as u32,
            max_subscriptions: constants::DEFAULT_MAX_SUBSCRIPTIONS,
            clients_can_modify_address_space: false,
        }
    }

    pub fn decoding_limits(&self) -> DecodingLimits {
        DecodingLimits {
            max_string_length: self.max_string_length as usize,
            max_byte_string_length: self.max_byte_string_length as usize,
            max_array_length: self.max_array_length as usize,
        }
    }

    pub fn add_endpoint(&mut self, id: &str, endpoint: ServerEndpoint) {
        self.endpoints.insert(id.to_string(), endpoint);
    }

    /// Returns a opc.tcp://server:port url that paths can be appended onto
    pub fn base_endpoint_url(&self) -> String {
        format!("opc.tcp://{}:{}", self.tcp_config.host, self.tcp_config.port)
    }

    /// Find the first endpoint that matches the specified url, security policy and message
    /// security mode.
    pub fn find_endpoint(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> Option<&ServerEndpoint> {
        let base_endpoint_url = self.base_endpoint_url();
        let endpoint = self.endpoints.iter().find(|&(_, e)| {
            // Test end point's security_policy_uri and matching url
            if url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url) {
                if e.security_policy() == security_policy && e.message_security_mode() == security_mode {
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