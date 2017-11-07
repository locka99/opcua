use std::path::PathBuf;
use std::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use opcua_types::MessageSecurityMode;
use opcua_types::constants as opcua_types_constants;
use opcua_types::url_matches_except_host;

use opcua_core::crypto::SecurityPolicy;
use opcua_core::config::Config;

use constants;

const DEFAULT_ENDPOINT_PATH: &'static str = "/";

pub const ANONYMOUS_USER_TOKEN_ID: &'static str = "anonymous";

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
    pub user: String,
    pub pass: Option<String>,
}

impl ServerUserToken {
    pub fn new_user_pass(user: &str, pass: &str) -> ServerUserToken {
        ServerUserToken {
            user: user.to_string(),
            pass: Some(pass.to_string())
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
    /// User tokens
    pub user_token_ids: BTreeSet<String>,
}

impl ServerEndpoint {
    pub fn new(path: &str, user_token_ids: &[String], security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> ServerEndpoint {
        ServerEndpoint {
            path: path.to_string(),
            security_policy: security_policy.to_string(),
            security_mode: security_mode.to_string(),
            user_token_ids: user_token_ids.iter().map(|id| id.clone()).collect(),
        }
    }

    pub fn new_none(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::None, MessageSecurityMode::None)
    }

    pub fn new_basic128rsa15_sign(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::Sign)
    }

    pub fn new_basic128rsa15_sign_encrypt(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt)
    }

    pub fn new_basic256_sign(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::Basic256, MessageSecurityMode::Sign)
    }

    pub fn new_basic256_sign_encrypt(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt)
    }

    pub fn new_basic256sha256_sign(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign)
    }

    pub fn new_basic256sha256_sign_encrypt(path: &str, user_token_ids: &[String]) -> ServerEndpoint {
        Self::new(path, user_token_ids, SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt)
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
    /// Url to a discovery server - adding this string causes the server to assume you wish to
    /// register the server with a discovery server.
    pub discovery_server_url: Option<String>,
    /// tcp configuration information
    pub tcp_config: TcpConfig,
    /// User tokens
    pub user_tokens: BTreeMap<String, ServerUserToken>,
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
            error!("Server configuration is invalid.  Max array length is invalid");
            valid = false;
        }
        if self.max_string_length == 0 {
            error!("Server configuration is invalid.  Max string length is invalid");
            valid = false;
        }
        if self.max_byte_string_length == 0 {
            error!("Server configuration is invalid.  Max byte string length is invalid");
            valid = false;
        }
        valid
    }
}

impl ServerConfig {
    pub fn new<T>(application_name: T, user_tokens: BTreeMap<String, ServerUserToken>, endpoints: BTreeMap<String, ServerEndpoint>) -> Self where T: Into<String> {
        let hostname = "127.0.0.1".to_string();

        let application_name = application_name.into();
        let application_uri = format!("urn:{}", application_name);
        let product_uri = format!("urn:{}", application_name);
        let pki_dir = PathBuf::from("./pki");

        ServerConfig {
            application_name,
            application_uri,
            product_uri,
            pki_dir,
            create_sample_keypair: false,
            discovery_server_url: None,
            tcp_config: TcpConfig {
                host: hostname,
                port: constants::DEFAULT_OPC_UA_SERVER_PORT,
                hello_timeout: constants::DEFAULT_HELLO_TIMEOUT_SECONDS,
            },
            user_tokens,
            endpoints,
            max_array_length: opcua_types_constants::MAX_ARRAY_LENGTH,
            max_string_length: opcua_types_constants::MAX_STRING_LENGTH,
            max_byte_string_length: opcua_types_constants::MAX_BYTE_STRING_LENGTH,
            max_subscriptions: constants::DEFAULT_MAX_SUBSCRIPTIONS,
        }
    }

    /// Create a server configuration that runs a server with no security and anonymous access enabled
    pub fn new_anonymous<T>(application_name: T) -> Self where T: Into<String> {
        let user_tokens = BTreeMap::new();
        let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID.to_string()];
        let mut endpoints = BTreeMap::new();
        endpoints.insert(
            "none".to_string(),
            ServerEndpoint::new_none(DEFAULT_ENDPOINT_PATH, &user_token_ids),
        );
        ServerConfig::new(application_name, user_tokens, endpoints)
    }

    /// Sample mode turns on everything including a hard coded user/pass
    pub fn new_sample() -> ServerConfig {
        warn!("Sample configuration is for testing purposes only. Use a proper configuration in your production environment");
        let application_name = "OPC UA Sample Server";

        let mut user_tokens = BTreeMap::new();

        let sample_user_id = "sample_user";
        user_tokens.insert(sample_user_id.to_string(), ServerUserToken {
            user: "sample".to_string(),
            pass: Some("sample1".to_string()),
        });
        user_tokens.insert("unused_user".to_string(), ServerUserToken {
            user: "unused".to_string(),
            pass: Some("unused1".to_string()),
        });

        let path = DEFAULT_ENDPOINT_PATH;
        let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID.to_string(), sample_user_id.to_string()];

        let mut endpoints = BTreeMap::new();
        endpoints.insert("none".to_string(), ServerEndpoint::new_none(path, &user_token_ids));
        endpoints.insert("basic128rsa15_sign".to_string(), ServerEndpoint::new_basic128rsa15_sign(path, &user_token_ids));
        endpoints.insert("basic128rsa15_sign_encrypt".to_string(), ServerEndpoint::new_basic128rsa15_sign_encrypt(path, &user_token_ids));
        endpoints.insert("basic256_sign".to_string(), ServerEndpoint::new_basic256_sign(path, &user_token_ids));
        endpoints.insert("basic256_sign_encrypt".to_string(), ServerEndpoint::new_basic256_sign_encrypt(path, &user_token_ids));
        endpoints.insert("basic256sha256_sign".to_string(), ServerEndpoint::new_basic256sha256_sign(path, &user_token_ids));
        endpoints.insert("basic256sha256_sign_encrypt".to_string(), ServerEndpoint::new_basic256sha256_sign_encrypt(path, &user_token_ids));
        endpoints.insert("no_access".to_string(), ServerEndpoint::new_none("/noaccess", &[]));
        let mut config = ServerConfig::new(application_name, user_tokens, endpoints);
        config.create_sample_keypair = true;
        config
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
                trace!("Found matching endpoint for url {} - {:?}", endpoint_url, e);
                if e.security_policy() == security_policy && e.message_security_mode() == security_mode {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        });
        if endpoint.is_some() {
            Some(endpoint.unwrap().1)
        } else {
            None
        }
    }
}