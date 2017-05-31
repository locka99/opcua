use serde_yaml;

use std::path::{Path, PathBuf};
use std::io::prelude::*;
use std::fs::File;
use std::env;

use std::result::Result;

use opcua_core;
use opcua_core::types::MessageSecurityMode;
use opcua_core::comms::SecurityPolicy;

use constants;

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
pub struct ServerEndpoint {
    /// Name for the endpoint
    pub name: String,
    /// Endpoint path
    pub path: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// Allow anonymous access (default false)
    pub anonymous: Option<bool>,
    /// Allow user name / password access
    pub user: Option<String>,
    pub pass: Option<String>,
}

const DEFAULT_ENDPOINT_NAME: &'static str = "Default";
const DEFAULT_ENDPOINT_PATH: &'static str = "/";

impl ServerEndpoint {
    pub fn new(name: &str, path: &str, anonymous: bool, user: &str, pass: &[u8], security_policy: &str, security_mode: &str) -> ServerEndpoint {
        ServerEndpoint {
            name: name.to_string(),
            path: path.to_string(),
            anonymous: Some(anonymous),
            user: if user.is_empty() { None } else { Some(user.to_string()) },
            pass: if user.is_empty() { None } else { Some(String::from_utf8(pass.to_vec()).unwrap()) },
            security_policy: security_policy.to_string(),
            security_mode: security_mode.to_string(),
        }
    }

    pub fn new_default(anonymous: bool, user: &str, pass: &[u8], security_policy: &str, security_mode: &str) -> ServerEndpoint {
        ServerEndpoint::new(DEFAULT_ENDPOINT_NAME, DEFAULT_ENDPOINT_PATH, anonymous, user, pass, security_policy, security_mode)
    }

    pub fn default_anonymous() -> ServerEndpoint {
        ServerEndpoint::new_default(true, "", &[], opcua_core::constants::SECURITY_POLICY_NONE, opcua_core::constants::SECURITY_MODE_NONE)
    }

    pub fn default_user_pass(user: &str, pass: &[u8]) -> ServerEndpoint {
        ServerEndpoint::new_default(false, user, pass, opcua_core::constants::SECURITY_POLICY_NONE, opcua_core::constants::SECURITY_MODE_NONE)
    }

    pub fn default_sign_encrypt() -> ServerEndpoint {
        ServerEndpoint::new_default(false, "", &[], opcua_core::constants::SECURITY_POLICY_BASIC_128_RSA_15, opcua_core::constants::SECURITY_MODE_SIGN_AND_ENCRYPT)
    }

    pub fn is_valid(&self) -> bool {
        let mut valid = true;
        // Validate the username and password fields
        if (self.user.is_some() && self.pass.is_none()) || (self.user.is_none() && self.pass.is_some()) {
            error!("Endpoint {} is invalid. User / password both need to be set or not set, not just one or the other", self.name);
            valid = false;
        }
        // Validate the security policy and mode
        let security_policy = SecurityPolicy::from_str(&self.security_policy);
        let security_mode = MessageSecurityMode::from_str(&self.security_mode);
        if security_policy == SecurityPolicy::Unknown {
            error!("Endpoint {} is invalid. Security policy \"{}\" is invalid. Valid values are None, Basic128Rsa15, Basic256, Basic256Sha256", self.name, self.security_policy);
            valid = false;
        } else if security_mode == MessageSecurityMode::Invalid {
            error!("Endpoint {} is invalid. Security mode \"{}\" is invalid. Valid values are None, Sign, SignAndEncrypt", self.name, self.security_mode);
            valid = false;
        } else if security_policy == SecurityPolicy::None && security_mode == MessageSecurityMode::None {
            // None either means anonymous == true and/or user/pass is set
            if (self.anonymous.is_none() || !self.anonymous.as_ref().unwrap()) & &self.user.is_none() {
                error! ("Endpoint {} is invalid. Mode requires either anonymous or user/pass connections but anonymous is not set to true", self.name);
                valid = false;
            }
        } else if (security_policy == SecurityPolicy::None && security_mode != MessageSecurityMode::None) ||
            (security_policy != SecurityPolicy::None && security_mode == MessageSecurityMode::None) {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (1).", self.name);
            valid = false;
        } else if security_policy != SecurityPolicy::None && security_mode == MessageSecurityMode::None {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (2).", self.name);
            valid = false;
        }
        valid
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
    pub pki_dir: String,
    /// Flag turns on or off discovery service
    pub discovery_service: bool,
    /// tcp configuration information
    pub tcp_config: TcpConfig,
    /// Endpoints supported by the server
    pub endpoints: Vec<ServerEndpoint>,
    /// Maximum number of subscriptions in a session
    pub max_subscriptions: u32,
    /// Max array length in elements
    pub max_array_length: u32,
    /// Max string length in characters
    pub max_string_length: u32,
    /// Max bytestring length in bytes
    pub max_byte_string_length: u32,
}

impl ServerConfig {
    pub fn default(endpoints: Vec<ServerEndpoint>) -> ServerConfig {
        let application_name = "OPCUA-Rust".to_string();
        let hostname = "127.0.0.1".to_string();

        let application_uri = format!("urn:{}", application_name);
        let product_uri = format!("urn:{}", application_name);

        let pki_dir = if let Ok(mut pki_dir) = env::current_dir() {
            pki_dir.push("pki");
            pki_dir
        } else {
            PathBuf::from("./pki")
        };

        ServerConfig {
            application_name: application_name,
            application_uri: application_uri,
            product_uri: product_uri,
            discovery_service: true,
            pki_dir: pki_dir.into_os_string().into_string().unwrap(),
            tcp_config: TcpConfig {
                host: hostname,
                port: constants::DEFAULT_OPC_UA_SERVER_PORT,
                hello_timeout: constants::DEFAULT_HELLO_TIMEOUT_SECONDS,
            },
            endpoints: endpoints,
            max_array_length: opcua_core::constants::MAX_ARRAY_LENGTH,
            max_string_length: opcua_core::constants::MAX_STRING_LENGTH,
            max_byte_string_length: opcua_core::constants::MAX_BYTE_STRING_LENGTH,
            max_subscriptions: constants::DEFAULT_MAX_SUBSCRIPTIONS,
        }
    }

    /// Returns the default server configuration to run a server with no security and anonymous access enabled
    pub fn default_anonymous() -> ServerConfig {
        ServerConfig::default(vec![ServerEndpoint::default_anonymous()])
    }

    pub fn default_user_pass(user: &str, pass: &[u8]) -> ServerConfig {
        ServerConfig::default(vec![ServerEndpoint::default_user_pass(user, pass)])
    }

    pub fn default_secure() -> ServerConfig {
        ServerConfig::default(vec![ServerEndpoint::default_sign_encrypt()])
    }

    /// Sample mode turns on everything including a hard coded user/pass
    pub fn default_sample() -> ServerConfig {
        ServerConfig::default(vec![
            ServerEndpoint::default_user_pass("sample", b"sample1"),
            ServerEndpoint::default_sign_encrypt()
        ])
    }

    pub fn save(&self, path: &Path) -> Result<(), ()> {
        if self.is_valid() {
            let s = serde_yaml::to_string(&self).unwrap();
            if let Ok(mut f) = File::create(path) {
                if f.write_all(s.as_bytes()).is_ok() {
                    return Ok(());
                }
            }
        }
        Err(())
    }

    pub fn load(path: &Path) -> Result<ServerConfig, ()> {
        if let Ok(mut f) = File::open(path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                if let Ok(config) = serde_yaml::from_str(&s) {
                    return Ok(config)
                }
            }
        }
        Err(())
    }

    pub fn is_valid(&self) -> bool {
        let mut valid = true;
        if self.endpoints.is_empty() {
            error! ("Server configuration is invalid. It defines no endpoints");
            valid = false;
        }
        for e in self.endpoints.iter() {
            if !e.is_valid() {
                valid = false;
            }
        }
        if self.max_array_length == 0 {
            error! ("Server configuration is invalid.  Max array length is invalid");
            valid = false;
        }
        if self.max_string_length == 0 {
            error! ("Server configuration is invalid.  Max string length is invalid");
            valid = false;
        }
        if self.max_byte_string_length == 0 {
            error! ("Server configuration is invalid.  Max byte string length is invalid");
            valid = false;
        }
        valid
    }
}