// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Client configuration data.

use std::{
    self,
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
};

use tokio::time::Duration;

use crate::{
    core::config::Config,
    crypto::SecurityPolicy,
    types::{ApplicationType, MessageSecurityMode, UAString},
};

use super::retry::SessionRetryPolicy;

pub const ANONYMOUS_USER_TOKEN_ID: &str = "ANONYMOUS";

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientUserToken {
    /// Username
    pub user: String,
    /// Password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
}

impl ClientUserToken {
    /// Constructs a client token which holds a username and password.
    pub fn user_pass<S, T>(user: S, password: T) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        ClientUserToken {
            user: user.into(),
            password: Some(password.into()),
            cert_path: None,
            private_key_path: None,
        }
    }

    /// Constructs a client token which holds a username and paths to X509 certificate and private key.
    pub fn x509<S>(user: S, cert_path: &Path, private_key_path: &Path) -> Self
    where
        S: Into<String>,
    {
        // Apparently on Windows, a PathBuf can hold weird non-UTF chars but they will not
        // be stored in a config file properly in any event, so this code will lossily strip them out.
        ClientUserToken {
            user: user.into(),
            password: None,
            cert_path: Some(cert_path.to_string_lossy().to_string()),
            private_key_path: Some(private_key_path.to_string_lossy().to_string()),
        }
    }

    /// Test if the token, i.e. that it has a name, and either a password OR a cert path and key path.
    /// The paths are not validated.
    pub fn is_valid(&self) -> bool {
        let mut valid = true;
        if self.user.is_empty() {
            error!("User token has an empty name.");
            valid = false;
        }
        // A token must properly represent one kind of token or it is not valid
        if self.password.is_some() {
            if self.cert_path.is_some() || self.private_key_path.is_some() {
                error!(
                    "User token {} holds a password and certificate info - it cannot be both.",
                    self.user
                );
                valid = false;
            }
        } else if self.cert_path.is_none() && self.private_key_path.is_none() {
            error!(
                "User token {} fails to provide a password or certificate info.",
                self.user
            );
            valid = false;
        } else if self.cert_path.is_none() || self.private_key_path.is_none() {
            error!(
                "User token {} fails to provide both a certificate path and a private key path.",
                self.user
            );
            valid = false;
        }
        valid
    }
}

/// Describes an endpoint, it's url security policy, mode and user token
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientEndpoint {
    /// Endpoint path
    pub url: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// User id to use with the endpoint
    #[serde(default = "ClientEndpoint::anonymous_id")]
    pub user_token_id: String,
}

impl ClientEndpoint {
    /// Makes a client endpoint
    pub fn new<T>(url: T) -> Self
    where
        T: Into<String>,
    {
        ClientEndpoint {
            url: url.into(),
            security_policy: SecurityPolicy::None.to_str().into(),
            security_mode: MessageSecurityMode::None.into(),
            user_token_id: Self::anonymous_id(),
        }
    }

    fn anonymous_id() -> String {
        ANONYMOUS_USER_TOKEN_ID.to_string()
    }

    // Returns the security policy
    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_str(&self.security_policy).unwrap()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct DecodingOptions {
    /// Maximum size of a message chunk in bytes. 0 means no limit
    pub(crate) max_message_size: usize,
    /// Maximum number of chunks in a message. 0 means no limit
    pub(crate) max_chunk_count: usize,
    /// Maximum size of each individual sent message chunk.
    pub(crate) max_chunk_size: usize,
    /// Maximum size of each received chunk.
    pub(crate) max_incoming_chunk_size: usize,
    /// Maximum length in bytes (not chars!) of a string. 0 actually means 0, i.e. no string permitted
    pub(crate) max_string_length: usize,
    /// Maximum length in bytes of a byte string. 0 actually means 0, i.e. no byte string permitted
    pub(crate) max_byte_string_length: usize,
    /// Maximum number of array elements. 0 actually means 0, i.e. no array permitted
    pub(crate) max_array_length: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Performance {
    /// Ignore clock skew allows the client to make a successful connection to the server, even
    /// when the client and server clocks are out of sync.
    pub(crate) ignore_clock_skew: bool,
    /// Maximum number of monitored items per request when recreating subscriptions on session recreation.
    pub(crate) recreate_monitored_items_chunk: usize,
    /// Maximum number of inflight messages.
    pub(crate) max_inflight_messages: usize,
}

/// Client OPC UA configuration
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    /// Name of the application that the client presents itself as to the server
    pub(crate) application_name: String,
    /// The application uri
    pub(crate) application_uri: String,
    /// Product uri
    pub(crate) product_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub(crate) create_sample_keypair: bool,
    /// Custom certificate path, to be used instead of the default .der certificate path
    pub(crate) certificate_path: Option<PathBuf>,
    /// Custom private key path, to be used instead of the default private key path
    pub(crate) private_key_path: Option<PathBuf>,
    /// Auto trusts server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub(crate) trust_server_certs: bool,
    /// Verify server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub(crate) verify_server_certs: bool,
    /// PKI folder, either absolute or relative to executable
    pub(crate) pki_dir: PathBuf,
    /// Preferred locales
    pub(crate) preferred_locales: Vec<String>,
    /// Identifier of the default endpoint
    pub(crate) default_endpoint: String,
    /// User tokens
    pub(crate) user_tokens: BTreeMap<String, ClientUserToken>,
    /// List of end points
    pub(crate) endpoints: BTreeMap<String, ClientEndpoint>,
    /// Decoding options used for serialization / deserialization
    pub(crate) decoding_options: DecodingOptions,
    /// Maximum number of times to attempt to reconnect to the server before giving up.
    /// -1 retries forever
    pub(crate) session_retry_limit: i32,

    /// Initial delay for exponential backoff when reconnecting to the server.
    pub(crate) session_retry_initial: Duration,
    /// Max delay between retry attempts.
    pub(crate) session_retry_max: Duration,
    /// Interval between each keep-alive request sent to the server.
    pub(crate) keep_alive_interval: Duration,

    /// Timeout for each request sent to the server.
    pub(crate) request_timeout: Duration,
    /// Timeout for publish requests, separate from normal timeout since
    /// subscriptions are often more time sensitive.
    pub(crate) publish_timeout: Duration,
    /// Minimum publish interval. Setting this higher will make sure that subscriptions
    /// publish together, which may reduce the number of publish requests if you have a lot of subscriptions.
    pub(crate) min_publish_interval: Duration,
    /// Maximum number of inflight publish requests before further requests are skipped.
    pub(crate) max_inflight_publish: usize,

    /// Requested session timeout in milliseconds
    pub(crate) session_timeout: u32,

    /// Client performance settings
    pub(crate) performance: Performance,
    /// Session name
    pub(crate) session_name: String,
}

impl Config for ClientConfig {
    /// Test if the config is valid, which requires at the least that
    fn is_valid(&self) -> bool {
        let mut valid = true;

        if self.application_name.is_empty() {
            error!("Application name is empty");
            valid = false;
        }
        if self.application_uri.is_empty() {
            error!("Application uri is empty");
            valid = false;
        }
        if self.user_tokens.contains_key(ANONYMOUS_USER_TOKEN_ID) {
            error!(
                "User tokens contains the reserved \"{}\" id",
                ANONYMOUS_USER_TOKEN_ID
            );
            valid = false;
        }
        if self.user_tokens.contains_key("") {
            error!("User tokens contains an endpoint with an empty id");
            valid = false;
        }
        self.user_tokens.iter().for_each(|(_, token)| {
            if !token.is_valid() {
                valid = false;
            }
        });
        if self.endpoints.is_empty() {
            warn!("Endpoint config contains no endpoints");
        } else {
            // Check for invalid ids in endpoints
            if self.endpoints.contains_key("") {
                error!("Endpoints contains an endpoint with an empty id");
                valid = false;
            }
            if !self.default_endpoint.is_empty()
                && !self.endpoints.contains_key(&self.default_endpoint)
            {
                error!(
                    "Default endpoint id {} does not exist in list of endpoints",
                    self.default_endpoint
                );
                valid = false;
            }
            // Check for invalid security policy and modes in endpoints
            self.endpoints.iter().for_each(|(id, e)| {
                if SecurityPolicy::from_str(&e.security_policy).unwrap() != SecurityPolicy::Unknown
                {
                    if MessageSecurityMode::Invalid
                        == MessageSecurityMode::from(e.security_mode.as_ref())
                    {
                        error!(
                            "Endpoint {} security mode {} is invalid",
                            id, e.security_mode
                        );
                        valid = false;
                    }
                } else {
                    error!(
                        "Endpoint {} security policy {} is invalid",
                        id, e.security_policy
                    );
                    valid = false;
                }
            });
        }
        if self.session_retry_limit < 0 && self.session_retry_limit != -1 {
            error!("Session retry limit of {} is invalid - must be -1 (infinite), 0 (never) or a positive value", self.session_retry_limit);
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
        ApplicationType::Client
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new("", "")
    }
}

impl ClientConfig {
    /// The default PKI directory
    pub const PKI_DIR: &'static str = "pki";

    pub fn new(application_name: impl Into<String>, application_uri: impl Into<String>) -> Self {
        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push(Self::PKI_DIR);

        let decoding_options = crate::types::DecodingOptions::default();
        ClientConfig {
            application_name: application_name.into(),
            application_uri: application_uri.into(),
            create_sample_keypair: false,
            certificate_path: None,
            private_key_path: None,
            trust_server_certs: false,
            verify_server_certs: true,
            product_uri: String::new(),
            pki_dir,
            preferred_locales: Vec::new(),
            default_endpoint: String::new(),
            user_tokens: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            session_retry_limit: SessionRetryPolicy::DEFAULT_RETRY_LIMIT as i32,
            session_retry_initial: Duration::from_secs(1),
            session_retry_max: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            min_publish_interval: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(60),
            max_inflight_publish: 2,
            session_timeout: 0,
            decoding_options: DecodingOptions {
                max_array_length: decoding_options.max_array_length,
                max_string_length: decoding_options.max_string_length,
                max_byte_string_length: decoding_options.max_byte_string_length,
                max_chunk_count: decoding_options.max_chunk_count,
                max_message_size: decoding_options.max_message_size,
                max_chunk_size: 65535,
                max_incoming_chunk_size: 65535,
            },
            performance: Performance {
                ignore_clock_skew: false,
                recreate_monitored_items_chunk: 1000,
                max_inflight_messages: 20,
            },
            session_name: "Rust OPC UA Client".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{self, collections::BTreeMap, path::PathBuf};

    use crate::client::ClientBuilder;
    use crate::core::config::Config;
    use crate::crypto::SecurityPolicy;
    use crate::types::*;

    use super::{ClientConfig, ClientEndpoint, ClientUserToken, ANONYMOUS_USER_TOKEN_ID};

    fn make_test_file(filename: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(filename);
        path
    }

    pub fn sample_builder() -> ClientBuilder {
        ClientBuilder::new()
            .application_name("OPC UA Sample Client")
            .application_uri("urn:SampleClient")
            .create_sample_keypair(true)
            .certificate_path("own/cert.der")
            .private_key_path("private/private.pem")
            .trust_server_certs(true)
            .pki_dir("./pki")
            .endpoints(vec![
                (
                    "sample_none",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::None.to_str()),
                        security_mode: String::from(MessageSecurityMode::None),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
                (
                    "sample_basic128rsa15",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_str()),
                        security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
                (
                    "sample_basic256",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::Basic256.to_str()),
                        security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
                (
                    "sample_basic256sha256",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::Basic256Sha256.to_str()),
                        security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
            ])
            .default_endpoint("sample_none")
            .user_token(
                "sample_user",
                ClientUserToken::user_pass("sample1", "sample1pwd"),
            )
            .user_token(
                "sample_user2",
                ClientUserToken::user_pass("sample2", "sample2pwd"),
            )
    }

    pub fn default_sample_config() -> ClientConfig {
        sample_builder().config()
    }

    #[test]
    fn client_sample_config() {
        // This test exists to create the samples/client.conf file
        // This test only exists to dump a sample config
        let config = default_sample_config();
        let mut path = std::env::current_dir().unwrap();
        path.push("..");
        path.push("samples");
        path.push("client.conf");
        println!("Path is {:?}", path);

        let saved = config.save(&path);
        println!("Saved = {:?}", saved);
        assert!(saved.is_ok());
        assert!(config.is_valid());
    }

    #[test]
    fn client_config() {
        let path = make_test_file("client_config.yaml");
        println!("Client path = {:?}", path);
        let config = default_sample_config();
        let saved = config.save(&path);
        println!("Saved = {:?}", saved);
        assert!(config.save(&path).is_ok());
        if let Ok(config2) = ClientConfig::load(&path) {
            assert_eq!(config, config2);
        } else {
            panic!("Cannot load config from file");
        }
    }

    #[test]
    fn client_invalid_security_policy_config() {
        let mut config = default_sample_config();
        // Security policy is wrong
        config.endpoints = BTreeMap::new();
        config.endpoints.insert(
            String::from("sample_none"),
            ClientEndpoint {
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from("http://blah"),
                security_mode: String::from(MessageSecurityMode::None),
                user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
            },
        );
        assert!(!config.is_valid());
    }

    #[test]
    fn client_invalid_security_mode_config() {
        let mut config = default_sample_config();
        // Message security mode is wrong
        config.endpoints = BTreeMap::new();
        config.endpoints.insert(
            String::from("sample_none"),
            ClientEndpoint {
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_uri()),
                security_mode: String::from("SingAndEncrypt"),
                user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
            },
        );
        assert!(!config.is_valid());
    }

    #[test]
    fn client_anonymous_user_tokens_id() {
        let mut config = default_sample_config();
        // id anonymous is reserved
        config.user_tokens = BTreeMap::new();
        config.user_tokens.insert(
            String::from("ANONYMOUS"),
            ClientUserToken {
                user: String::new(),
                password: Some(String::new()),
                cert_path: None,
                private_key_path: None,
            },
        );
        assert!(!config.is_valid());
    }
}
