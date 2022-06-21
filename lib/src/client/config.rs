// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Client configuration data.

use std::{
    self,
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{
    core::config::Config,
    crypto::SecurityPolicy,
    types::{ApplicationType, MessageSecurityMode, UAString},
};

use super::session_retry_policy::SessionRetryPolicy;

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
        } else {
            if self.cert_path.is_none() && self.private_key_path.is_none() {
                error!(
                    "User token {} fails to provide a password or certificate info.",
                    self.user
                );
                valid = false;
            } else if self.cert_path.is_none() || self.private_key_path.is_none() {
                error!("User token {} fails to provide both a certificate path and a private key path.", self.user);
                valid = false;
            }
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
    pub max_message_size: usize,
    /// Maximum number of chunks in a message. 0 means no limit
    pub max_chunk_count: usize,
    /// Maximum length in bytes (not chars!) of a string. 0 actually means 0, i.e. no string permitted
    pub max_string_length: usize,
    /// Maximum length in bytes of a byte string. 0 actually means 0, i.e. no byte string permitted
    pub max_byte_string_length: usize,
    /// Maximum number of array elements. 0 actually means 0, i.e. no array permitted
    pub max_array_length: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Performance {
    /// Ignore clock skew allows the client to make a successful connection to the server, even
    /// when the client and server clocks are out of sync.
    pub ignore_clock_skew: bool,
    /// Use a single-threaded executor. The default executor uses a thread pool with a worker
    /// thread for each CPU core available on the system.
    pub single_threaded_executor: bool,
}

/// Client OPC UA configuration
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    /// Name of the application that the client presents itself as to the server
    pub application_name: String,
    /// The application uri
    pub application_uri: String,
    /// Product uri
    pub product_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub create_sample_keypair: bool,
    /// Custom certificate path, to be used instead of the default .der certificate path
    pub certificate_path: Option<PathBuf>,
    /// Custom private key path, to be used instead of the default private key path
    pub private_key_path: Option<PathBuf>,
    /// Auto trusts server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub trust_server_certs: bool,
    /// Verify server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub verify_server_certs: bool,
    /// PKI folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
    /// Preferred locales
    pub preferred_locales: Vec<String>,
    /// Identifier of the default endpoint
    pub default_endpoint: String,
    /// User tokens
    pub user_tokens: BTreeMap<String, ClientUserToken>,
    /// List of end points
    pub endpoints: BTreeMap<String, ClientEndpoint>,
    /// Decoding options used for serialization / deserialization
    pub decoding_options: DecodingOptions,
    /// Max retry limit -1, 0 or number
    pub session_retry_limit: i32,
    /// Retry interval in milliseconds
    pub session_retry_interval: u32,
    /// Session timeout period in milliseconds
    pub session_timeout: u32,
    /// Client performance settings
    pub performance: Performance,
    /// Session name
    pub session_name: String,
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

    pub fn new<T>(application_name: T, application_uri: T) -> Self
    where
        T: Into<String>,
    {
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
            session_retry_interval: SessionRetryPolicy::DEFAULT_RETRY_INTERVAL_MS,
            session_timeout: 0,
            decoding_options: DecodingOptions {
                max_array_length: decoding_options.max_array_length,
                max_string_length: decoding_options.max_string_length,
                max_byte_string_length: decoding_options.max_byte_string_length,
                max_chunk_count: decoding_options.max_chunk_count,
                max_message_size: decoding_options.max_message_size,
            },
            performance: Performance {
                ignore_clock_skew: false,
                single_threaded_executor: true,
            },
            session_name: "Rust OPC UA Client".into(),
        }
    }
}
