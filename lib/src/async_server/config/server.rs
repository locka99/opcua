// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Provides configuration settings for the server including serialization and deserialization from file.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    async_server::constants,
    core::{comms::url::url_matches_except_host, config::Config},
    crypto::{CertificateStore, SecurityPolicy, Thumbprint},
    server::prelude::{ApplicationDescription, LocalizedText},
    types::{service_types::ApplicationType, DecodingOptions, MessageSecurityMode, UAString},
};

use super::{endpoint::ServerEndpoint, limits::Limits};

pub const ANONYMOUS_USER_TOKEN_ID: &str = "ANONYMOUS";

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
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
pub struct ServerConfig {
    /// An id for this server
    pub application_name: String,
    /// A description for this server
    pub application_uri: String,
    /// Product url
    pub product_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    #[serde(default)]
    pub create_sample_keypair: bool,
    /// Path to a custom certificate, to be used instead of the default .der certificate
    #[serde(default)]
    pub certificate_path: Option<PathBuf>,
    /// Path to a custom private key, to be used instead of the default private key
    #[serde(default)]
    pub private_key_path: Option<PathBuf>,
    /// Checks the certificate's time validity
    #[serde(default)]
    pub certificate_validation: CertificateValidation,
    /// PKI folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
    /// Url to a discovery server - adding this string causes the server to assume you wish to
    /// register the server with a discovery server.
    #[serde(default)]
    pub discovery_server_url: Option<String>,
    /// tcp configuration information
    pub tcp_config: TcpConfig,
    /// Server OPA UA limits
    #[serde(default)]
    pub limits: Limits,
    /// Supported locale ids
    #[serde(default)]
    pub locale_ids: Vec<String>,
    /// User tokens
    pub user_tokens: BTreeMap<String, ServerUserToken>,
    /// discovery endpoint url which may or may not be the same as the service endpoints below.
    pub discovery_urls: Vec<String>,
    /// Default endpoint id
    #[serde(default)]
    pub default_endpoint: Option<String>,
    /// Endpoints supported by the server
    pub endpoints: BTreeMap<String, ServerEndpoint>,
    /// Interval in milliseconds between each time the subscriptions are polled.
    #[serde(default = "defaults::subscription_poll_interval_ms")]
    pub subscription_poll_interval_ms: u64,
    /// Default publish request timeout.
    #[serde(default = "defaults::publish_timeout_default_ms")]
    pub publish_timeout_default_ms: u64,
    /// Max message timeout for non-publish requests.
    /// Will not be applied for requests that are handled synchronously.
    /// Set to 0 for no timeout, meaning that a timeout will only be applied if
    /// the client requests one.
    /// If this is greater than zero and the client requests a timeout of 0,
    /// this will be used.
    #[serde(default = "defaults::max_timeout_ms")]
    pub max_timeout_ms: u32,
}

mod defaults {
    use crate::async_server::constants;

    pub fn subscription_poll_interval_ms() -> u64 {
        constants::SUBSCRIPTION_TIMER_RATE_MS
    }

    pub fn publish_timeout_default_ms() -> u64 {
        constants::DEFAULT_PUBLISH_TIMEOUT_MS
    }

    pub fn max_timeout_ms() -> u32 {
        300_000
    }
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

    fn application_description(&self) -> ApplicationDescription {
        ApplicationDescription {
            application_uri: self.application_uri(),
            application_name: LocalizedText::new("", self.application_name().as_ref()),
            application_type: self.application_type(),
            product_uri: self.product_uri(),
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: self.discovery_urls(),
        }
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
            subscription_poll_interval_ms: defaults::subscription_poll_interval_ms(),
            publish_timeout_default_ms: defaults::publish_timeout_default_ms(),
            max_timeout_ms: defaults::max_timeout_ms(),
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
            locale_ids,
            user_tokens,
            discovery_urls,
            endpoints,
            ..Default::default()
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
        base_endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> Option<&ServerEndpoint> {
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
