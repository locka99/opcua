use std;
use std::path::PathBuf;
use std::collections::BTreeMap;
use std::str::FromStr;

use opcua_types::MessageSecurityMode;
use opcua_core::config::Config;
use opcua_core::crypto::SecurityPolicy;

pub const ANONYMOUS_USER_TOKEN_ID: &str = "anonymous";

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientUserToken {
    /// Username
    pub user: String,
    /// Password
    pub password: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientEndpoint {
    /// Endpoint path
    pub url: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// User id to use with the endpoint
    #[serde(default = "ClientEndpoint::anonymous")]
    pub user_token_id: String
}

impl ClientEndpoint {
    fn anonymous() -> String {
        ANONYMOUS_USER_TOKEN_ID.to_string()
    }

    // Returns the security policy
    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_str(&self.security_policy).unwrap()
    }
}

/// Client OPC UA configuration
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    /// Name of the application that the client presents itself as to the server
    pub application_name: String,
    /// The application uri
    pub application_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub create_sample_keypair: bool,
    /// Auto trusts server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub trust_server_certs: bool,
    /// Product uri
    pub product_uri: String,
    /// pki folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
    /// Identifier of the default endpoint
    pub default_endpoint: String,
    /// User tokens
    pub user_tokens: BTreeMap<String, ClientUserToken>,
    /// List of end points
    pub endpoints: BTreeMap<String, ClientEndpoint>
}

impl Config for ClientConfig {
    fn is_valid(&self) -> bool {
        let mut valid = true;

        if self.user_tokens.contains_key(ANONYMOUS_USER_TOKEN_ID) {
            error!("User tokens contains the reserved \"{}\" id", ANONYMOUS_USER_TOKEN_ID);
            valid = false;
        }
        if self.user_tokens.contains_key("") {
            warn!("User tokens contains an endpoint with an empty id");
        }

        // Check for duplicate ids in endpoints
        if self.endpoints.contains_key("") {
            warn!("Endpoints contains an endpoint with an empty id");
        }

        // Check for invalid security policy and modes in endpoints
        for (id, e) in &self.endpoints {
            if SecurityPolicy::from_str(&e.security_policy).unwrap() != SecurityPolicy::Unknown {
                if MessageSecurityMode::Invalid == MessageSecurityMode::from(e.security_mode.as_ref()) {
                    error!("Endpoint {} security mode {} is invalid", id, e.security_mode);
                    valid = false;
                }
            } else {
                error!("Endpoint {} security policy {} is invalid", id, e.security_policy);
                valid = false;
            }
        }

        valid
    }
}

impl ClientConfig {
    pub fn new<T>(application_name: T, application_uri: T) -> Self where T: Into<String> {
        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push("pki");
        ClientConfig {
            application_name: application_name.into(),
            application_uri: application_uri.into(),
            create_sample_keypair: false,
            trust_server_certs: false,
            product_uri: String::new(),
            pki_dir,
            default_endpoint: String::new(),
            user_tokens: BTreeMap::new(),
            endpoints: BTreeMap::new()
        }
    }
}
