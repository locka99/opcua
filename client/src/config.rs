use std;
use std::path::PathBuf;

use opcua_core::config::Config;

pub trait ClientUserToken {}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientEndpoint {
    /// Name for the endpoint
    pub name: String,
    /// Endpoint path
    pub url: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String
}

/// Client OPC UA configuration
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    pub application_name: String,
    pub application_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub create_sample_keypair: bool,
    /// Product uri
    pub product_uri: String,
    /// pki folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
    /// List of end points
    pub endpoints: Vec<ClientEndpoint>
}

impl Config for ClientConfig {
    fn is_valid(&self) -> bool {
        true
    }
}

impl ClientConfig {
    pub fn new(application_name: &str, application_uri: &str) -> Self {
        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push("pki");

        ClientConfig {
            application_name: application_name.to_string(),
            application_uri: application_uri.to_string(),
            create_sample_keypair: false,
            product_uri: String::new(),
            pki_dir,
            endpoints: Vec::new()
        }
    }

    #[cfg(test)]
    pub fn default_sample() -> Self {
        use std::path::PathBuf;
        use opcua_core::crypto::SecurityPolicy;
        use opcua_types::MessageSecurityMode;

        let pki_dir = PathBuf::from("./pki");
        let endpoints = vec![
            ClientEndpoint {
                name: String::from("sample_none"),
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from(SecurityPolicy::None.to_uri()),
                security_mode: String::from(MessageSecurityMode::None),
            },
            ClientEndpoint {
                name: String::from("sample_basic128rsa15"),
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_uri()),
                security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            },
            ClientEndpoint {
                name: String::from("sample_basic256"),
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from(SecurityPolicy::Basic256.to_uri()),
                security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            },
            ClientEndpoint {
                name: String::from("sample_basic256sha256"),
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from(SecurityPolicy::Basic256Sha256.to_uri()),
                security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            },
        ];

        ClientConfig {
            application_name: "OPC UA Sample Client".to_string(),
            application_uri: "urn:SampleClient".to_string(),
            create_sample_keypair: true,
            product_uri: String::new(),
            pki_dir,
            endpoints
        }
    }
}
