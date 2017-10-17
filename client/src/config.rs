use std;
use std::path::PathBuf;

use opcua_core::config::Config;

pub trait ClientUserToken {}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientEndpoint {
    /// Name for the endpoint
    pub name: String,
    /// Endpoint path
    pub path: String,
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
    /// pki folder, either absolute or relative to executable
    pub pki_dir: PathBuf,
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
            pki_dir,
        }
    }

    pub fn new_sample() -> Self {
        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push("pki");

        ClientConfig {
            application_name: "OPC UA Sample Client".to_string(),
            application_uri: String::new(),
            create_sample_keypair: true,
            pki_dir,
        }
    }
}
