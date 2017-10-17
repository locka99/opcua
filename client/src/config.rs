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
    pub pki_dir: String,
}

impl Config for ClientConfig {
    fn is_valid(&self) -> bool {
        true
    }
}

impl ClientConfig {
    pub fn new() -> Self {
        ClientConfig {
            application_name: String::new(),
            application_uri: String::new(),
            create_sample_keypair: false,
            pki_dir: String::new(),
        }
    }
}
