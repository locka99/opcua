use serde_yaml;

use std::path::Path;
use std::io::prelude::*;
use std::fs::File;

use std::result::Result;

use opcua_core::types::MessageSecurityMode;

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
}

impl ServerConfig {
    /// Returns the default server configuration to run a server with no security and anonymous access enabled
    pub fn default_anonymous() -> ServerConfig {
        let application_name = "OPCUA-Rust".to_string();
        let application_uri = format!("urn:{}", application_name);
        let product_uri = format!("urn:{}", application_name);
        ServerConfig {
            application_name: application_name,
            application_uri: application_uri,
            product_uri: product_uri,
            discovery_service: true,
            pki_dir: "pki".to_string(),
            tcp_config: TcpConfig {
                host: "127.0.0.1".to_string(),
                port: 1234,
                hello_timeout: 120,
            },
            endpoints: vec![ServerEndpoint {
                name: "Default".to_string(),
                path: "/".to_string(),
                security_policy: "None".to_string(),
                security_mode: "None".to_string(),
                anonymous: Some(true),
                user: None,
                pass: None,
            }],
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ()> {
        let s = serde_yaml::to_string(&self).unwrap();
        if let Ok(mut f) = File::create(path) {
            if f.write_all(s.as_bytes()).is_ok() {
                return Ok(());
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

    pub fn message_security_mode() -> MessageSecurityMode {
        MessageSecurityMode::None
    }
}