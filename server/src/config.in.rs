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
    pub security_policy: String,
    pub security_mode: String,
    pub user_name: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    /// An id for this server
    pub application_name: String,
    /// A description for this server
    pub application_url: String,
    /// Default endpoint
    pub default_path: String,
    /// pki folder, either absolute or relative to executable
    pub pki_dir: String,
    /// tcp configuration information
    pub tcp_config: TcpConfig,
    /// Endpoints supported by the server
    pub endpoints: Vec<ServerEndpoint>,
}

impl ServerConfig {
    /// Returns the default server configuration.
    pub fn default() -> ServerConfig {
        ServerConfig {
            application_name: "OPC UA".to_string(),
            application_url: "".to_string(),
            default_path: "/",
            pki_dir: "pki",
            tcp_config: TcpConfig {
                host: "127.0.0.1".to_string(),
                port: 1234,
                hello_timeout: 120,
            },
            endpoints: vec![ServerEndpoint {
                name: "Default",
                path: "/",
                security_policy: "None",
                security_mode: "None",
                user_name: "",
                password: "",
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