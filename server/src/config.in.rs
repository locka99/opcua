use serde_yaml;

use std::path::Path;
use std::io::prelude::*;
use std::fs::File;

use std::result::Result;

use opcua_core::types::MessageSecurityMode;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    /// An id for this config
    pub id: String,
    /// A description for this config
    pub description: String,
    /// The hostname to supply in the endpoints
    pub host: String,
    /// The port number of the service
    pub port: u16,
    /// Path on the endpoint
    pub path: String,
    /// Timeout for hello on a session in seconds
    pub hello_timeout: u32,
}

impl ServerConfig {
    /// Returns the default server configuration.
    pub fn default() -> ServerConfig {
        ServerConfig {
            id: "".to_string(),
            description: "".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1234,
            path: "/".to_string(),
            hello_timeout: 120,
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