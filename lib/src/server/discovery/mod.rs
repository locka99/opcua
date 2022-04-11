// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::client::prelude::ClientBuilder;

use crate::server::state::ServerState;

// Note these two functions are presently informational, but in the future they could
// be used to automatically set up trust between LDS and server if the server
// were set via configuration to do that.

/// Returns the directory where the UA-LDS service stores its certs on Windows
fn windows_lds_pki_dir() -> String {
    /// Default derived from https://github.com/OPCFoundation/UA-LDS/blob/master/win32/platform.c
    const WINDOWS_LDS_PKI_DIR: &str = r#"C:\ProgramData\OPC Foundation\UA\pki"#;

    if cfg!(windows) {
        // On Windows the logic can check the environment variable like UA-LDS does
        if let Ok(mut pki_dir) = std::env::var("ALLUSERSPROFILE") {
            pki_dir.push_str(r#"\OPC Foundation\UA\pki"#);
            pki_dir
        } else {
            WINDOWS_LDS_PKI_DIR.to_string()
        }
    } else {
        WINDOWS_LDS_PKI_DIR.to_string()
    }
}

/// Returns the directory where the UA-LDS service stores its certs on Linux
fn linux_lds_pki_dir() -> String {
    /// Derived from https://github.com/OPCFoundation/UA-LDS/blob/master/linux/platform.c
    const LINUX_LDS_PKI_DIR: &str = "/opt/opcfoundation/ualds/pki";
    LINUX_LDS_PKI_DIR.to_string()
}

/// Registers the specified endpoints with the specified discovery server
pub fn register_with_discovery_server(discovery_server_url: &str, server_state: &ServerState) {
    debug!(
        "register_with_discovery_server, for {}",
        discovery_server_url
    );
    let server_config = trace_read_lock!(server_state.config);

    // Create a client, ensuring to retry only once
    let client = ClientBuilder::new()
        .application_name("DiscoveryClient")
        .application_uri("urn:DiscoveryClient")
        .pki_dir(server_config.pki_dir.clone())
        .session_retry_limit(1)
        .client();

    if let Some(mut client) = client {
        // This follows the local discovery process described in part 12 of the spec, calling
        // find_servers on it first.

        // Connect to the server and call find_servers to ensure it is a discovery server
        match client.find_servers(discovery_server_url) {
            Ok(servers) => {
                debug!("Servers on the discovery endpoint - {:?}", servers);
                // Register the server
                let registered_server = server_state.registered_server();
                match client.register_server(discovery_server_url, registered_server) {
                    Ok(_) => {}
                    Err(err) => {
                        error!(
                            r#"Cannot register server with discovery server \"{}\".
The errors immediately preceding this message may be caused by this issue.
Check if the error "{}" indicates the reason why that the registration could not happen.

Check that your server can connect to the discovery server and that your server's cert is trusted by
the discovery server and vice versa. The discovery server's PKI directory is (Windows)
{} or (Linux) {}."#,
                            discovery_server_url,
                            err,
                            windows_lds_pki_dir(),
                            linux_lds_pki_dir()
                        );
                    }
                }
            }
            Err(err) => {
                error!(
                    "Cannot find servers on discovery url {}, error = {:?}",
                    discovery_server_url, err
                );
            }
        }
    } else {
        error!("Cannot create a discovery server client config");
    }

    debug!("register_with_discovery_server, finished");
}
