use std::{path::PathBuf, time::Duration};

use crate::{
    client::{Client, ClientBuilder},
    types::RegisteredServer,
};

use futures::never::Never;

#[cfg(windows)]
fn lds_pki_dir() -> String {
    if let Ok(mut pki_dir) = std::env::var("ALLUSERSPROFILE") {
        pki_dir.push_str(r#"\OPC Foundation\UA\pki"#);
        pki_dir
    } else {
        r#"C:\ProgramData\OPC Foundation\UA\pki"#.to_string()
    }
}

#[cfg(not(windows))]
fn lds_pki_dir() -> String {
    "/opt/opcfoundation/ualds/pki".to_owned()
}

async fn register_with_discovery_server(
    client: &mut Client,
    discovery_server_url: &str,
    registered_server: RegisteredServer,
) {
    match client.find_servers(discovery_server_url).await {
        Ok(servers) => {
            debug!("Servers on the discovery endpoint - {:?}", servers);
            match client
                .register_server(discovery_server_url, registered_server)
                .await
            {
                Ok(_) => {}
                Err(err) => {
                    error!(
                        r#"Cannot register server with discovery server \"{}\".
The errors immediately preceding this message may be caused by this issue.
Check if the error "{}" indicates the reason why that the registration could not happen.

Check that your server can connect to the discovery server and that your server's cert is trusted by
the discovery server and vice versa. The default discovery server PKI directory is {}."#,
                        discovery_server_url,
                        err,
                        lds_pki_dir()
                    );
                }
            }
        }
        Err(err) => {
            error!(
                "Cannot find servers on discovery url {}, error = {}",
                discovery_server_url, err
            );
        }
    }
}

#[cfg(not(feature = "discovery-server-registration"))]
fn periodic_discovery_server_registration(
    discovery_server_url: &str,
    _registered_server: RegisteredServer,
    _pki_dir: PathBuf,
    _interval: Duration,
) -> Never {
    info!(
        "Discovery server registration is disabled, registration with {} will not happen",
        discovery_server_url
    );
    futures::future::pending().await;
}

#[cfg(feature = "discovery-server-registration")]
pub(crate) async fn periodic_discovery_server_registration(
    discovery_server_url: &str,
    registered_server: RegisteredServer,
    pki_dir: PathBuf,
    interval: Duration,
) -> Never {
    let mut interval = tokio::time::interval(interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let client = ClientBuilder::new()
        .application_name("DiscoveryClient")
        .application_uri("urn:DiscoveryClient")
        .pki_dir(pki_dir)
        .session_retry_limit(1)
        .client();

    let Some(mut client) = client else {
        error!("Failed to create a valid client for discovery server registration");
        return futures::future::pending().await;
    };

    loop {
        interval.tick().await;

        register_with_discovery_server(
            &mut client,
            discovery_server_url,
            registered_server.clone(),
        )
        .await;
    }
}
