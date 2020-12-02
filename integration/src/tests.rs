use chrono::Utc;
use log::*;
use opcua_client::prelude::*;
use opcua_console_logging;
use opcua_server::{self, prelude::*};
use std::{
    sync::{mpsc, mpsc::channel, Arc, RwLock},
    thread,
};

use crate::harness::*;

fn endpoint_none() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::None.to_str(),
        MessageSecurityMode::None,
    )
        .into()
}

fn endpoint_basic128rsa15_sign() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Basic128Rsa15.to_str(),
        MessageSecurityMode::Sign,
    )
        .into()
}

fn endpoint_basic128rsa15_sign_encrypt() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Basic128Rsa15.to_str(),
        MessageSecurityMode::SignAndEncrypt,
    )
        .into()
}

fn endpoint_basic256_sign() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Basic256.to_str(),
        MessageSecurityMode::Sign,
    )
        .into()
}

fn endpoint_basic256_sign_encrypt() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Basic256.to_str(),
        MessageSecurityMode::SignAndEncrypt,
    )
        .into()
}

fn endpoint_basic256sha256_sign() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Basic256Sha256.to_str(),
        MessageSecurityMode::Sign,
    )
        .into()
}

fn endpoint_basic256sha256_sign_encrypt() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Basic256Sha256.to_str(),
        MessageSecurityMode::SignAndEncrypt,
    )
        .into()
}

fn endpoint_aes128sha256rsaoaep_sign() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Aes128Sha256RsaOaep.to_str(),
        MessageSecurityMode::Sign,
    )
        .into()
}

fn endpoint_aes128sha256rsaoaep_sign_encrypt() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Aes128Sha256RsaOaep.to_str(),
        MessageSecurityMode::SignAndEncrypt,
    )
        .into()
}

fn endpoint_aes256sha256rsapss_sign() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Aes256Sha256RsaPss.to_str(),
        MessageSecurityMode::Sign,
    )
        .into()
}

fn endpoint_aes256sha256rsapss_sign_encrypt() -> EndpointDescription {
    (
        "/",
        SecurityPolicy::Aes256Sha256RsaPss.to_str(),
        MessageSecurityMode::SignAndEncrypt,
    )
        .into()
}

/// This is the most basic integration test starting the server on a thread, setting an abort flag
/// and expecting the test to complete before it times out.
#[test]
#[ignore]
fn server_abort() {
    opcua_console_logging::init();

    let server = Arc::new(RwLock::new(new_server(0)));
    let server2 = server.clone();

    // This is pretty lame, but to tell if the thread has terminated or not, there is no try_join
    // so we will have the thread send a message when it is finishing via a receiver

    let (tx, rx) = channel();
    let _t = thread::spawn(move || {
        // This should run & block until it is told to abort
        Server::run_server(server);
        tx.send(()).unwrap();
    });

    {
        // Set the abort flag
        server2.write().unwrap().abort();
    }

    // Wait for the message or timeout to occur
    let timeout = 10000;
    let start_time = Utc::now();
    loop {
        if let Ok(_) = rx.try_recv() {
            info!("Abort test succeeded");
            break;
        }
        let now = Utc::now();
        let elapsed = now.signed_duration_since(start_time.clone());
        if elapsed.num_milliseconds() > timeout {
            panic!(
                "Abort test timed out after {} ms",
                elapsed.num_milliseconds()
            );
        }
    }
}

/// Start a server, send a HELLO message but then wait for the server
/// to timeout and drop the connection.
#[test]
#[ignore]
fn hello_timeout() {
    use std::io::Read;
    use std::net::TcpStream;

    let port = next_port();
    // For this test we want to set the hello timeout to a low value for the sake of speed.

    // The server will be a normal server, the client will just open the socket and keep the
    // socket open for longer than the timeout period. The server is expected to close the socket for the
    // test to pass.

    let client_test = move |_rx_client_command: mpsc::Receiver<ClientCommand>, _client: Client| {
        // Client will open a socket, and sit there waiting for the socket to close, which should happen in under the timeout_wait_duration
        let timeout_wait_duration = std::time::Duration::from_secs(
            opcua_server::constants::DEFAULT_HELLO_TIMEOUT_SECONDS as u64 + 3,
        );

        let host = crate::harness::hostname();
        let address = (host.as_ref(), port);
        debug!("Client is going to connect to port {:?}", address);

        let mut stream = TcpStream::connect(address).unwrap();
        let mut buf = [0u8];

        // Spin around for the timeout to finish and then try using the socket to see if it is still open.
        let start = std::time::Instant::now();
        loop {
            thread::sleep(std::time::Duration::from_millis(100));
            let now = std::time::Instant::now();
            if now - start > timeout_wait_duration {
                debug!("Timeout wait duration has passed, so trying to read from the socket");
                let result = stream.read(&mut buf);
                match result {
                    Ok(v) => {
                        if v > 0 {
                            panic!(
                                "Hello timeout exceeded and socket is still open, result = {}",
                                v
                            )
                        } else {
                            // From
                            debug!("Client got a read of 0 bytes on the socket, so treating by terminating with success");
                            break;
                        }
                    }
                    Err(err) => {
                        debug!(
                            "Client got an error {:?} on the socket terminating successfully",
                            err
                        );
                        break;
                    }
                }
            }
        }
    };

    let (client, server) = new_client_server(port);
    perform_test(client, server, Some(client_test), regular_server_test);
}

/// Start a server, fetch a list of endpoints, verify they are correct
#[test]
#[ignore]
fn get_endpoints() {
    // Connect to server and get a list of endpoints
    connect_with_get_endpoints(next_port());
}

/// Connect to the server using no encryption, anonymous
#[test]
#[ignore]
fn connect_none() {
    // Connect a session using None security policy and anonymous token.
    connect_with(next_port(), endpoint_none(), IdentityToken::Anonymous);
}

/// Connect to the server using Basic128Rsa15 + Sign
#[test]
#[ignore]
fn connect_basic128rsa15_sign() {
    // Connect a session with Basic128Rsa and Sign
    connect_with(
        next_port(),
        endpoint_basic128rsa15_sign(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Basic128Rsa15 + SignEncrypt
#[test]
#[ignore]
fn connect_basic128rsa15_sign_and_encrypt() {
    // Connect a session with Basic128Rsa and SignAndEncrypt
    connect_with(
        next_port(),
        endpoint_basic128rsa15_sign_encrypt(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Basic256 + Sign
#[test]
#[ignore]
fn connect_basic256_sign() {
    // Connect a session with Basic256 and Sign
    connect_with(
        next_port(),
        endpoint_basic256_sign(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Basic256 + SignEncrypt
#[test]
#[ignore]
fn connect_basic256_sign_and_encrypt() {
    // Connect a session with Basic256 and SignAndEncrypt
    connect_with(
        next_port(),
        endpoint_basic256_sign_encrypt(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Basic256Sha256 + Sign
#[test]
#[ignore]
fn connect_basic256sha256_sign() {
    // Connect a session with Basic256Sha256 and Sign
    connect_with(
        next_port(),
        endpoint_basic256sha256_sign(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Basic256Sha256 + SignEncrypt
#[test]
#[ignore]
fn connect_basic256sha256_sign_and_encrypt() {
    connect_with(
        next_port(),
        endpoint_basic256sha256_sign_encrypt(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Aes128Sha256RsaOaep + Sign
#[test]
#[ignore]
fn connect_aes128sha256rsaoaep_sign() {
    connect_with(
        next_port(),
        endpoint_aes128sha256rsaoaep_sign(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Aes128Sha256RsaOaep + SignEncrypt
#[test]
#[ignore]
fn connect_aes128sha256rsaoaep_sign_encrypt() {
    connect_with(
        next_port(),
        endpoint_aes128sha256rsaoaep_sign_encrypt(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Aes128Sha256RsaOaep + Sign
#[test]
#[ignore]
fn connect_aes256sha256rsapss_sign() {
    connect_with(
        next_port(),
        endpoint_aes256sha256rsapss_sign(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server using Aes128Sha256RsaOaep + SignEncrypt
#[test]
#[ignore]
fn connect_aes256sha256rsapss_sign_encrypt() {
    connect_with(
        next_port(),
        endpoint_aes256sha256rsapss_sign_encrypt(),
        IdentityToken::Anonymous,
    );
}

/// Connect to the server user/pass
#[test]
#[ignore]
fn connect_basic128rsa15_with_username_password() {
    // Connect a session using username/password token
    connect_with(
        next_port(),
        endpoint_basic128rsa15_sign_encrypt(),
        client_user_token(),
    );
}

/// Connect a session using an invalid username/password token and expect it to fail
#[test]
#[ignore]
fn connect_basic128rsa15_with_invalid_username_password() {
    connect_with_invalid_active_session(
        next_port(),
        endpoint_basic128rsa15_sign_encrypt(),
        client_invalid_user_token(),
    );
}

/// Connect a session using an X509 key and certificate
#[test]
#[ignore]
fn connect_basic128rsa15_with_x509_token() {
    connect_with(
        next_port(),
        endpoint_basic128rsa15_sign_encrypt(),
        client_x509_token(),
    );
}

/// Connect to a server, read a variable, write a value to the variable, read the variable to verify it changed
#[test]
#[ignore]
fn read_write_read() {
    let mut client_endpoint = endpoint_basic128rsa15_sign_encrypt();
    let port = next_port();
    let identity_token = client_x509_token();

    client_endpoint.endpoint_url =
        UAString::from(endpoint_url(port, client_endpoint.endpoint_url.as_ref()));
    connect_with_client_test(
        port,
        move |_rx_client_command: mpsc::Receiver<ClientCommand>, mut client: Client| {
            info!(
                "Client will try to connect to endpoint {:?}",
                client_endpoint
            );
            let session = client
                .connect_to_endpoint(client_endpoint, identity_token)
                .unwrap();

            let node_id = stress_node_id(1);

            // Read the existing value
            {
                let mut session = session.write().unwrap();
                let results = session.read(&[node_id.clone().into()]).unwrap();
                let value = &results[0];
                debug!("value = {:?}", value);
                assert_eq!(*value.value.as_ref().unwrap(), Variant::Int32(0))
            }

            {
                let mut session = session.write().unwrap();
                let results = session
                    .write(&[WriteValue {
                        node_id: node_id.clone(),
                        attribute_id: AttributeId::Value as u32,
                        index_range: UAString::null(),
                        value: Variant::Int32(1).into(),
                    }])
                    .unwrap()
                    .unwrap();
                let value = results[0];
                assert_eq!(value, StatusCode::Good);
            }

            {
                let mut session = session.write().unwrap();
                let results = session.read(&[node_id.into()]).unwrap();
                let value = &results[0];
                assert_eq!(*value.value.as_ref().unwrap(), Variant::Int32(1))
            }

            {
                let mut session = session.write().unwrap();
                session.disconnect();
            }
        },
    );
}

/// Connect with the server and attempt to subscribe and monitor 1000 variables
#[test]
#[ignore]
fn subscribe_1000() {
    let mut client_endpoint = endpoint_basic128rsa15_sign_encrypt();
    let port = next_port();
    let identity_token = client_x509_token();

    client_endpoint.endpoint_url =
        UAString::from(endpoint_url(port, client_endpoint.endpoint_url.as_ref()));
    connect_with_client_test(
        port,
        move |_rx_client_command: mpsc::Receiver<ClientCommand>, mut client: Client| {
            info!(
                "Client will try to connect to endpoint {:?}",
                client_endpoint
            );
            let session = client
                .connect_to_endpoint(client_endpoint, identity_token)
                .unwrap();
            let mut session = session.write().unwrap();

            let start_time = Utc::now();

            // Create subscription
            let subscription_id = session
                .create_subscription(
                    2000.0f64,
                    100,
                    100,
                    0,
                    0,
                    true,
                    DataChangeCallback::new(|_| {
                        panic!("This shouldn't be called");
                    }),
                )
                .unwrap();

            // NOTE: There is a default limit of 1000 items in arrays, so this list will go from 1 to 1000 inclusive

            // Create monitored items - the last one does not exist so expect that to fail
            let items_to_create = (0..1000)
                .map(|i| i + 1) // From v0001 to v1000
                .map(|i| (i, stress_node_id(i)))
                .map(|(i, node_id)| MonitoredItemCreateRequest {
                    item_to_monitor: node_id.into(),
                    monitoring_mode: MonitoringMode::Reporting,
                    requested_parameters: MonitoringParameters {
                        client_handle: i as u32,
                        sampling_interval: 1000.0f64,
                        filter: ExtensionObject::null(),
                        queue_size: 1,
                        discard_oldest: true,
                    },
                })
                .collect::<Vec<_>>();

            let elapsed = Utc::now() - start_time;
            assert!(elapsed.num_milliseconds() < 500i64);
            error!("Elapsed time = {}ms", elapsed.num_milliseconds());

            let results = session
                .create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create)
                .unwrap();
            results.iter().enumerate().for_each(|(i, result)| {
                if i == 999 {
                    // Last idx var does not exist so expect it to fail
                    error!("Checkout {}", result.status_code);
                    assert!(result.status_code.is_bad());
                } else {
                    assert!(result.status_code.is_good());
                }
            });

            session.disconnect();
        },
    );
}
