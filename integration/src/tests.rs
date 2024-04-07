use std::{sync::Arc, thread};

use chrono::Utc;
use log::*;

use opcua::client::{Client, DataChangeCallback, IdentityToken};
use opcua::server::prelude::*;
use opcua::sync::*;

use tokio::sync::mpsc::{self, unbounded_channel};

use crate::harness::*;

fn endpoint(
    port: u16,
    path: &str,
    _security_policy: SecurityPolicy,
    _message_security_mode: MessageSecurityMode,
) -> EndpointDescription {
    let mut endpoint =
        EndpointDescription::from(("", SecurityPolicy::None.to_str(), MessageSecurityMode::None));
    endpoint.endpoint_url = endpoint_url(port, path);
    endpoint
}

fn endpoint_none(port: u16) -> EndpointDescription {
    endpoint(port, "/", SecurityPolicy::None, MessageSecurityMode::None)
}

fn endpoint_basic128rsa15_sign(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::Sign,
    )
}

fn endpoint_basic128rsa15_sign_encrypt(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
    )
}

fn endpoint_basic256_sign(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Basic256,
        MessageSecurityMode::Sign,
    )
}

fn endpoint_basic256_sign_encrypt(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Basic256,
        MessageSecurityMode::SignAndEncrypt,
    )
}

fn endpoint_basic256sha256_sign(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::Sign,
    )
}

fn endpoint_basic256sha256_sign_encrypt(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::SignAndEncrypt,
    )
}

fn endpoint_aes128sha256rsaoaep_sign(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::Sign,
    )
}

fn endpoint_aes128sha256rsaoaep_sign_encrypt(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::SignAndEncrypt,
    )
}

fn endpoint_aes256sha256rsapss_sign(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::Sign,
    )
}

fn endpoint_aes256sha256rsapss_sign_encrypt(port: u16) -> EndpointDescription {
    endpoint(
        port,
        "/",
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::SignAndEncrypt,
    )
}

/// This is the most basic integration test starting the server on a thread, setting an abort flag
/// and expecting the test to complete before it times out.
#[test]
fn server_abort() {
    opcua::console_logging::init();

    let server = Arc::new(RwLock::new(new_server(0)));
    let server2 = server.clone();

    // This is pretty lame, but to tell if the thread has terminated or not, there is no try_join
    // so we will have the thread send a message when it is finishing via a receiver

    let (tx, mut rx) = unbounded_channel();
    let _t = thread::spawn(move || {
        // This should run & block until it is told to abort
        Server::run_server(server);
        tx.send(()).unwrap();
    });

    {
        // Set the abort flag
        server2.write().abort();
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
#[tokio::test]
async fn hello_timeout() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let port = next_port();
    // For this test we want to set the hello timeout to a low value for the sake of speed.

    // The server will be a normal server, the client will just open the socket and keep the
    // socket open for longer than the timeout period. The server is expected to close the socket for the
    // test to pass.

    let client_test = move |_rx_client_command: mpsc::UnboundedReceiver<ClientCommand>,
                            _client: Client| async move {
        // Client will open a socket, and sit there waiting for the socket to close, which should happen in under the timeout_wait_duration
        let timeout_wait_duration = std::time::Duration::from_secs(2);

        let host = crate::harness::hostname();
        let address = (host.as_ref(), port);
        let mut c = 0;
        // Getting a connection can sometimes take a few tries, since the server reports it is
        // ready before it actually is in some cases.
        let mut stream = loop {
            let stream = TcpStream::connect(address).await;
            if let Ok(stream) = stream {
                break stream;
            }
            c += 1;
            if c >= 10 {
                panic!("Failed to connect to server");
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        };
        debug!("Client is going to connect to port {:?}", address);

        let mut buf = [0u8];

        // Spin around for the timeout to finish and then try using the socket to see if it is still open.
        let start = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let now = std::time::Instant::now();
            if now - start > timeout_wait_duration {
                debug!("Timeout wait duration has passed, so trying to read from the socket");
                let result = stream.read(&mut buf).await;
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

    let (client, server) = new_client_server(port, false);
    perform_test(client, server, Some(client_test), regular_server_test).await;
}

/// Start a server, fetch a list of endpoints, verify they are correct
#[tokio::test]
async fn get_endpoints() {
    println!("Enter test");
    // Connect to server and get a list of endpoints
    connect_with_get_endpoints(next_port()).await;
}

/// Connect to the server using no encryption, anonymous
#[tokio::test]
async fn connect_none() {
    // Connect a session using None security policy and anonymous token.
    let port = next_port();
    connect_with(port, endpoint_none(port), IdentityToken::Anonymous).await;
}

/// Connect to the server using Basic128Rsa15 + Sign
#[tokio::test]
async fn connect_basic128rsa15_sign() {
    // Connect a session with Basic128Rsa and Sign
    let port = next_port();
    connect_with(
        port,
        endpoint_basic128rsa15_sign(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Basic128Rsa15 + SignEncrypt
#[tokio::test]
async fn connect_basic128rsa15_sign_and_encrypt() {
    // Connect a session with Basic128Rsa and SignAndEncrypt
    let port = next_port();
    connect_with(
        port,
        endpoint_basic128rsa15_sign_encrypt(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Basic256 + Sign
#[tokio::test]
async fn connect_basic256_sign() {
    // Connect a session with Basic256 and Sign
    let port = next_port();
    connect_with(port, endpoint_basic256_sign(port), IdentityToken::Anonymous).await;
}

/// Connect to the server using Basic256 + SignEncrypt
#[tokio::test]
async fn connect_basic256_sign_and_encrypt() {
    // Connect a session with Basic256 and SignAndEncrypt
    let port = next_port();
    connect_with(
        port,
        endpoint_basic256_sign_encrypt(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Basic256Sha256 + Sign
#[tokio::test]
async fn connect_basic256sha256_sign() {
    // Connect a session with Basic256Sha256 and Sign
    let port = next_port();
    connect_with(
        port,
        endpoint_basic256sha256_sign(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Basic256Sha256 + SignEncrypt
#[tokio::test]
async fn connect_basic256sha256_sign_and_encrypt() {
    let port = next_port();
    connect_with(
        port,
        endpoint_basic256sha256_sign_encrypt(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Aes128Sha256RsaOaep + Sign
#[tokio::test]
async fn connect_aes128sha256rsaoaep_sign() {
    let port = next_port();
    connect_with(
        port,
        endpoint_aes128sha256rsaoaep_sign(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Aes128Sha256RsaOaep + SignEncrypt
#[tokio::test]
async fn connect_aes128sha256rsaoaep_sign_encrypt() {
    let port = next_port();
    connect_with(
        port,
        endpoint_aes128sha256rsaoaep_sign_encrypt(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Aes128Sha256RsaOaep + Sign
#[tokio::test]
async fn connect_aes256sha256rsapss_sign() {
    let port = next_port();
    connect_with(
        port,
        endpoint_aes256sha256rsapss_sign(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server using Aes128Sha256RsaOaep + SignEncrypt
#[tokio::test]
async fn connect_aes256sha256rsapss_sign_encrypt() {
    let port = next_port();
    connect_with(
        port,
        endpoint_aes256sha256rsapss_sign_encrypt(port),
        IdentityToken::Anonymous,
    )
    .await;
}

/// Connect to the server user/pass
#[tokio::test]
async fn connect_basic128rsa15_with_username_password() {
    // Connect a session using username/password token
    let port = next_port();
    connect_with(
        port,
        endpoint_basic128rsa15_sign_encrypt(port),
        client_user_token(),
    )
    .await;
}

/// Connect a session using an invalid username/password token and expect it to fail
#[tokio::test]
async fn connect_basic128rsa15_with_invalid_username_password() {
    let port = next_port();
    connect_with_invalid_token(
        port,
        endpoint_basic128rsa15_sign_encrypt(port),
        client_invalid_user_token(),
    )
    .await;
}

/// Connect a session using an X509 key and certificate
#[tokio::test]
async fn connect_basic128rsa15_with_x509_token() {
    let port = next_port();
    connect_with(
        port,
        endpoint_basic128rsa15_sign_encrypt(port),
        client_x509_token(),
    )
    .await;
}

/// Connect to a server, read a variable, write a value to the variable, read the variable to verify it changed
#[tokio::test]
async fn read_write_read() {
    let port = next_port();
    let client_endpoint = endpoint_basic128rsa15_sign_encrypt(port);
    let identity_token = client_x509_token();
    connect_with_client_test(
        port,
        move |_rx_client_command: mpsc::UnboundedReceiver<ClientCommand>, mut client: Client| async move {
            info!(
                "Client will try to connect to endpoint {:?}",
                client_endpoint
            );
            let (session, event_loop) = client
                .new_session_from_endpoint(client_endpoint, identity_token)
                .await
                .unwrap();

            let handle = event_loop.spawn();
            session.wait_for_connection().await;

            let node_id = stress_node_id(1);

            // Read the existing value
            let results = session
                .read(&[node_id.clone().into()], TimestampsToReturn::Both, 1.0)
                .await
                .unwrap();
            let value = &results[0];
            debug!("value = {:?}", value);
            assert_eq!(*value.value.as_ref().unwrap(), Variant::Int32(0));

            let results = session
                .write(&[WriteValue {
                    node_id: node_id.clone(),
                    attribute_id: AttributeId::Value as u32,
                    index_range: UAString::null(),
                    value: Variant::Int32(1).into(),
                }])
                .await
                .unwrap();
            let value = results[0];
            assert_eq!(value, StatusCode::Good);

            let results = session
                .read(&[node_id.into()], TimestampsToReturn::Both, 1.0)
                .await
                .unwrap();
            let value = &results[0];
            assert_eq!(*value.value.as_ref().unwrap(), Variant::Int32(1));

            session.disconnect().await.unwrap();
            handle.await.unwrap();
        },
        false
    ).await;
}

/// Connect with the server and attempt to subscribe and monitor 1000 variables
#[tokio::test]
async fn subscribe_1000() {
    let port = next_port();
    let client_endpoint = endpoint_basic128rsa15_sign_encrypt(port);
    let identity_token = client_x509_token();

    connect_with_client_test(
        port,
        move |_rx_client_command: mpsc::UnboundedReceiver<ClientCommand>, mut client: Client| async move {
            info!(
                "Client will try to connect to endpoint {:?}",
                client_endpoint
            );
            let (session, event_loop) = client
                .new_session_from_endpoint(client_endpoint, identity_token)
                .await
                .unwrap();

            let handle = event_loop.spawn();
            session.wait_for_connection().await;

            let start_time = Utc::now();

            // Create subscription
            let subscription_id = session
                .create_subscription(
                    std::time::Duration::from_secs(2),
                    100,
                    100,
                    0,
                    0,
                    true,
                    DataChangeCallback::new(|_, _| {
                        panic!("This shouldn't be called");
                    }),
                )
                .await
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
                .create_monitored_items(subscription_id, TimestampsToReturn::Both, items_to_create)
                .await
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

            session.disconnect().await.unwrap();
            handle.await.unwrap();
        },
        false
    ).await;
}

#[tokio::test]
async fn method_call() {
    // Call a method on the server, one exercising some parameters in and out
    let port = next_port();
    let client_endpoint = endpoint_none(port);

    connect_with_client_test(
        port,
        move |_rx_client_command: mpsc::UnboundedReceiver<ClientCommand>, mut client: Client| async move {
            info!(
                "Client will try to connect to endpoint {:?}",
                client_endpoint
            );
            let (session, event_loop) = client
                .new_session_from_endpoint(client_endpoint, IdentityToken::Anonymous)
                .await
                .unwrap();

            let handle = event_loop.spawn();
            session.wait_for_connection().await;

            // Call the method
            let input_arguments = Some(vec![Variant::from("Foo")]);
            let method = CallMethodRequest {
                object_id: functions_object_id(),
                method_id: hellox_method_id(),
                input_arguments,
            };
            let result = session.call(method).await.unwrap();

            // Result should say "Hello Foo"
            assert!(result.status_code.is_good());
            let output_args = result.output_arguments.unwrap();
            assert_eq!(output_args.len(), 1);
            let msg = output_args.get(0).unwrap();
            assert_eq!(msg.to_string(), "Hello Foo!");

            session.disconnect().await.unwrap();
            handle.await.unwrap();
        },
        false
    ).await;
}
