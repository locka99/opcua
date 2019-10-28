use std::{
    sync::{
        Arc, mpsc, mpsc::channel,
        RwLock,
    },
    thread,
};

use chrono::Utc;
use log::*;

use opcua_client::prelude::*;
use opcua_console_logging;
use opcua_server::{
    self,
    prelude::*,
};

use crate::harness::*;

fn endpoint_none() -> EndpointDescription {
    ("/", SecurityPolicy::None.to_str(), MessageSecurityMode::None).into()
}

fn endpoint_basic128rsa15_sign() -> EndpointDescription {
    ("/", SecurityPolicy::Basic128Rsa15.to_str(), MessageSecurityMode::Sign).into()
}

fn endpoint_basic128rsa15_sign_encrypt() -> EndpointDescription {
    ("/", SecurityPolicy::Basic128Rsa15.to_str(), MessageSecurityMode::SignAndEncrypt).into()
}

fn endpoint_basic256_sign() -> EndpointDescription {
    ("/", SecurityPolicy::Basic256.to_str(), MessageSecurityMode::Sign).into()
}

fn endpoint_basic256_sign_encrypt() -> EndpointDescription {
    ("/", SecurityPolicy::Basic256.to_str(), MessageSecurityMode::SignAndEncrypt).into()
}

fn endpoint_basic256sha256_sign() -> EndpointDescription {
    ("/", SecurityPolicy::Basic256Sha256.to_str(), MessageSecurityMode::Sign).into()
}

fn endpoint_basic256sha256_sign_encrypt() -> EndpointDescription {
    ("/", SecurityPolicy::Basic256Sha256.to_str(), MessageSecurityMode::SignAndEncrypt).into()
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
            panic!("Abort test timed out after {} ms", elapsed.num_milliseconds());
        }
    }
}

/// Start a server, send a HELLO message but then wait for the server
/// to timeout and drop the connection.
#[test]
#[ignore]
fn hello_timeout() {
    use std::net::TcpStream;
    use std::io::Read;

    let port = next_port();
    // For this test we want to set the hello timeout to a low value for the sake of speed.

    // The server will be a normal server, the client will just open the socket and keep the
    // socket open for longer than the timeout period. The server is expected to close the socket for the
    // test to pass.

    let client_test = move |_rx_client_command: mpsc::Receiver<ClientCommand>, _client: Client| {
        // Client will open a socket, and sit there waiting for the socket to close, which should happen in under the timeout_wait_duration
        let timeout_wait_duration = std::time::Duration::from_secs(opcua_server::constants::DEFAULT_HELLO_TIMEOUT_SECONDS as u64 + 3);

        let host = hostname();
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
                            panic!("Hello timeout exceeded and socket is still open, result = {}", v)
                        } else {
                            // From
                            debug!("Client got a read of 0 bytes on the socket, so treating by terminating with success");
                            break;
                        }
                    }
                    Err(err) => {
                        debug!("Client got an error {:?} on the socket terminating successfully", err);
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
    connect_with(next_port(), endpoint_basic128rsa15_sign(), IdentityToken::Anonymous);
}

/// Connect to the server using Basic128Rsa15 + SignEncrypt
#[test]
#[ignore]
fn connect_basic128rsa15_sign_and_encrypt() {
    // Connect a session with Basic128Rsa and SignAndEncrypt
    connect_with(next_port(), endpoint_basic128rsa15_sign_encrypt(), IdentityToken::Anonymous);
}

/// Connect to the server using Basic256 + Sign
#[test]
#[ignore]
fn connect_basic256_sign() {
    // Connect a session with Basic256 and Sign
    connect_with(next_port(), endpoint_basic256_sign(), IdentityToken::Anonymous);
}

/// Connect to the server using Basic256 + SignEncrypt
#[test]
#[ignore]
fn connect_basic256_sign_and_encrypt() {
    // Connect a session with Basic256 and SignAndEncrypt
    connect_with(next_port(), endpoint_basic256_sign_encrypt(), IdentityToken::Anonymous);
}

/// Connect to the server using Basic256Sha256 + Sign
#[test]
#[ignore]
fn connect_basic256sha256_sign() {
    // Connect a session with Basic256Sha256 and Sign
    connect_with(next_port(), endpoint_basic256sha256_sign(), IdentityToken::Anonymous);
}

/// Connect to the server using Basic256Sha256 + SignEncrypt
#[test]
#[ignore]
fn connect_basic256sha256_sign_and_encrypt() {
    // Connect a session with Basic256Sha256 and SignAndEncrypt
    connect_with(next_port(), endpoint_basic256sha256_sign_encrypt(), IdentityToken::Anonymous);
}

/// Connect to the server user/pass
#[test]
#[ignore]
fn connect_basic128rsa15_with_username_password() {
    // Connect a session using username/password token
    connect_with(next_port(), endpoint_basic128rsa15_sign_encrypt(), client_user_token());
}

#[test]
#[ignore]
fn connect_basic128rsa15_with_invalid_username_password() {
    // Connect a session using an invalid username/password token and expect it to fail
    connect_with_invalid_active_session(next_port(), endpoint_basic128rsa15_sign_encrypt(), client_invalid_user_token());
}

#[test]
#[ignore]
fn connect_basic128rsa15_with_x509_token() {
    // Connect a session using an X509 key and certificate
    connect_with(next_port(), endpoint_basic128rsa15_sign_encrypt(), client_x509_token());
}
