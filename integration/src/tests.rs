use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;
use std::time;

use chrono::Utc;

// Integration tests are asynchronous so futures will be used
use opcua_core;
use opcua_server;
use opcua_types::*;
use opcua_server::config::{ServerEndpoint, ServerConfig};
use opcua_server::builder::ServerBuilder;
use opcua_server::prelude::*;
use opcua_client::prelude::*;
use opcua_client::config::{ClientConfig, ClientUserToken};
use opcua_console_logging;

const ENDPOINT_ID_NONE: &str = "sample_none";
const ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT: &str = "sample_basic128rsa15_signencrypt";
const ENDPOINT_ID_BASIC128RSA15_SIGN: &str = "sample_basic128rsa15_sign";
const ENDPOINT_ID_BASIC256_SIGN_ENCRYPT: &str = "sample_basic256_signencrypt";
const ENDPOINT_ID_BASIC256_SIGN: &str = "sample_basic256_sign";
const ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT: &str = "sample_basic256sha256_signencrypt";
const ENDPOINT_ID_BASIC256SHA256_SIGN: &str = "sample_basic256sha256_sign";

#[test]
fn hello_timeout() {
    // For this test we want to set the hello timeout to a low value for the sake of speed.
}

#[test]
fn get_endpoints() {
    // Connect to server and get a list of endpoints
}

#[test]
fn connect_none() {
    // Connect a session using None security policy and anonymous token.
    connect_with(next_port_offset(), ENDPOINT_ID_NONE);
}

#[test]
fn connect_none_username_password() {
    // Connect a session using None security policy and username/password token
    // connect_with(ENDPOINT_ID_);
}

#[test]
fn connect_basic128rsa15_sign() {
    // Connect a session with Basic128Rsa and Sign
    connect_with(next_port_offset(), ENDPOINT_ID_BASIC128RSA15_SIGN);
}

#[test]
fn connect_basic128rsa15_sign_and_encrypt() {
    // Connect a session with Basic128Rsa and SignAndEncrypt
    connect_with(next_port_offset(), ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT);
}

#[test]
fn connect_basic256_sign() {
    // Connect a session with Basic256 and Sign
    connect_with(next_port_offset(), ENDPOINT_ID_BASIC256_SIGN);
}

#[test]
fn connect_basic256_sign_and_encrypt() {
    // Connect a session with Basic256 and SignAndEncrypt
    connect_with(next_port_offset(), ENDPOINT_ID_BASIC256_SIGN_ENCRYPT);
}

#[test]
fn connect_basic256sha256_sign() {
    // Connect a session with Basic256Sha256 and Sign
    connect_with(next_port_offset(), ENDPOINT_ID_BASIC256SHA256_SIGN);
}

#[test]
fn connect_basic256sha256_sign_and_encrypt() {
    // Connect a session with Basic256Sha256 and SignAndEncrypt
    connect_with(next_port_offset(), ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT);
}

static NEXT_PORT_OFFSET: AtomicUsize = ATOMIC_USIZE_INIT;

fn next_port_offset() -> u16 {
    // hand out an incrementing port so tests can be run in parallel without interfering with each other
    NEXT_PORT_OFFSET.fetch_add(1, Ordering::SeqCst) as u16
}

fn hostname() -> String {
    // To avoid certificate trouble, use the computer's own name for tne endpoint
    let mut names = opcua_core::crypto::X509Data::computer_hostnames();
    if names.is_empty() { "localhost".to_string() } else { names.remove(0) }
}

fn endpoint_url(port_offset: u16) -> String {
    // To avoid certificate trouble, use the computer's own name for tne endpoint
    format!("opc.tcp://{}:{}", hostname(), 4855u16 + port_offset)
}

fn v1_node_id() -> NodeId { NodeId::new(2, "v1") }

fn new_server(port_offset: u16) -> Server {
    let endpoint_path = "/";

    // Both client server define this
    let sample_user_id = "sample";

    // Create user tokens - anonymous and a sample user
    let user_token_ids = vec![opcua_server::prelude::ANONYMOUS_USER_TOKEN_ID, sample_user_id];

    // Create an OPC UA server with sample configuration and default node set
    let server = ServerBuilder::new()
        .application_name("integration_server")
        .discovery_url(endpoint_url(port_offset))
        .create_sample_keypair(true)
        .pki_dir("./pki-server")
        .discovery_server_url(None)
        .host_port(hostname(), 4855 + port_offset)
        .user_token(sample_user_id, ServerUserToken::new_user_pass("sample", "sample1"))
        .endpoints(
            [
                ("none", endpoint_path, SecurityPolicy::None, MessageSecurityMode::None, &user_token_ids),
                ("basic128rsa15_sign", endpoint_path, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::Sign, &user_token_ids),
                ("basic128rsa15_sign_encrypt", endpoint_path, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt, &user_token_ids),
                ("basic256_sign", endpoint_path, SecurityPolicy::Basic256, MessageSecurityMode::Sign, &user_token_ids),
                ("basic256_sign_encrypt", endpoint_path, SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt, &user_token_ids),
                ("basic256sha256_sign", endpoint_path, SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign, &user_token_ids),
                ("basic256sha256_sign_encrypt", endpoint_path, SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, &user_token_ids),
            ].iter().map(|v| {
                (v.0.to_string(), ServerEndpoint::from((v.1, v.2, v.3, &v.4[..])))
            }).collect())
        .server().unwrap();

    // Allow untrusted access to the server
    {
        let mut certificate_store = server.certificate_store.write().unwrap();
        certificate_store.trust_unknown_certs = true;
    }

    // Populate the address space with some variables
    let v1_node = v1_node_id();
    {
        let mut address_space = server.address_space.write().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space
            .add_folder("Sample", "Sample", &AddressSpace::objects_folder_id())
            .unwrap();

        // Add variables
        let _ = address_space.add_variables(
            vec![Variable::new(&v1_node, "v1", "v1", "v1 variable", 0 as Int32)],
            &sample_folder_id);

        // Register a getter for the variable
        if let Some(ref mut v) = address_space.find_variable_mut(v1_node.clone()) {
            let getter = AttrFnGetter::new(move |_, _| -> Result<Option<DataValue>, StatusCode> {
                Ok(Some(DataValue::new(100)))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }
    }

    server
}

fn new_client(port_offset: u16) -> Client {
    let mut config = ClientConfig::new("integration_client", "x");
    let anonymous_id = opcua_server::prelude::ANONYMOUS_USER_TOKEN_ID;

    // Make some endpoints
    let endpoints = [
        (ENDPOINT_ID_NONE, SecurityPolicy::None, MessageSecurityMode::None, anonymous_id),
        (ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt, anonymous_id),
        (ENDPOINT_ID_BASIC128RSA15_SIGN, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::Sign, anonymous_id),
        (ENDPOINT_ID_BASIC256_SIGN_ENCRYPT, SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt, anonymous_id),
        (ENDPOINT_ID_BASIC256_SIGN, SecurityPolicy::Basic256, MessageSecurityMode::Sign, anonymous_id),
        (ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT, SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, anonymous_id),
        (ENDPOINT_ID_BASIC256SHA256_SIGN, SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign, anonymous_id),
    ].iter().map(|v| {
        (v.0.to_string(), ClientEndpoint {
            url: endpoint_url(port_offset),
            security_policy: v.1.into(),
            security_mode: v.2.into(),
            user_token_id: v.3.to_string(),
        })
    }).collect::<BTreeMap<_, _>>();

    let user_tokens = vec![
        ("sample_user".to_string(), ClientUserToken::new("sample", "sample1")),
    ].into_iter().collect::<BTreeMap<_, _>>();

    config.pki_dir = PathBuf::from("./pki-client");
    config.create_sample_keypair = true;
    config.trust_server_certs = true;
    config.endpoints = endpoints;
    config.user_tokens = user_tokens;
    config.default_endpoint = ENDPOINT_ID_NONE.to_string();
    config.trust_server_certs = true;

    Client::new(config)
}

fn new_client_server(port_offset: u16) -> (Client, Server) {
    (new_client(port_offset), new_server(port_offset))
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientCommand {
    Start,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientResponse {
    Starting,
    Ready,
    Finished(bool),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerCommand {
    Quit
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerResponse {
    Starting,
    Ready,
    Finished(bool),
}

fn perform_test<CT, ST>(port_offset: u16, client_test: Option<CT>, server_test: ST)
    where CT: FnOnce(mpsc::Receiver<ClientCommand>, Client) + Send + 'static,
          ST: FnOnce(mpsc::Receiver<ServerCommand>, Server) + Send + 'static {
    opcua_console_logging::init();

    let (client, server) = new_client_server(port_offset);

    // Spawn the CLIENT thread
    let (client_thread, tx_client_command, rx_client_response) = {
        // Create channels for client command and response
        let (tx_client_command, rx_client_command) = channel::<ClientCommand>();
        let (tx_client_response, rx_client_response) = channel::<ClientResponse>();

        let client_thread = thread::spawn(move || {
            info!("Client test thread is running");
            let result = if let Some(client_test) = client_test {
                // Wait for start command so we know server is ready
                let msg = rx_client_command.recv().unwrap();
                assert_eq!(msg, ClientCommand::Start);

                // Client is ready
                let _ = tx_client_response.send(ClientResponse::Ready);

                // Client test will run
                trace!("Running client test");

                let _ = tx_client_response.send(ClientResponse::Starting);

                // TODO this should be inside a catch_unwind but putting the rx_ inside triggers
                // a compiler error because the tx_ sits on the other side

                client_test(rx_client_command, client);
                true
            } else {
                trace!("No client test");
                true
            };
            let _ = tx_client_response.send(ClientResponse::Finished(result));
        });
        (client_thread, tx_client_command, rx_client_response)
    };

    // Spawn the SERVER thread
    let (server_thread, tx_server_command, rx_server_response) = {
        // Create channels for server command and response
        let (tx_server_command, rx_server_command) = channel();
        let (tx_server_response, rx_server_response) = channel();
        let server_thread = thread::spawn(move || {
            // Server thread
            trace!("Running server test");
            let _ = tx_server_response.send(ServerResponse::Starting);
            let _ = tx_server_response.send(ServerResponse::Ready);
            // TODO catch_unwind
            server_test(rx_server_command, server);
            let _ = tx_server_response.send(ServerResponse::Finished(true));
        });
        (server_thread, tx_server_command, rx_server_response)
    };

    let start_time = Utc::now();

    let timeout = 30000;

    let mut client_has_finished = false;
    let mut client_success = false;
    let mut server_has_finished = false;
    let mut server_success = false;

    // Loop until either the client or the server has quit, or the timeout limit is reached
    while !client_has_finished || !server_has_finished {
        // Timeout test
        let now = Utc::now();
        let elapsed = now.signed_duration_since(start_time.clone());
        if elapsed.num_milliseconds() > timeout {
            let _ = tx_client_command.send(ClientCommand::Quit);
            let _ = tx_server_command.send(ServerCommand::Quit);
            panic!("Test timed out after {} ms", elapsed.num_milliseconds());
        }

        // Check for a client response
        if let Ok(response) = rx_client_response.try_recv() {
            match response {
                ClientResponse::Starting => {
                    info!("Client test is starting");
                }
                ClientResponse::Ready => {
                    info!("Client is ready");
                }
                ClientResponse::Finished(success) => {
                    info!("Client test finished");
                    client_success = success;
                    client_has_finished = true;
                    if !server_has_finished {
                        info!("Telling the server to quit");
                        let _ = tx_server_command.send(ServerCommand::Quit);
                    }
                }
            }
        }

        // Check for a server response
        if let Ok(response) = rx_server_response.try_recv() {
            match response {
                ServerResponse::Starting => {
                    info!("Server test is starting");
                }
                ServerResponse::Ready => {
                    info!("Server test is ready");
                    // Tell the client to start
                    let _ = tx_client_command.send(ClientCommand::Start);
                }
                ServerResponse::Finished(success) => {
                    info!("Server test finished");
                    server_success = success;
                    server_has_finished = true;
                }
            }
        }

        thread::sleep(time::Duration::from_millis(1000));
    }

    // Threads should exit by now
    let _ = client_thread.join();
    let _ = server_thread.join();

    assert!(client_success);
    assert!(server_success);

    trace!("test complete")
}

fn connect_with(port_offset: u16, endpoint_id: &str) {
    let endpoint_id = endpoint_id.to_string();
    let client_test = move |rx_client_command: mpsc::Receiver<ClientCommand>, mut client: Client| {
        // Connect to the server
        info!("Client will try to connect to endpoint {}", endpoint_id);
        let session = client.connect_and_activate(Some(&endpoint_id)).unwrap();

        // Read the variable
        let mut values = {
            let mut session = session.write().unwrap();
            let read_nodes = vec![ReadValueId::from(v1_node_id())];
            session.read_nodes(&read_nodes).unwrap().unwrap()
        };
        assert_eq!(values.len(), 1);

        let value = values.remove(0).value;
        assert_eq!(value, Some(Variant::from(100)));
    };

    let server_test = |rx_server_command: mpsc::Receiver<ServerCommand>, server: Server| {
        trace!("Hello from server");
        // Wrap the server - a little juggling is required to give one rc
        // to a thread while holding onto one.
        let server = Arc::new(RwLock::new(server));
        let server2 = server.clone();

        // Server runs on its own thread
        let t = thread::spawn(move || {
            Server::run(server);
        });

        // Listen for quit command, if we get one then finish
        loop {
            if let Ok(command) = rx_server_command.recv() {
                match command {
                    ServerCommand::Quit => {
                        // Tell the server to quit
                        {
                            info!("Server test received quit");
                            let mut server = server2.write().unwrap();
                            server.abort();
                        }
                        // wait for server thread to quit
                        let _ = t.join();
                        info!("Server has terminated quit");
                        break;
                    }
                }
            }
        }
    };

    perform_test(port_offset, Some(client_test), server_test);
}
