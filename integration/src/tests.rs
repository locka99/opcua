use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::sync::mpsc;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;
use std::time;

use chrono::Utc;

// Integration tests are asynchronous so futures will be used
use opcua_core;
use opcua_server;
use opcua_server::prelude::*;
use opcua_client::prelude::*;

const ENDPOINT_ID_NONE: &'static str = "sample_none";
const ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT: &'static str = "sample_basic128rsa15_signencrypt";
const ENDPOINT_ID_BASIC128RSA15_SIGN: &'static str = "sample_basic128rsa15_sign";
const ENDPOINT_ID_BASIC256_SIGN_ENCRYPT: &'static str = "sample_basic256_signencrypt";
const ENDPOINT_ID_BASIC256_SIGN: &'static str = "sample_basic256_sign";
const ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT: &'static str = "sample_basic256sha256_signencrypt";
const ENDPOINT_ID_BASIC256SHA256_SIGN: &'static str = "sample_basic256sha256_sign";


fn hostname() -> String {
    // To avoid certificate trouble, use the computer's own name for tne endpoint
    let mut names = opcua_core::crypto::X509Data::computer_hostnames();
    if names.is_empty() { "localhost".to_string() } else { names.remove(0) }
}

fn endpoint_url() -> String {
    // To avoid certificate trouble, use the computer's own name for tne endpoint
    format!("opc.tcp://{}:4855", hostname())
}

fn new_client_server() -> (Client, Server) {
    let endpoint_path = "/";

    // Both client server define this
    let anonymous_id = opcua_server::prelude::ANONYMOUS_USER_TOKEN_ID;

    // Create some endpoints
    let server = {
        let mut user_tokens = BTreeMap::new();
        let sample_user_id = "sample";
        user_tokens.insert(sample_user_id.to_string(), ServerUserToken::new_user_pass("sample", "sample1"));

        let user_token_ids = vec![anonymous_id.to_string(), sample_user_id.to_string()];

        // Create endpoints in every configuration
        let mut endpoints = BTreeMap::new();
        endpoints.insert("none".to_string(), ServerEndpoint::new_none(endpoint_path, &user_token_ids));
        endpoints.insert("basic128rsa15_sign".to_string(), ServerEndpoint::new_basic128rsa15_sign(endpoint_path, &user_token_ids));
        endpoints.insert("basic128rsa15_sign_encrypt".to_string(), ServerEndpoint::new_basic128rsa15_sign_encrypt(endpoint_path, &user_token_ids));
        endpoints.insert("basic256_sign".to_string(), ServerEndpoint::new_basic256_sign(endpoint_path, &user_token_ids));
        endpoints.insert("basic256_sign_encrypt".to_string(), ServerEndpoint::new_basic256_sign_encrypt(endpoint_path, &user_token_ids));
        endpoints.insert("basic256sha256_sign".to_string(), ServerEndpoint::new_basic256sha256_sign(endpoint_path, &user_token_ids));
        endpoints.insert("basic256sha256_sign_encrypt".to_string(), ServerEndpoint::new_basic256sha256_sign_encrypt(endpoint_path, &user_token_ids));

        let mut config = ServerConfig::new("integration_server", user_tokens, endpoints);
        config.discovery_url = endpoint_url();
        config.create_sample_keypair = true;
        config.pki_dir = PathBuf::from("./pki-server");
        config.discovery_server_url = None;
        config.tcp_config.host = hostname();

        // Create an OPC UA server with sample configuration and default node set
        let server = Server::new(config);

        // Allow untrusted access to the server
        {
            let mut certificate_store = server.certificate_store.write().unwrap();
            certificate_store.trust_unknown_certs = true;
        }

        server
    };

    let client = {
        let mut config = ClientConfig::new("integration_client", "x");

        let mut endpoints = BTreeMap::new();
        endpoints.insert(String::from(ENDPOINT_ID_NONE), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::None.to_str()),
            security_mode: String::from(MessageSecurityMode::None),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from(ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_str()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from(ENDPOINT_ID_BASIC128RSA15_SIGN), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_str()),
            security_mode: String::from(MessageSecurityMode::Sign),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from(ENDPOINT_ID_BASIC256_SIGN_ENCRYPT), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::Basic256.to_str()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from(ENDPOINT_ID_BASIC256_SIGN), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::Basic256.to_str()),
            security_mode: String::from(MessageSecurityMode::Sign),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from(ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::Basic256Sha256.to_str()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from(ENDPOINT_ID_BASIC256SHA256_SIGN), ClientEndpoint {
            url: endpoint_url(),
            security_policy: String::from(SecurityPolicy::Basic256Sha256.to_str()),
            security_mode: String::from(MessageSecurityMode::Sign),
            user_token_id: anonymous_id.to_string(),
        });

        let mut user_tokens = BTreeMap::new();
        user_tokens.insert(
            String::from("sample_user"),
            ClientUserToken {
                user: String::from("sample"),
                password: String::from("sample1"),
            });
        config.pki_dir = PathBuf::from("./pki-client");
        config.create_sample_keypair = true;
        config.trust_server_certs = true;
        config.endpoints = endpoints;
        config.user_tokens = user_tokens;
        config.default_endpoint = ENDPOINT_ID_NONE.to_string();
        config.trust_server_certs = true;

        Client::new(config)
    };

    (client, server)
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
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerCommand {
    Quit
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerResponse {
    Starting,
    Ready,
    Finished,
}

fn perform_test<CT, ST>(client_test: Option<CT>, server_test: ST)
    where CT: FnOnce(&mpsc::Receiver<ClientCommand>, &mpsc::Sender<ClientResponse>, Client) + Send + 'static,
          ST: FnOnce(&mpsc::Receiver<ServerCommand>, &mpsc::Sender<ServerResponse>, Server) + Send + 'static {
    let (client, server) = new_client_server();

    // Spawn the CLIENT thread
    let (client_thread, tx_client_command, rx_client_response) = {
        // Create channels for client command and response
        let (tx_client_command, rx_client_command) = channel::<ClientCommand>();
        let (tx_client_response, rx_client_response) = channel::<ClientResponse>();
        let client_thread = thread::spawn(move || {
            info!("Client test thread is running");
            if let Some(client_test) = client_test {
                // Wait for start command so we know server is ready
                let msg = rx_client_command.recv().unwrap();
                assert_eq!(msg, ClientCommand::Start);

                // Client is ready
                tx_client_response.send(ClientResponse::Ready);

                // Client test will run
                trace!("Running client test");
                let _ = tx_client_response.send(ClientResponse::Starting);
                client_test(&rx_client_command, &tx_client_response, client);
            } else {
                trace!("No client test");
            }
            let _ = tx_client_response.send(ClientResponse::Finished);
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
            server_test(&rx_server_command, &tx_server_response, server);
            let _ = tx_server_response.send(ServerResponse::Finished);
        });
        (server_thread, tx_server_command, rx_server_response)
    };

    let start_time = Utc::now();

    let timeout = 30000;

    let mut client_has_finished = false;
    let mut server_has_finished = false;
    let mut test_timeout = false;

    // Loop until either the client or the server has quit, or the timeout limit is reached
    while !client_has_finished || !server_has_finished {
        // Timeout test
        if !test_timeout {
            let now = Utc::now();
            let elapsed = now.signed_duration_since(start_time.clone());
            if elapsed.num_milliseconds() > timeout {
                let _ = tx_client_command.send(ClientCommand::Quit);
                let _ = tx_server_command.send(ServerCommand::Quit);
                test_timeout = true;
                panic!("Test timed out after {} ms", elapsed.num_milliseconds());
            }
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
                ClientResponse::Finished => {
                    info!("Client test finished");
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
                ServerResponse::Finished => {
                    info!("Server test finished");
                    server_has_finished = true;
                }
            }
        }

        thread::sleep(time::Duration::from_millis(1000));
    }

    // Threads should exit by now
    let _ = client_thread.join();
    let _ = server_thread.join();

    // TODO process the result
    trace!("test complete")
}

#[test]
fn hello_timeout() {
    // For this test we want to set the hello timeout to a low value for the sake of speed.
}

#[test]
fn get_endpoints() {
    // Connect to server and get a list of endpoints
}

fn connect_with(endpoint_id: &str) {
    opcua_core::init_logging();

    let endpoint_id = endpoint_id.to_string();
    let client_test = move |rx_client_command: &mpsc::Receiver<ClientCommand>, tx_client_response: &mpsc::Sender<ClientResponse>, mut client: Client| {
        // Connect to the server
        info!("Client will try to connect to endpoint {}", endpoint_id);
        let session = client.connect_and_activate(Some(&endpoint_id));
        assert!(session.is_ok());
    };

    let server_test = |rx_server_command: &mpsc::Receiver<ServerCommand>, tx_server_response: &mpsc::Sender<ServerResponse>, server: Server| {
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

    perform_test(Some(client_test), server_test);
}

#[test]
fn connect_none() {
    // Connect a session using None security policy and anonymous token.
    connect_with(ENDPOINT_ID_NONE);
}

#[test]
fn connect_none_username_password() {
    // Connect a session using None security policy and username/password token
    // connect_with(ENDPOINT_ID_);
}

#[test]
fn connect_basic128rsa15_sign() {
    // Connect a session with Basic128Rsa and Sign
    connect_with(ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT);
}

#[test]
fn connect_basic128rsa15_sign_and_encrypt() {
    // Connect a session with Basic128Rsa and SignAndEncrypt
    // connect_with(IdentityToken::Anonymous, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt);
}

#[test]
fn connect_basic256_sign() {
    // Connect a session with Basic256 and Sign
    connect_with(ENDPOINT_ID_BASIC256_SIGN);
}

#[test]
fn connect_basic256_sign_and_encrypt() {
    // Connect a session with Basic256 and SignAndEncrypt
    connect_with(ENDPOINT_ID_BASIC256_SIGN_ENCRYPT);
//    connect_with(IdentityToken::Anonymous, SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt);
}

#[test]
fn connect_basic256sha256_sign() {
    // Connect a session with Basic256Sha256 and Sign
    connect_with(ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT);
//    connect_with(IdentityToken::Anonymous, SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign);
}

#[test]
fn connect_basic256sha256_sign_and_encrypt() {
    // Connect a session with Basic256Sha256 and SignAndEncrypt
//    connect_with(IdentityToken::Anonymous, SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt);
}