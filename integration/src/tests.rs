use chrono::{DateTime, Utc};
// Integration tests are asynchronous so futures will be used
use opcua_client::prelude::*;
use opcua_core;
use opcua_server;
use opcua_server::prelude::*;
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::mpsc::channel;
use std::thread;

fn new_client_server() -> (Client, Server) {
    opcua_core::init_logging();

    let endpoint_path = "/";

    // Both client server define this
    let anonymous_id = opcua_server::prelude::ANONYMOUS_USER_TOKEN_ID;

    // Create some endpoints
    let server = {
        let mut user_tokens = BTreeMap::new();
        let sample_user_id = "sample";
        user_tokens.insert(sample_user_id.to_string(), ServerUserToken::new_user_pass("sample", "sample1"));

        let user_token_ids = vec![anonymous_id.to_string(), sample_user_id.to_string()];

        let mut endpoints = BTreeMap::new();
        endpoints.insert("none".to_string(), ServerEndpoint::new_none(endpoint_path, &user_token_ids));
        endpoints.insert("basic128rsa15_sign".to_string(), ServerEndpoint::new_basic128rsa15_sign(endpoint_path, &user_token_ids));
        endpoints.insert("basic128rsa15_sign_encrypt".to_string(), ServerEndpoint::new_basic128rsa15_sign_encrypt(endpoint_path, &user_token_ids));
        endpoints.insert("basic256_sign".to_string(), ServerEndpoint::new_basic256_sign(endpoint_path, &user_token_ids));
        endpoints.insert("basic256_sign_encrypt".to_string(), ServerEndpoint::new_basic256_sign_encrypt(endpoint_path, &user_token_ids));
        endpoints.insert("basic256sha256_sign".to_string(), ServerEndpoint::new_basic256sha256_sign(endpoint_path, &user_token_ids));
        endpoints.insert("basic256sha256_sign_encrypt".to_string(), ServerEndpoint::new_basic256sha256_sign_encrypt(endpoint_path, &user_token_ids));
        let mut config = ServerConfig::new("x", user_tokens, endpoints);
        config.create_sample_keypair = true;

        // Create an OPC UA server with sample configuration and default node set
        Server::new(config)
    };

    let client = {
        let mut config = ClientConfig::new("x", "x");

        let mut endpoints = BTreeMap::new();
        endpoints.insert(String::from("sample_none"), ClientEndpoint {
            url: String::from("opc.tcp://127.0.0.1:4855/"),
            security_policy: String::from(SecurityPolicy::None.to_str()),
            security_mode: String::from(MessageSecurityMode::None),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from("sample_basic128rsa15"), ClientEndpoint {
            url: String::from("opc.tcp://127.0.0.1:4855/"),
            security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_str()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from("sample_basic256"), ClientEndpoint {
            url: String::from("opc.tcp://127.0.0.1:4855/"),
            security_policy: String::from(SecurityPolicy::Basic256.to_str()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: anonymous_id.to_string(),
        });
        endpoints.insert(String::from("sample_basic256sha256"), ClientEndpoint {
            url: String::from("opc.tcp://127.0.0.1:4855/"),
            security_policy: String::from(SecurityPolicy::Basic256Sha256.to_str()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: anonymous_id.to_string(),
        });
        let mut user_tokens = BTreeMap::new();
        user_tokens.insert(
            String::from("sample_user"),
            ClientUserToken {
                user: String::from("sample"),
                password: String::from("sample1"),
            });


        config.create_sample_keypair = true;
        config.trust_server_certs = true;
        config.endpoints = endpoints;
        config.user_tokens = user_tokens;
        Client::new(config)
    };

    (client, server)
}

enum ClientCommand {
    Quit
}

enum ClientResponse {
    Starting,
    Finished,
}

enum ServerCommand {
    Quit
}

enum ServerResponse {
    Starting,
    Finished,
}

fn perform_test<CT, ST>(client_test: Option<CT>, server_test: ST)
    where CT: FnOnce(&mpsc::Sender<ClientResponse>, &mpsc::Receiver<ClientCommand>, &Client) + Send + 'static,
          ST: FnOnce(&mpsc::Sender<ServerResponse>, &mpsc::Receiver<ServerCommand>, &Server) + Send + 'static {
    let (client, server) = new_client_server();

    // Spawn the CLIENT thread
    let (tx_client, rx_main_client) = {
        let (tx_client, rx_client) = channel();
        let (tx_main, rx_main_client) = channel();

        thread::spawn(move || {
            if let Some(client_test) = client_test {
                // Client thread
                trace!("Running client test");
                client_test(&tx_main, &rx_client, &client);
            } else {
                trace!("No client test");
            }
            let _ = tx_main.send(ClientResponse::Finished);
        });
        (tx_client, rx_main_client)
    };

    // Spawn the SERVER thread
    let (tx_server, rx_main_server) = {
        let (tx_server, rx_server) = channel();
        let (tx_main, rx_main_server) = channel();

        thread::spawn(move || {
            // Server thread
            trace!("Running server test");
            server_test(&tx_main, &rx_server, &server);
            let _ = tx_main.send(ServerResponse::Finished);
        });
        (tx_server, rx_main_server)
    };


    let start_time = Utc::now();

    // Loop until either the client or the server has quit
    let mut client_has_finished = false;
    let mut server_has_finished = false;
    let mut test_timeout = false;

    while !client_has_finished || !server_has_finished {

        // Timeout test
        if !test_timeout {
            let now = Utc::now();
            let elapsed = now.signed_duration_since(start_time.clone());
            if elapsed.num_milliseconds() > 30000 {
                let _ = tx_client.send(ClientCommand::Quit);
                let _ = tx_server.send(ServerCommand::Quit);
                test_timeout = true;
                panic!("Test timed out after {} ms", elapsed.num_milliseconds());
            }
        }

        if let Ok(response) = rx_main_client.try_recv() {
            match response {
                ClientResponse::Starting => {
                    trace!("Client test is starting");
                }
                ClientResponse::Finished => {
                    trace!("Client test finished");
                    client_has_finished = true;
                }
            }
        }
        if let Ok(response) = rx_main_server.try_recv() {
            match response {
                ServerResponse::Starting => {
                    trace!("Client test is starting");
                }
                ServerResponse::Finished => {
                    trace!("Server test finished");
                    server_has_finished = true;
                }
            }
        }
    }

    // TODO process the result
    trace!("test complete")
}


#[test]
fn connect() {
    let client_test = |tx_client: &mpsc::Sender<ClientResponse>, rx_client: &mpsc::Receiver<ClientCommand>, client: &Client| {
        trace!("Hello from client");
        let _ = tx_client.send(ClientResponse::Starting);
    };

    let server_test = |tx_server: &mpsc::Sender<ServerResponse>, rx_server: &mpsc::Receiver<ServerCommand>, server: &Server| {
        trace!("Hello from server");
        let _ = tx_server.send(ServerResponse::Starting);
        // Server runs on its own thread
        thread::spawn(|| {
            // Client thread
            //server.run();
        });
    };

    perform_test(Some(client_test), server_test);
}

#[test]
fn hello_timeout() {
    // For this test we want to set the hello timeout to a low value for the sake of speed.
}

#[test]
fn get_endpoints() {
    // Connect to server and get a list of endpoints
}

#[test]
fn connect_none_anonymous() {
    // Connect a session using None security policy and anonymous token.
}

#[test]
fn connect_none_username_password() {
    // Connect a session using None security policy and username/password token
}
