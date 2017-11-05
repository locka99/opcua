use std::collections::BTreeMap;
use std::thread;
use std::sync::mpsc::channel;

// Integration tests are asynchronous so futures will be used
use futures;


use opcua_core;
use opcua_client::prelude::*;
use opcua_server::prelude::*;
use opcua_server;

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
                password: String::from("sample1")
            });


        config.create_sample_keypair = true;
        config.trust_server_certs = true;
        config.endpoints = endpoints;
        config.user_tokens = user_tokens;
        Client::new(config)
    };

    (client, server)
}

enum ClientCommand {}

enum ClientResponse {
    Quit
}

enum ServerCommand {}

enum ServerResponse {
    Quit
}

fn perform_test() {
    let (client, server) = new_client_server();

    // Now spawn a couple of threads to house the client and server.
    let (tx_client, rx_client) = channel();
    thread::spawn(move || {
        // Client thread
        let _ = tx_client.send(ClientResponse::Quit);
    });

    let (tx_server, rx_server) = channel();
    thread::spawn(move || {
        // Server thread
        let _ = tx_server.send(ServerResponse::Quit);
    });

    // Loop until either the client or the server has quit
    loop {
        if let Ok(response) = rx_client.try_recv() {
            match response {
                ClientResponse::Quit => {
                    trace!("Client quit");
                    break;
                }
            }
        }
        if let Ok(response) = rx_server.try_recv() {
            match response {
                ServerResponse::Quit => {
                    trace!("Server quit");
                    break;
                }
            }
        }
    }

    // TODO process the result

    trace!("test complete")
}


#[test]
fn connect() {}

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
