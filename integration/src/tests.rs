use chrono::Utc;
// Integration tests are asynchronous so futures will be used
use opcua_client::prelude::*;
use opcua_core;
use opcua_server;
use opcua_server::prelude::*;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::sync::mpsc;
use std::sync::mpsc::channel;
use std::thread;
use std::time;

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
    // Ready,
    Finished,
}

enum ServerCommand {
    Quit
}

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
            if let Some(client_test) = client_test {
                // Client thread
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
                    trace!("Client test is starting");
                }
                ClientResponse::Ready => {
                    trace!("Client is ready");
                }
                ClientResponse::Finished => {
                    trace!("Client test finished");
                    client_has_finished = true;

                    if !server_has_finished {
                        trace!("Telling the server to quit");
                        let _ = tx_server_command.send(ServerCommand::Quit);
                    }
                }
            }
        }

        // Check for a server response
        if let Ok(response) = rx_server_response.try_recv() {
            match response {
                ServerResponse::Starting => {
                    trace!("Server test is starting");
                }
                ServerResponse::Ready => {
                    trace!("Server test is ready");
                }
                ServerResponse::Finished => {
                    trace!("Server test finished");
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
fn connect() {
    let client_test = |rx_client_command: &mpsc::Receiver<ClientCommand>, tx_client_response: &mpsc::Sender<ClientResponse>, _client: Client| {
        trace!("Hello from client");
    };

    let server_test = |rx_server_command: &mpsc::Receiver<ServerCommand>, tx_server_response: &mpsc::Sender<ServerResponse>, server: Server| {
        trace!("Hello from server");
        // Wrap the server - a little juggling is required to give one rc
        // to a thread while holding onto one.
        let server = Arc::new(RwLock::new(server));
        let server2 = server.clone();

        // Server runs on its own thread
        let t = thread::spawn(move || {
            // Client thread
            // Server::run(server);
        });

        // Listen for quit command, if we get one then finish
        loop {
            if let Ok(command) = rx_server_command.recv() {
                match command {
                    ServerCommand::Quit => {
                        // Tell the server to quit
                        {
                            trace!("Server test received quit");
                            let mut server = server2.write().unwrap();
                            server.abort();
                        }
                        // wait for server thread to quit
                        let _ = t.join();
                        break;
                    }
                }
            }
        }
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
