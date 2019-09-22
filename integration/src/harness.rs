use std::{
    sync::{
        Arc, atomic::{AtomicUsize, Ordering}, mpsc, mpsc::channel, Mutex,
        RwLock,
    },
    thread, time,
};

use chrono::Utc;
use log::*;

use opcua_client::prelude::*;
use opcua_console_logging;
use opcua_core::{self, runtime_components};
use opcua_server::{
    self,
    builder::ServerBuilder,
    config::ServerEndpoint,
    prelude::*,
};

use crate::*;

const TEST_TIMEOUT: i64 = 30000;

static NEXT_PORT_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub fn next_port_offset() -> u16 {
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

fn server_user_token() -> ServerUserToken {
    ServerUserToken::user_pass("sample", "sample1")
}

pub fn new_server(port_offset: u16) -> Server {
    let endpoint_path = "/";

    // Both client server define this
    let sample_user_id = "sample";

    // Create user tokens - anonymous and a sample user
    let user_token_ids = vec![opcua_server::prelude::ANONYMOUS_USER_TOKEN_ID, sample_user_id];

    // Create an OPC UA server with sample configuration and default node set
    let server = ServerBuilder::new()
        .application_name("integration_server")
        .application_uri("urn:integration_server")
        .discovery_urls(vec![endpoint_url(port_offset)])
        .create_sample_keypair(true)
        .pki_dir("./pki-server")
        .discovery_server_url(None)
        .host_and_port(hostname(), 4855 + port_offset)
        .user_token(sample_user_id, server_user_token())
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
        let certificate_store = server.certificate_store();
        let mut certificate_store = certificate_store.write().unwrap();
        certificate_store.trust_unknown_certs = true;
    }

    // Populate the address space with some variables
    let v1_node = v1_node_id();
    {
        let address_space = server.address_space();
        let mut address_space = address_space.write().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space
            .add_folder("Sample", "Sample", &NodeId::objects_folder_id())
            .unwrap();

        // Add variables
        let _ = address_space.add_variables(
            vec![Variable::new(&v1_node, "v1", "v1", 0 as i32)],
            &sample_folder_id);

        // Register a getter for the variable
        if let Some(ref mut v) = address_space.find_variable_mut(v1_node.clone()) {
            let getter = AttrFnGetter::new(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
                Ok(Some(DataValue::new(100)))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }
    }

    server
}

fn new_client(port_offset: u16) -> Client {
    let anonymous_id = opcua_server::prelude::ANONYMOUS_USER_TOKEN_ID;
    ClientBuilder::new()
        .application_name("integration_client")
        .application_uri("x")
        .pki_dir("./pki-client")
        .endpoints(
            [
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
            }).collect::<Vec<_>>())
        .default_endpoint(ENDPOINT_ID_NONE)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .user_token("sample_user", ClientUserToken::new("sample", "sample1"))
        .client().unwrap()
}

fn new_client_server(port_offset: u16) -> (Client, Server) {
    (new_client(port_offset), new_server(port_offset))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientCommand {
    Start,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientResponse {
    Starting,
    Ready,
    Finished(bool),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerCommand {
    Quit
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerResponse {
    Starting,
    Ready,
    Finished(bool),
}

pub fn perform_test<CT, ST>(port_offset: u16, client_test: Option<CT>, server_test: ST)
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
                //  a compiler error because the tx_ sits on the other side

                client_test(rx_client_command, client);
                true
            } else {
                trace!("No client test");
                true
            };
            info!("Client test has completed, sending ClientResponse::Finished({:?})", result);
            let _ = tx_client_response.send(ClientResponse::Finished(result));
            info!("Client thread has finished");
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
            info!("Server test thread is running");
            let _ = tx_server_response.send(ServerResponse::Starting);
            let _ = tx_server_response.send(ServerResponse::Ready);
            // TODO catch_unwind
            server_test(rx_server_command, server);

            let result = true;
            info!("Server test has completed, sending ServerResponse::Finished({:?})", result);
            let _ = tx_server_response.send(ServerResponse::Finished(result));
            info!("Server thread has finished");
        });
        (server_thread, tx_server_command, rx_server_response)
    };

    let start_time = Utc::now();

    let timeout = TEST_TIMEOUT;

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

            error!("Test timed out after {} ms", elapsed.num_milliseconds());
            error!("Running components:\n  {}", {
                let components = runtime_components!();
                components.iter().cloned().collect::<Vec<String>>().join("\n  ")
            });

            panic!();
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
                    info!("Client test finished, result = {:?}", success);
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
                    info!("Server test finished, result = {:?}", success);
                    server_success = success;
                    server_has_finished = true;
                }
            }
        }

        thread::sleep(time::Duration::from_millis(1000));
    }

    info!("Joining on threads....");

    // Threads should exit by now
    let _ = client_thread.join();
    let _ = server_thread.join();

    assert!(client_success);
    assert!(server_success);

    info!("test complete")
}

pub fn connect_with(port_offset: u16, endpoint_id: &str) {
    let endpoint_id = endpoint_id.to_string();
    let client_test = move |_rx_client_command: mpsc::Receiver<ClientCommand>, mut client: Client| {
        // Connect to the server
        info!("Client will try to connect to endpoint {}", endpoint_id);
        let session = client.connect_to_endpoint_id(Some(&endpoint_id)).unwrap();
        let mut session = session.write().unwrap();

        // Read the variable
        let mut values = {
            let read_nodes = vec![ReadValueId::from(v1_node_id())];
            session.read(&read_nodes).unwrap().unwrap()
        };
        assert_eq!(values.len(), 1);

        let value = values.remove(0).value;
        assert_eq!(value, Some(Variant::from(100)));

        session.disconnect();
    };

    let server_test = |rx_server_command: mpsc::Receiver<ServerCommand>, server: Server| {
        trace!("Hello from server");
        // Wrap the server - a little juggling is required to give one rc
        // to a thread while holding onto one.
        let server = Arc::new(RwLock::new(server));
        let server2 = server.clone();

        // Server runs on its own thread
        let t = thread::spawn(move || {
            Server::run_server(server);
            info!("Server thread has finished");
        });

        // Listen for quit command, if we get one then finish
        loop {
            if let Ok(command) = rx_server_command.recv() {
                match command {
                    ServerCommand::Quit => {
                        // Tell the server to quit
                        {
                            info!("1. ------------------------ Server test received quit");
                            let mut server = server2.write().unwrap();
                            server.abort();
                        }
                        // wait for server thread to quit
                        let _ = t.join();
                        info!("2. ------------------------ Server has now terminated after quit");
                        break;
                    }
                }
            } else {
                info!("Receiver broke so terminating server test loop");
                break;
            }
        }
    };

    perform_test(port_offset, Some(client_test), server_test);
}
