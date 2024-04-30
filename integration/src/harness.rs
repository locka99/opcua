use opcua::server::address_space::types::{
    MethodBuilder, ObjectBuilder, Variable, VariableBuilder,
};
use opcua::server::address_space::AttrFnGetter;
use std::future::Future;
use std::time::{Duration, Instant};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::mpsc::unbounded_channel;

use log::*;

use opcua::client::{Client, ClientBuilder, IdentityToken};
use opcua::{
    runtime_components,
    server::{
        builder::ServerBuilder, callbacks, config::ServerEndpoint, prelude::*,
        session::SessionManager,
    },
    sync::*,
};

use crate::*;

const TEST_TIMEOUT: u64 = 30000;

pub fn functions_object_id() -> NodeId {
    NodeId::new(2, "Functions")
}

pub fn hellox_method_id() -> NodeId {
    NodeId::new(2, "HelloX")
}

static NEXT_PORT_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub fn next_port() -> u16 {
    port_from_offset(next_port_offset())
}

fn next_port_offset() -> u16 {
    // hand out an incrementing port so tests can be run in parallel without interfering with each other
    NEXT_PORT_OFFSET.fetch_add(1, Ordering::SeqCst) as u16
}

pub fn hostname() -> String {
    // To avoid certificate trouble, use the computer's own name for the endpoint
    let mut names = opcua::crypto::X509Data::computer_hostnames();
    if names.is_empty() {
        "localhost".to_string()
    } else {
        names.remove(0)
    }
}

fn port_from_offset(port_offset: u16) -> u16 {
    4855u16 + port_offset
}

pub fn endpoint_url(port: u16, path: &str) -> UAString {
    // To avoid certificate trouble, use the computer's own name for tne endpoint
    format!("opc.tcp://{}:{}{}", hostname(), port, path).into()
}

fn v1_node_id() -> NodeId {
    NodeId::new(2, "v1")
}

pub fn stress_node_id(idx: usize) -> NodeId {
    NodeId::new(2, format!("v{:04}", idx))
}

const USER_X509_CERTIFICATE_PATH: &str = "./x509/user_cert.der";
const USER_X509_PRIVATE_KEY_PATH: &str = "./x509/user_private_key.pem";

pub fn server_user_token() -> ServerUserToken {
    ServerUserToken::user_pass("sample1", "sample1pwd")
}

pub fn server_x509_token() -> ServerUserToken {
    ServerUserToken::x509("x509", &PathBuf::from(USER_X509_CERTIFICATE_PATH))
}

pub fn client_x509_token() -> IdentityToken {
    IdentityToken::X509(
        PathBuf::from(USER_X509_CERTIFICATE_PATH),
        PathBuf::from(USER_X509_PRIVATE_KEY_PATH),
    )
}

pub fn client_user_token() -> IdentityToken {
    IdentityToken::UserName(CLIENT_USERPASS_ID.into(), "sample1pwd".into())
}

pub fn client_invalid_user_token() -> IdentityToken {
    IdentityToken::UserName(CLIENT_USERPASS_ID.into(), "xxxx".into())
}

pub fn new_server(port: u16) -> Server {
    let endpoint_path = "/";

    // Both client and server define this
    let sample_user_id = CLIENT_USERPASS_ID;
    let x509_user_id = CLIENT_X509_ID;

    // Create user tokens - anonymous and a sample user
    let user_token_ids = vec![
        opcua::server::prelude::ANONYMOUS_USER_TOKEN_ID,
        sample_user_id,
        x509_user_id,
    ];

    // Create an OPC UA server with sample configuration and default node set
    let server = ServerBuilder::new()
        .application_name("integration_server")
        .application_uri("urn:integration_server")
        .discovery_urls(vec![endpoint_url(port, endpoint_path).to_string()])
        .create_sample_keypair(true)
        .pki_dir(format!("./pki-server/{}", port))
        .discovery_server_url(None)
        .host_and_port(hostname(), port)
        .user_token(sample_user_id, server_user_token())
        .user_token(x509_user_id, server_x509_token())
        .endpoints(
            [
                (
                    "none",
                    endpoint_path,
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &user_token_ids,
                ),
                (
                    "basic128rsa15_sign",
                    endpoint_path,
                    SecurityPolicy::Basic128Rsa15,
                    MessageSecurityMode::Sign,
                    &user_token_ids,
                ),
                (
                    "basic128rsa15_sign_encrypt",
                    endpoint_path,
                    SecurityPolicy::Basic128Rsa15,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids,
                ),
                (
                    "basic256_sign",
                    endpoint_path,
                    SecurityPolicy::Basic256,
                    MessageSecurityMode::Sign,
                    &user_token_ids,
                ),
                (
                    "basic256_sign_encrypt",
                    endpoint_path,
                    SecurityPolicy::Basic256,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids,
                ),
                (
                    "basic256sha256_sign",
                    endpoint_path,
                    SecurityPolicy::Basic256Sha256,
                    MessageSecurityMode::Sign,
                    &user_token_ids,
                ),
                (
                    "basic256sha256_sign_encrypt",
                    endpoint_path,
                    SecurityPolicy::Basic256Sha256,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids,
                ),
                (
                    "endpoint_aes128sha256rsaoaep_sign",
                    endpoint_path,
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    MessageSecurityMode::Sign,
                    &user_token_ids,
                ),
                (
                    "endpoint_aes128sha256rsaoaep_sign_encrypt",
                    endpoint_path,
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids,
                ),
                (
                    "endpoint_aes256sha256rsapss_sign",
                    endpoint_path,
                    SecurityPolicy::Aes256Sha256RsaPss,
                    MessageSecurityMode::Sign,
                    &user_token_ids,
                ),
                (
                    "endpoint_aes256sha256rsapss_sign_encrypt",
                    endpoint_path,
                    SecurityPolicy::Aes256Sha256RsaPss,
                    MessageSecurityMode::SignAndEncrypt,
                    &user_token_ids,
                ),
            ]
            .iter()
            .map(|v| {
                (
                    v.0.to_string(),
                    ServerEndpoint::from((v.1, v.2, v.3, &v.4[..])),
                )
            })
            .collect(),
        )
        .server()
        .unwrap();

    // Allow untrusted access to the server
    {
        let certificate_store = server.certificate_store();
        let mut certificate_store = certificate_store.write();
        certificate_store.set_trust_unknown_certs(true);
    }

    {
        let address_space = server.address_space();
        let mut address_space = address_space.write();

        // Populate the address space with some variables
        let v1_node = v1_node_id();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space
            .add_folder("Sample", "Sample", &NodeId::objects_folder_id())
            .unwrap();

        // Add variables
        let _ = address_space.add_variables(
            vec![Variable::new(&v1_node, "v1", "v1", 0 as i32)],
            &sample_folder_id,
        );

        // Register a getter for the variable
        if let Some(ref mut v) = address_space.find_variable_mut(v1_node.clone()) {
            let getter = AttrFnGetter::new(
                move |_, _, _, _, _, _| -> Result<Option<DataValue>, StatusCode> {
                    Ok(Some(DataValue::new_now(100)))
                },
            );
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }

        // Add a bunch of sequential vars too, similar to demo-server
        let node_ids = (0..1000)
            .map(|i| stress_node_id(i))
            .collect::<Vec<NodeId>>();
        let folder_id = address_space
            .add_folder("Stress", "Stress", &NodeId::objects_folder_id())
            .unwrap();

        node_ids.iter().enumerate().for_each(|(i, node_id)| {
            let name = format!("stress node v{:04}", i);
            VariableBuilder::new(&node_id, &name, &name)
                .data_type(DataTypeId::Int32)
                .value(0i32)
                .writable()
                .organized_by(&folder_id)
                .insert(&mut address_space);
        });

        let functions_object_id = functions_object_id();
        ObjectBuilder::new(&functions_object_id, "Functions", "Functions")
            .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut address_space);

        MethodBuilder::new(&hellox_method_id(), "HelloX", "HelloX")
            .component_of(functions_object_id)
            .input_args(
                &mut address_space,
                &[("YourName", DataTypeId::String).into()],
            )
            .output_args(&mut address_space, &[("Result", DataTypeId::String).into()])
            .callback(Box::new(HelloX))
            .insert(&mut address_space);
    }

    server
}

struct HelloX;

impl callbacks::Method for HelloX {
    fn call(
        &mut self,
        _session_id: &NodeId,
        _session_map: Arc<RwLock<SessionManager>>,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        debug!("HelloX method called");
        // Validate input to be a string
        let mut out1 = Variant::Empty;
        let in1_status = if let Some(ref input_arguments) = request.input_arguments {
            if let Some(in1) = input_arguments.get(0) {
                if let Variant::String(in1) = in1 {
                    out1 = Variant::from(format!("Hello {}!", &in1));
                    StatusCode::Good
                } else {
                    StatusCode::BadTypeMismatch
                }
            } else if input_arguments.len() == 0 {
                return Err(StatusCode::BadArgumentsMissing);
            } else {
                // Shouldn't get here because there is 1 argument
                return Err(StatusCode::BadTooManyArguments);
            }
        } else {
            return Err(StatusCode::BadArgumentsMissing);
        };

        let status_code = if in1_status.is_good() {
            StatusCode::Good
        } else {
            StatusCode::BadInvalidArgument
        };

        Ok(CallMethodResult {
            status_code,
            input_argument_results: Some(vec![in1_status]),
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![out1]),
        })
    }
}

fn new_client(port: u16, quick_timeout: bool) -> Client {
    let builder = ClientBuilder::new()
        .application_name("integration_client")
        .application_uri("x")
        .pki_dir(format!("./pki-client/{port}"))
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_initial(Duration::from_millis(200));

    let builder = if quick_timeout {
        builder.session_retry_limit(1)
    } else {
        builder
    };
    builder.client().unwrap()
}

pub fn new_client_server(port: u16, quick_timeout: bool) -> (Client, Server) {
    (new_client(port, quick_timeout), new_server(port))
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
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerResponse {
    Starting,
    Ready,
    Finished(bool),
}

pub async fn perform_test<CT, ST, CFut, SFut>(
    client: Client,
    server: Server,
    client_test: Option<CT>,
    server_test: ST,
) where
    CT: FnOnce(mpsc::UnboundedReceiver<ClientCommand>, Client) -> CFut + Send + 'static,
    ST: FnOnce(mpsc::UnboundedReceiver<ServerCommand>, Server) -> SFut + Send + 'static,
    CFut: Future<Output = ()> + Send + 'static,
    SFut: Future<Output = ()> + Send + 'static,
{
    opcua::console_logging::init();

    // Spawn the CLIENT future
    let (client_fut, tx_client_command, mut rx_client_response) = {
        println!("Begin test");
        // Create channels for client command and response
        let (tx_client_command, mut rx_client_command) = unbounded_channel::<ClientCommand>();
        let (tx_client_response, rx_client_response) = unbounded_channel::<ClientResponse>();

        let client_fut = tokio::task::spawn(async move {
            println!("Enter client fut");
            let result = if let Some(client_test) = client_test {
                // Wait for start command so we know server is ready
                println!("Begin wait for client RX");
                let msg = rx_client_command.recv().await.unwrap();

                assert_eq!(msg, ClientCommand::Start);
                // Client is ready
                let _ = tx_client_response.send(ClientResponse::Ready);

                // Client test will run
                trace!("Running client test");

                let _ = tx_client_response.send(ClientResponse::Starting);

                println!("Begin client test");
                client_test(rx_client_command, client).await;
                true
            } else {
                trace!("No client test");
                true
            };
            let _ = tx_client_response.send(ClientResponse::Finished(result));
        });
        (client_fut, tx_client_command, rx_client_response)
    };

    // Spawn the SERVER future
    let (server_fut, tx_server_command, mut rx_server_response) = {
        // Create channels for server command and response
        let (tx_server_command, rx_server_command) = unbounded_channel();
        let (tx_server_response, rx_server_response) = unbounded_channel();
        println!("Make server fut");
        let server_fut = tokio::task::spawn(async move {
            println!("Begin server");
            // Server future
            info!("Server test thread is running");
            let _ = tx_server_response.send(ServerResponse::Starting);
            let _ = tx_server_response.send(ServerResponse::Ready);

            println!("Begin server test");
            server_test(rx_server_command, server).await;

            let result = true;
            info!(
                "Server test has completed, sending ServerResponse::Finished({:?})",
                result
            );
            let _ = tx_server_response.send(ServerResponse::Finished(result));
            info!("Server thread has finished");
        });
        (server_fut, tx_server_command, rx_server_response)
    };

    let start_time = Instant::now();

    let timeout = TEST_TIMEOUT;

    let mut client_has_finished = false;
    let mut client_success = false;
    let mut server_has_finished = false;
    let mut server_success = false;

    let end_time = start_time + std::time::Duration::from_millis(timeout);

    // Loop until either the client or the server has quit, or the timeout limit is reached
    while !client_has_finished || !server_has_finished {
        select! {
            _ = tokio::time::sleep_until(end_time.into()) => {
                let _ = tx_client_command.send(ClientCommand::Quit);
                let _ = tx_server_command.send(ServerCommand::Quit);

                error!("Test timed out after {} ms", timeout);
                error!("Running components:\n  {}", {
                    let components = runtime_components!();
                    components
                        .iter()
                        .cloned()
                        .collect::<Vec<String>>()
                        .join("\n  ")
                });

                server_success = false;
                client_success = false;

                break;
            }
            response = rx_client_response.recv() => {
                match response {
                    Some(ClientResponse::Starting) => {
                        info!("Client test is starting");
                    }
                    Some(ClientResponse::Ready) => {
                        info!("Client is ready");
                    }
                    Some(ClientResponse::Finished(success)) => {
                        info!("Client test finished, result = {:?}", success);
                        client_success = success;
                        client_has_finished = true;
                        if !server_has_finished {
                            info!("Telling the server to quit");
                            let _ = tx_server_command.send(ServerCommand::Quit);
                        }
                    }
                    None => {
                    }
                }
            }
            response = rx_server_response.recv() => {
                match response {
                    Some(ServerResponse::Starting) => {
                        info!("Server test is starting");
                    }
                    Some(ServerResponse::Ready) => {
                        info!("Server test is ready");
                        // Tell the client to start
                        let _ = tx_client_command.send(ClientCommand::Start);
                    }
                    Some(ServerResponse::Finished(success)) => {
                        info!("Server test finished, result = {:?}", success);
                        server_success = success;
                        server_has_finished = true;
                    }
                    None => {
                    }
                }
            }
        }
    }

    info!("Joining on threads....");

    // Threads should exit by now
    let _ = client_fut.await.unwrap();
    let _ = server_fut.await.unwrap();

    assert!(client_success);
    assert!(server_success);

    info!("test complete")
}

pub async fn get_endpoints_client_test(
    server_url: &str,
    _identity_token: IdentityToken,
    _rx_client_command: mpsc::UnboundedReceiver<ClientCommand>,
    client: Client,
) {
    let endpoints = client
        .get_server_endpoints_from_url(server_url)
        .await
        .unwrap();
    // Value should match number of expected endpoints
    assert_eq!(endpoints.len(), 11);
}

pub async fn regular_client_test(
    client_endpoint: impl Into<EndpointDescription>,
    identity_token: IdentityToken,
    _rx_client_command: mpsc::UnboundedReceiver<ClientCommand>,
    mut client: Client,
) {
    // Connect to the server
    let client_endpoint = client_endpoint.into();
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

    // Read the variable
    let mut values = {
        let read_nodes = vec![ReadValueId::from(v1_node_id())];
        session
            .read(&read_nodes, TimestampsToReturn::Both, 1.0)
            .await
            .unwrap()
    };
    assert_eq!(values.len(), 1);

    let value = values.remove(0).value;
    assert_eq!(value, Some(Variant::from(100)));

    session.disconnect().await.unwrap();
    handle.await.unwrap();
}

pub async fn invalid_token_test(
    client_endpoint: impl Into<EndpointDescription>,
    identity_token: IdentityToken,
    _rx_client_command: mpsc::UnboundedReceiver<ClientCommand>,
    mut client: Client,
) {
    // Connect to the server
    let client_endpoint = client_endpoint.into();
    info!(
        "Client will try to connect to endpoint {:?}",
        client_endpoint
    );
    let (_, event_loop) = client
        .new_session_from_endpoint(client_endpoint, identity_token)
        .await
        .unwrap();
    let res = event_loop.spawn().await.unwrap();
    assert_eq!(res, StatusCode::BadUserAccessDenied);
}

pub async fn regular_server_test(
    mut rx_server_command: mpsc::UnboundedReceiver<ServerCommand>,
    server: Server,
) {
    trace!("Hello from server");
    // Wrap the server - a little juggling is required to give one rc
    // to a thread while holding onto one.
    let server = Arc::new(RwLock::new(server));
    let server2 = server.clone();

    // Server runs on its own thread
    let t = tokio::task::spawn_blocking(move || {
        Server::run_server(server);
        info!("Server thread has finished");
    });

    // Listen for quit command, if we get one then finish
    loop {
        if let Some(command) = rx_server_command.recv().await {
            match command {
                ServerCommand::Quit => {
                    // Tell the server to quit
                    {
                        info!("1. ------------------------ Server test received quit");
                        let mut server = server2.write();
                        server.abort();
                    }
                    // wait for server thread to quit
                    let _ = t.await.unwrap();
                    info!("2. ------------------------ Server has now terminated after quit");
                    break;
                }
            }
        } else {
            info!("Receiver broke so terminating server test loop");
            break;
        }
    }
}

pub async fn connect_with_client_test<CT, Fut>(port: u16, client_test: CT, quick_timeout: bool)
where
    CT: FnOnce(mpsc::UnboundedReceiver<ClientCommand>, Client) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (client, server) = new_client_server(port, quick_timeout);
    perform_test(client, server, Some(client_test), regular_server_test).await;
}

pub async fn connect_with_get_endpoints(port: u16) {
    connect_with_client_test(
        port,
        move |rx_client_command: mpsc::UnboundedReceiver<ClientCommand>, client: Client| async move {
            get_endpoints_client_test(
                &endpoint_url(port, "/").as_ref(),
                IdentityToken::Anonymous,
                rx_client_command,
                client,
            )
            .await;
        },
        false
    ).await;
}

pub async fn connect_with_invalid_token(
    port: u16,
    client_endpoint: EndpointDescription,
    identity_token: IdentityToken,
) {
    connect_with_client_test(
        port,
        move |rx_client_command: mpsc::UnboundedReceiver<ClientCommand>, client: Client| async move {
            invalid_token_test(client_endpoint, identity_token, rx_client_command, client).await;
        },
        true
    )
    .await;
}

pub async fn connect_with(
    port: u16,
    client_endpoint: EndpointDescription,
    identity_token: IdentityToken,
) {
    connect_with_client_test(
        port,
        move |rx_client_command: mpsc::UnboundedReceiver<ClientCommand>, client: Client| async move {
            regular_client_test(client_endpoint, identity_token, rx_client_command, client).await;
        },
        false
    ).await;
}
