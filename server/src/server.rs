use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use opcua_core;
use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use address_space::*;

use comms::tcp_transport::*;

use config::{ServerConfig};

#[derive(Clone)]
pub struct Endpoint {
    pub endpoint_url: String,
    pub security_policy_uri: UAString,
    pub security_mode: MessageSecurityMode,
    pub anonymous: bool,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// Server state is any state associated with the server as a whole that individual sessions might
/// be interested in. That includes configuration info, address space etc.
#[derive(Clone)]
pub struct ServerState {
    /// The application URI
    pub application_uri: UAString,
    /// The product URI
    pub product_uri: UAString,
    /// The application name
    pub application_name: LocalizedText,
    /// The protocol, hostname and port formatted as a url, but less the path
    pub base_endpoint: String,
    /// The time the server started
    pub start_time: DateTime,
    /// The list of namespaces
    pub namespaces: Vec<String>,
    /// The list of servers (by urn)
    pub servers: Vec<String>,
    // A list of endpoints
    pub endpoints: Vec<Endpoint>,
    /// Server configuration
    pub config: Arc<Mutex<ServerConfig>>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: ByteString,
    /// The address space
    pub address_space: Arc<Mutex<AddressSpace>>,
}

impl ServerState {
    pub fn endpoints(&self) -> Vec<EndpointDescription> {
        let mut endpoints: Vec<EndpointDescription> = Vec::with_capacity(self.endpoints.len());
        for e in &self.endpoints {
            let mut user_identity_tokens = Vec::new();
            if e.anonymous {
                user_identity_tokens.push(UserTokenPolicy::new_anonymous());
            }

            // TODO username / pass
            // user_identity_tokens.push(UserTokenPolicy::new_user_pass());
            endpoints.push(EndpointDescription {
                endpoint_url: UAString::from_str(&e.endpoint_url),
                server: ApplicationDescription {
                    application_uri: self.application_uri.clone(),
                    product_uri: self.product_uri.clone(),
                    application_name: self.application_name.clone(),
                    application_type: ApplicationType::Server,
                    gateway_server_uri: UAString::null(),
                    discovery_profile_uri: UAString::null(),
                    discovery_urls: None,
                },
                server_certificate: self.server_certificate.clone(),
                security_mode: e.security_mode,
                security_policy_uri: e.security_policy_uri.clone(),
                user_identity_tokens: Some(user_identity_tokens),
                transport_profile_uri: UAString::from_str(opcua_core::profiles::TRANSPORT_BINARY),
                security_level: 1,
            });
        }
        endpoints
    }
}

/// The Server represents a running instance of OPC UA. There can be more than one server running
/// at a time providing they do not share the same thread or listen on the same ports.
pub struct Server {
    /// The server state is everything that sessions share - address space, configuration etc.
    pub server_state: Arc<Mutex<ServerState>>,
    /// List of open sessions
    pub sessions: Vec<Arc<Mutex<TcpTransport>>>,
    /// Flag set to cause server to abort
    abort: bool,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: &ServerConfig) -> Server {
        // Set from config
        let application_name = config.application_name.clone();
        let application_uri = UAString::from_str(&config.application_uri);
        let product_uri = UAString::from_str(&config.product_uri);
        let namespaces = vec!["http://opcfoundation.org/UA/".to_string(), config.application_uri.clone()];
        let start_time = DateTime::now();
        let servers = vec![config.application_uri.clone()];
        let base_endpoint = format!("opc.tcp://{}:{}", config.tcp_config.host, config.tcp_config.port);

        let mut endpoints = Vec::new();
        for e in &config.endpoints {
            let endpoint_url = format!("{}{}", base_endpoint, e.path);
            let security_mode = MessageSecurityMode::from_str(&e.security_mode);
            let security_policy_uri = SecurityPolicy::from_str(&e.security_policy).to_uri().to_string();
            let anonymous = if let Some(anonymous) = e.anonymous.as_ref() {
                *anonymous
            } else {
                false
            };
            endpoints.push(Endpoint {
                endpoint_url: endpoint_url,
                security_policy_uri: UAString::from_str(&security_policy_uri),
                security_mode: security_mode,
                anonymous: anonymous,
                user: e.user.clone(),
                pass: e.pass.clone(),
            });
        }

        let server_certificate = ByteString::null();
        let address_space = AddressSpace::new();

        let server_state = ServerState {
            application_uri: application_uri,
            product_uri: product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from_str(&application_name),
            },
            namespaces: namespaces,
            servers: servers,
            base_endpoint: base_endpoint,
            start_time: start_time,
            endpoints: endpoints,
            config: Arc::new(Mutex::new(config.clone())),
            server_certificate: server_certificate,
            address_space: Arc::new(Mutex::new(address_space))
        };

        {
            let mut address_space = server_state.address_space.lock().unwrap();
            address_space.add_server_nodes(&server_state);
        }

        Server {
            server_state: Arc::new(Mutex::new(server_state)),
            abort: false,
            sessions: Vec::new()
        }
    }

    /// Create a new server instance using the server default configuration
    pub fn new_default() -> Server {
        Server::new(&ServerConfig::default_anonymous())
    }

    // Terminates the running server
    pub fn abort(&mut self) {
        self.abort = true;
    }

    /// Runs the server
    pub fn run(&mut self) {
        let (host, port, base_endpoint) = {
            let server_state = self.server_state.lock().unwrap();
            let config = server_state.config.lock().unwrap();
            (config.tcp_config.host.clone(), config.tcp_config.port, server_state.base_endpoint.clone())
        };
        let sock_addr = (host.as_str(), port);
        let listener = TcpListener::bind(&sock_addr).unwrap();
        loop {
            if self.abort {
                break;
            }
            info!("Waiting for Connection on {}", base_endpoint);
            for stream in listener.incoming() {
                info!("Handling new connection {:?}", stream);
                match stream {
                    Ok(stream) => {
                        self.handle_connection(stream);
                    }
                    Err(err) => {
                        warn!("Got an error on stream {:?}", err);
                    }
                }
            }
        }
    }

    /// Handles the incoming request
    fn handle_connection(&mut self, stream: TcpStream) {
        debug!("Connection thread spawning");
        // Spawn a thread for the connection
        let session = Arc::new(Mutex::new(TcpTransport::new(&self.server_state)));
        self.sessions.push(session.clone());
        thread::spawn(move || {
            session.lock().unwrap().run(stream);
            info!("Session thread is terminated");
        });
    }
}
