use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::address_space::*;

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
    pub application_uri: UAString,
    pub product_uri: UAString,
    pub application_name: LocalizedText,
    // The protocol, hostname and port formatted as a url, but less the path
    pub base_endpoint: String,
    // A list of endpoints
    pub endpoints: Vec<Endpoint>,
    /// Server configuration
    pub config: Arc<Mutex<ServerConfig>>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: ByteString,
    /// The address space
    pub address_space: Arc<Mutex<AddressSpace>>,
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

        let base_endpoint = format!("opc.tcp://{}:{}", config.tcp_config.host, config.tcp_config.port);

        let mut endpoints = Vec::new();
        for e in &config.endpoints {
            let endpoint_url = format!("{}{}", base_endpoint, e.path);
            let security_mode = MessageSecurityMode::from_str(&e.security_mode);
            let security_policy_uri = SecurityPolicy::from_str(&e.security_policy).to_uri().to_string();
            let anonymous = if let Some( anonymous) = e.anonymous.as_ref() {
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

        Server {
            server_state: Arc::new(Mutex::new(ServerState {
                application_uri: application_uri,
                product_uri: product_uri,
                application_name: LocalizedText {
                    locale: UAString::null(),
                    text: UAString::from_str(&application_name),
                },
                base_endpoint: base_endpoint,
                endpoints: endpoints,
                config: Arc::new(Mutex::new(config.clone())),
                server_certificate: ByteString::null(),
                address_space: Arc::new(Mutex::new(AddressSpace::new_top_level()))
            })),
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
