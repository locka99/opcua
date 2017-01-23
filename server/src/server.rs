use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use opcua_core::types::*;
use opcua_core::address_space::*;

use tcp_transport::{TcpTransport};

use config::{ServerConfig};

/// Server state is any state associated with the server as a whole that individual sessions might
/// be interested in. That includes configuration info, address space etc.
#[derive(Clone)]
pub struct ServerState {
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
        Server {
            server_state: Arc::new(Mutex::new(ServerState {
                config: Arc::new(Mutex::new(config.clone())),
                server_certificate: ByteString::null(),
                address_space: Arc::new(Mutex::new(AddressSpace::new()))
            })),
            abort: false,
            sessions: Vec::new()
        }
    }

    /// Create a new server instance using the server default configuration
    pub fn new_default() -> Server {
        Server::new(&ServerConfig::default())
    }

    // Terminates the running server
    pub fn abort(&mut self) {
        self.abort = true;
    }

    /// Runs the server
    pub fn run(&mut self) {
        let (host, port, endpoint) = {
            let server_state = self.server_state.lock().unwrap();
            let config = server_state.config.lock().unwrap();
            (config.tcp_config.host.clone(), config.tcp_config.port, config.default_path.clone())
        };
        let sock_addr = (host.as_str(), port);
        let listener = TcpListener::bind(&sock_addr).unwrap();
        loop {
            if self.abort {
                break;
            }
            info!("Waiting for Connection on opc.tcp://{}:{}{}", host, port, endpoint);
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
