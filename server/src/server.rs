use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use session::{TcpSession, SessionConfig};

use config::{ServerConfig};

/// The Server represents a running instance of OPC UA. There can be more than one server running
/// at a time providing they do not share the same thread or listen on the same ports.
pub struct Server {
    pub config: ServerConfig,
    pub sessions: Vec<Arc<Mutex<TcpSession>>>,
    abort: bool,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Server {
        Server { config: config, abort: false, sessions: Vec::new() }
    }

    /// Create a new server instance using the server default configuration
    pub fn new_default() -> Server {
        Server::new(ServerConfig::default())
    }

    // Terminates the running server
    pub fn abort(&mut self) {
        self.abort = true;
    }

    /// Runs the server
    pub fn run(&mut self) {
        let host = self.config.host.clone();
        let sock_addr = (host.as_str(), self.config.port);
        let listener = TcpListener::bind(&sock_addr).unwrap();
        loop {
            if self.abort {
                break;
            }
            info!("Waiting for Connection on opc.tcp://{}:{}{}", self.config.host, self.config.port, self.config.path);
            for stream in listener.incoming() {
                let server_config = self.config.clone();
                match stream {
                    Ok(stream) => {
                        self.handle_connection(stream, &server_config);
                    }
                    Err(err) => {
                        warn!("Got an error on stream {:?}", err);
                    }
                }
            }
        }
    }

    /// Handles the incoming request
    fn handle_connection(&mut self, stream: TcpStream, server_config: &ServerConfig) {
        // Spawn a thread for the connection
        let session_config = SessionConfig {
            hello_timeout: server_config.hello_timeout,
        };
        let session = Arc::new(Mutex::new(TcpSession::new(session_config)));
        self.sessions.push(session.clone());
        thread::spawn(move || {
            TcpSession::run(stream, session);
        });
    }
}
