//! The server module defines types related to the server, it's current running state
//! and end point information.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::thread;

use opcua_types::*;

use opcua_core::prelude::*;
use opcua_core::config::Config;

use constants;
use address_space::types::AddressSpace;
use comms::tcp_transport::*;
use config::{ServerConfig};
use server_state::{ServerState, ServerDiagnostics};
use util::PollingAction;

/// The Server represents a running instance of OPC UA. There can be more than one server running
/// at a time providing they do not share the same thread or listen on the same ports.
pub struct Server {
    /// The server state is everything that sessions share - address space, configuration etc.
    pub server_state: Arc<Mutex<ServerState>>,
    /// List of open connections
    pub connections: Vec<Arc<Mutex<TcpTransport>>>,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Server {
        if !config.is_valid() {
            panic!("Cannot create a server using an invalid configuration.");
        }

        // Set from config
        let application_name = config.application_name.clone();
        let application_uri = UAString::from(config.application_uri.as_ref());
        let product_uri = UAString::from(config.product_uri.as_ref());
        let namespaces = vec!["http://opcfoundation.org/UA/".to_string(), "urn:OPCUA-Rust-Internal".to_string(), config.application_uri.clone()];
        let start_time = DateTime::now();
        let servers = vec![config.application_uri.clone()];
        let base_endpoint = format!("opc.tcp://{}:{}", config.tcp_config.host, config.tcp_config.port);
        let max_subscriptions = config.max_subscriptions as usize;
        let address_space = Arc::new(Mutex::new(AddressSpace::new()));
        let diagnostics = ServerDiagnostics::new();
        // TODO max string, byte string and array lengths

        // Security, pki auto create cert
        let pki_path = PathBuf::from(&config.pki_dir);
        let certificate_store = CertificateStore::new(&pki_path);
        let (server_certificate, server_pkey) = if certificate_store.ensure_pki_path().is_err() {
            error!("Folder for storing certificates cannot be examined so server has no application instance certificate or private key.");
            (None, None)
        } else {
            let result = certificate_store.read_own_cert_and_pkey();
            if let Ok(result) = result {
                let (cert, pkey) = result;
                (Some(cert), Some(pkey))
            } else {
                // For sample projects, this value will be true and as a convenience we will create
                // a certificate and private key if they do not exist.
                if config.create_sample_keypair {
                    info!("Creating sample application instance certificate and private key");
                    let result = certificate_store.create_and_store_application_instance_cert(&X509Data::sample_cert(), false);
                    if let Err(err) = result {
                        error!("Certificate creation failed, error = {}", err);
                        (None, None)
                    } else {
                        let (cert, pkey) = result.unwrap();
                        (Some(cert), Some(pkey))
                    }
                } else {
                    error!("Application instance certificate and private key could not be read - {}", result.unwrap_err());
                    (None, None)
                }
            }
        };
        if server_certificate.is_none() || server_pkey.is_none() {
            error!("Server is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }
        let certificate_store = Arc::new(Mutex::new(certificate_store));
        let config = Arc::new(Mutex::new(config.clone()));

        let server_state = ServerState {
            application_uri,
            product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from(application_name),
            },
            namespaces,
            servers,
            base_endpoint,
            start_time,
            config,
            certificate_store,
            server_certificate,
            server_pkey,
            address_space,
            last_subscription_id: 0,
            max_subscriptions,
            min_publishing_interval: constants::MIN_PUBLISHING_INTERVAL,
            max_keep_alive_count: constants::MAX_KEEP_ALIVE_COUNT,
            diagnostics,
            abort: false,
        };

        // Set some values in the address space from the server state
        {
            let mut address_space = server_state.address_space.lock().unwrap();
            address_space.set_server_state(&server_state);
        }

        Server {
            server_state: Arc::new(Mutex::new(server_state)),
            connections: Vec::new()
        }
    }

    // Terminates the running server
    pub fn abort(&mut self) {
        let mut server_state = self.server_state.lock().unwrap();
        server_state.abort = true;
    }

    /// Runs the server
    pub fn run(&mut self) {
        let (host, port, _) = {
            let server_state = self.server_state.lock().unwrap();
            let config = server_state.config.lock().unwrap();
            (config.tcp_config.host.clone(), config.tcp_config.port, server_state.base_endpoint.clone())
        };
        let sock_addr = (host.as_str(), port);
        let listener = TcpListener::bind(&sock_addr).unwrap();

        {
            let server_state = self.server_state.lock().unwrap();
            let config = server_state.config.lock().unwrap();

            info!("OPC UA Server: {}", server_state.application_name);
            info!("Supported endpoints:");
            for (id, endpoint) in &config.endpoints {
                let users: Vec<String> = endpoint.user_token_ids.iter().map(|id| id.clone()).collect();
                let users = users.join(", ");

                info!("Endpoint \"{}\": {}", id, endpoint.path);
                info!("  Security Mode:    {}", endpoint.security_mode);
                info!("  Security Policy:  {}", endpoint.security_policy);
                info!("  Supported user tokens - {}", users);
            }
        }
        info!("Waiting for Connection");

        // This iterator runs forever, just accept()'ing the next incoming connection.
        for stream in listener.incoming() {
            if self.is_abort() {
                info!("Server is aborting");
                break;
            }
            info!("Handling new connection {:?}", stream);
            match stream {
                Ok(stream) => {
                    self.handle_connection(stream);
                }
                Err(err) => {
                    warn!("Got an error on stream {:?}", err);
                }
            }
            // Clear out dead sessions
            self.remove_dead_connections();
        }
    }

    fn is_abort(&mut self) -> bool {
        let server_state = self.server_state.lock().unwrap();
        server_state.abort
    }

    fn remove_dead_connections(&mut self) {
        // Go through all connections, removing those that have terminated
        self.connections.retain(|connection| {
            // Try to obtain the lock on the transport and the session and check if session is terminated
            // if it is, then we'll use its termination status to sweep it out.
            let mut lock = connection.try_lock();
            if let Ok(ref mut connection) = lock {
                let mut lock = connection.session.try_lock();
                if let Ok(ref mut session) = lock {
                    if session.terminated {
                        info!("Removing terminated session");
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            }
        });
    }

    /// Creates a polling action that happens continuously on an interval. The supplied
    /// function receives the address space which it can do what it likes with.
    ///
    /// This function is be updating values in the address space individually or en masse.
    /// The returned PollingAction will ensure the function is called for as long as it is
    /// in scope. Once the action is dropped, the function will no longer be called.
    pub fn create_address_space_polling_action<F>(&mut self, interval_ms: u32, action: F) -> PollingAction
        where F: 'static + FnMut(&mut AddressSpace) + Send {
        let mut action = action;
        let address_space = {
            let server_state = self.server_state.lock().unwrap();
            server_state.address_space.clone()
        };
        PollingAction::new(interval_ms, move || {
            // Call the provided closure with the address space
            action(&mut address_space.lock().unwrap());
        })
    }

    /// Handles the incoming request
    fn handle_connection(&mut self, stream: TcpStream) {
        trace!("Connection thread spawning");
        // Spawn a thread for the connection
        let session = Arc::new(Mutex::new(TcpTransport::new(self.server_state.clone())));
        self.connections.push(session.clone());
        thread::spawn(move || {
            session.lock().unwrap().run(stream);
            info!("Session thread is terminated");
        });
    }
}
