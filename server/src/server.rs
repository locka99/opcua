//! Provides the [`Server`] type and functionality related to it.

use std::sync::{Arc, RwLock, Mutex};
use std::net::SocketAddr;
use std::marker::Sync;
use std::time::{Instant, Duration};
use std::thread;

use futures::{Future, Stream};
use futures::future;
use futures::sync::mpsc::{unbounded, UnboundedSender};
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_timer::Interval;

use opcua_types::service_types::ServerState as ServerStateType;
use opcua_core::config::Config;
use opcua_core::prelude::*;

use crate::{
    address_space::types::AddressSpace,
    comms::tcp_transport::*,
    comms::transport::Transport,
    config::ServerConfig,
    constants,
    diagnostics::ServerDiagnostics,
    discovery,
    metrics::ServerMetrics,
    services::message_handler::MessageHandler,
    session::Session,
    state::ServerState,
    util::PollingAction,
};

pub type Connections = Vec<Arc<RwLock<TcpTransport>>>;

/// This represents a running instance of an OPC UA server. There can be more than one server running
/// at a time providing they do not share the same thread or listen on the same ports.
///
/// A `Server` is initialised from a [`ServerConfig`] which determines what port the server
/// runs on, the endpoints it supports, the identity tokens it supports and so forth.
///
/// The server's [`AddressSpace`] is initialised with the default address space values, but may also
/// be extended with additional nodes representing folders, variables, methods etc.
///
/// The server's [`CertificateStore`] manages the server's private key and public certificate. It
/// also manages public certificates of incoming clients and arranges them into trusted and rejected
/// collections.
///
/// [`ServerConfig`]: ../config/struct.ServerConfig.html
/// [`AddressSpace`]: ../address_space/address_space/struct.AddressSpace.html
/// [`CertificateStore`]: ../../opcua_core/crypto/certificate_store/struct.CertificateStore.html
///
pub struct Server {
    /// List of pending polling actions to add to the server once run is called
    pending_polling_actions: Vec<(u64, Box<dyn Fn() + Send + Sync + 'static>)>,
    /// Certificate store for certs
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Server metrics - diagnostics and anything else that someone might be interested in that
    /// describes the current state of the server
    server_metrics: Arc<RwLock<ServerMetrics>>,
    /// The server state is everything that sessions share that can possibly change. State
    /// is initialised from a [`ServerConfig`].
    server_state: Arc<RwLock<ServerState>>,
    /// Address space
    address_space: Arc<RwLock<AddressSpace>>,
    /// List of open connections
    connections: Arc<RwLock<Connections>>,
}

impl From<ServerConfig> for Server {
    fn from(config: ServerConfig) -> Server {
        Server::new(config)
    }
}

impl Server {
    /// Creates a new [`Server`] instance, initialising it from a [`ServerConfig`].
    ///
    /// [`Server`]: ./struct.Server.html
    /// [`ServerConfig`]: ../config/struct.ServerConfig.html
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
        let diagnostics = Arc::new(RwLock::new(ServerDiagnostics::default()));
        // TODO max string, byte string and array lengths

        // Security, pki auto create cert
        let application_description = if config.create_sample_keypair { Some(config.application_description()) } else { None };
        let (certificate_store, server_certificate, server_pkey) = CertificateStore::new_with_keypair(&config.pki_dir, application_description);
        if server_certificate.is_none() || server_pkey.is_none() {
            error!("Server is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }
        let config = Arc::new(RwLock::new(config.clone()));

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
            state: ServerStateType::Shutdown,
            start_time,
            config,
            server_certificate,
            server_pkey,
            last_subscription_id: 0,
            max_subscriptions,
            min_publishing_interval: constants::MIN_PUBLISHING_INTERVAL,
            default_keep_alive_count: constants::DEFAULT_KEEP_ALIVE_COUNT,
            max_keep_alive_count: constants::MAX_KEEP_ALIVE_COUNT,
            max_lifetime_count: constants::MAX_KEEP_ALIVE_COUNT * 3,
            diagnostics,
            abort: false,
        };
        let server_state = Arc::new(RwLock::new(server_state));

        // Set some values in the address space from the server state
        let address_space = Arc::new(RwLock::new(AddressSpace::new()));

        {
            let mut address_space = trace_write_lock_unwrap!(address_space);
            address_space.set_server_state(server_state.clone());
        }

        // Server metrics
        let server_metrics = Arc::new(RwLock::new(ServerMetrics::new()));

        // Cert store
        let certificate_store = Arc::new(RwLock::new(certificate_store));

        let server = Server {
            pending_polling_actions: Vec::new(),
            server_state,
            server_metrics: server_metrics.clone(),
            address_space,
            certificate_store,
            connections: Arc::new(RwLock::new(Vec::new())),
        };

        let mut server_metrics = trace_write_lock_unwrap!(server_metrics);
        server_metrics.set_server_info(&server);

        server
    }

    /// Runs the server which blocks until it completes either by aborting or by error. Typically
    /// a server should be run on its own thread.
    pub fn run(self) {
        let server = Arc::new(RwLock::new(self));
        Self::run_server(server);
    }

    /// Runs the supplied server reference counted server. The function will block until the server
    /// terminates, i.e. all running tokio tasks finish.
    pub fn run_server(server: Arc<RwLock<Server>>) {
        // Debug endpoints
        {
            let server = trace_read_lock_unwrap!(server);
            server.log_endpoint_info();
        }

        // Get the address and discovery url
        let (sock_addr, discovery_server_url) = {
            let server = trace_read_lock_unwrap!(server);
            let sock_addr = server.get_socket_address();
            let server_state = trace_read_lock_unwrap!(server.server_state);
            let config = trace_read_lock_unwrap!(server_state.config);
            (sock_addr, config.discovery_server_url.clone())
        };

        if sock_addr.is_none() {
            error!("Cannot resolve server address, check configuration of server");
            return;
        }
        let sock_addr = sock_addr.unwrap();

        // These are going to be used to abort the thread via the completion pack

        info!("Waiting for Connection");
        // This is the main tokio task
        tokio::run({
            let server = server.clone();
            let server_for_listener = server.clone();

            let (tx_abort, rx_abort) = unbounded::<()>();

            // Put the server into a running state
            future::lazy(move || {
                {
                    let mut server = trace_write_lock_unwrap!(server);
                    // Running
                    {
                        let mut server_state = trace_write_lock_unwrap!(server.server_state);
                        server_state.start_time = DateTime::now();
                        server_state.set_state(ServerStateType::Running);
                    }

                    // Start a timer that registers the server with a discovery server
                    server.start_discovery_server_registration_timer(discovery_server_url);
                    // Start any pending polling action timers
                    server.start_pending_polling_actions();
                }

                // Start a server abort task loop
                Self::start_abort_poll(server, tx_abort);

                future::ok(())
            }).and_then(move |_| {
                use crate::completion_pact::stream_completion_pact;
                // Listen for connections
                let listener = TcpListener::bind(&sock_addr).unwrap();
                stream_completion_pact(listener.incoming(), rx_abort)
                    .for_each(move |socket| {
                        // Clear out dead sessions
                        info!("Handling new connection {:?}", socket);
                        let mut server = trace_write_lock_unwrap!(server_for_listener);
                        // Check for abort
                        if {
                            let server_state = trace_read_lock_unwrap!(server.server_state);
                            server_state.is_abort()
                        } {
                            info!("Server is aborting so it will not accept new connections");
                        } else {
                            server.handle_connection(socket);
                        }
                        Ok(())
                    })
                    .map(|_| {
                        info!("Completion pact has completed");
                    })
                    .map_err(|err| {
                        error!("Completion pact, incoming error = {:?}", err);
                    })
            }).map(|_| {
                info!("Server task is finished");
            }).map_err(|err| {
                error!("Server task is finished with an error {:?}", err);
            })
        });
        info!("Server has stopped");
    }

    pub fn server_state(&self) -> Arc<RwLock<ServerState>> {
        self.server_state.clone()
    }

    pub fn certificate_store(&self) -> Arc<RwLock<CertificateStore>> {
        self.certificate_store.clone()
    }

    pub fn address_space(&self) -> Arc<RwLock<AddressSpace>> {
        self.address_space.clone()
    }

    pub fn connections(&self) -> Arc<RwLock<Connections>> {
        self.connections.clone()
    }

    pub fn server_metrics(&self) -> Arc<RwLock<ServerMetrics>> {
        self.server_metrics.clone()
    }

    // Sets a flag telling the running server to abort. The abort will happen asynchronously after
    // all sessions have disconnected.
    pub fn abort(&mut self) {
        info!("Server has been instructed to abort");
        let mut server_state = trace_write_lock_unwrap!(self.server_state);
        server_state.abort();
    }

    /// Strip out dead connections, i.e those which have disconnected. Returns `true` if there are
    /// still open connections after this function completes.
    fn remove_dead_connections(&self) -> bool {
        // Go through all connections, removing those that have terminated
        let mut connections = trace_write_lock_unwrap!(self.connections);
        connections.retain(|connection| {
            // Try to obtain the lock on the transport and the session and check if session is terminated
            // if it is, then we'll use its termination status to sweep it out.
            let mut lock = connection.try_read();
            if let Ok(ref mut connection) = lock {
                !connection.is_session_terminated()
            } else {
                true
            }
        });
        !connections.is_empty()
    }

    // Log information about the endpoints on this server
    fn log_endpoint_info(&self) {
        let server_state = trace_read_lock_unwrap!(self.server_state);
        let config = trace_read_lock_unwrap!(server_state.config);
        info!("OPC UA Server: {}", server_state.application_name);
        info!("Base url: {}", server_state.base_endpoint);
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

    fn get_socket_address(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        let server_state = trace_read_lock_unwrap!(self.server_state);
        let config = trace_read_lock_unwrap!(server_state.config);
        // Resolve this host / port to an address (or not)
        let address = format!("{}:{}", config.tcp_config.host, config.tcp_config.port);
        if let Ok(mut addrs_iter) = address.to_socket_addrs() {
            addrs_iter.next()
        } else {
            None
        }
    }

    // This timer will poll the server to see if it has aborted. It also cleans up dead connections.
    // If it determines to abort it will signal the tx_abort so that the main listener loop can
    // be broken at its convenience.
    fn start_abort_poll(server: Arc<RwLock<Server>>, tx_abort: UnboundedSender<()>) {
        let task = Interval::new(Instant::now(), Duration::from_millis(1000))
            .take_while(move |_| {
                trace!("abort_poll_task.take_while");
                let abort = {
                    // Check if there are any open sessions
                    let server = trace_read_lock_unwrap!(server);
                    let has_open_connections = server.remove_dead_connections();
                    let server_state = trace_read_lock_unwrap!(server.server_state);
                    // Predicate breaks take_while on abort & no open connections
                    if server_state.is_abort() {
                        if has_open_connections {
                            warn!("Abort called while there were still open connections");
                        }
                        true
                    } else {
                        false
                    }
                };
                if abort {
                    info!("Server has aborted so, sending a command to break the listen loop");
                    tx_abort.unbounded_send(()).unwrap();
                }
                future::ok(!abort)
            })
            .for_each(|_| {
                // DO NOTHING - take_while is where we do stuff
                Ok(())
            })
            .map(|_| {
                info!("Abort poll task is finished");
            })
            .map_err(|err| {
                error!("Abort poll error = {:?}", err);
            });

        tokio::spawn(task);
    }

    /// Start a timer that triggers every 5 minutes and causes the server to register itself with a discovery server
    fn start_discovery_server_registration_timer(&self, discovery_server_url: Option<String>) {
        if let Some(discovery_server_url) = discovery_server_url {
            info!("Server has set a discovery server url {} which will be used to register the server", discovery_server_url);
            let server_state = self.server_state.clone();
            let server_state_for_take = self.server_state.clone();

            // The registration timer fires on a duration, so make that duration and pretend the
            // last time it fired was now - duration, so it should instantly fire when polled next.
            let register_duration = Duration::from_secs(5 * 60);
            let last_registered = Instant::now() - register_duration;
            let last_registered = Arc::new(Mutex::new(last_registered));

            // Polling happens fairly quickly so task can terminate on server abort, however
            // it is looking for the registration duration to have elapsed until it actually does
            // anything.
            let task = Interval::new(Instant::now(), Duration::from_millis(1000))
                .take_while(move |_| {
                    trace!("discovery_server_register.take_while");
                    let server_state = trace_read_lock_unwrap!(server_state_for_take);
                    future::ok(!server_state.is_abort())
                })
                .for_each(move |_| {
                    // Test if registration needs to happen, i.e. if this is first time around,
                    // or if duration has elapsed since last attempt.
                    trace!("discovery_server_register.for_each");
                    let now = Instant::now();
                    let mut last_registered = trace_lock_unwrap!(last_registered);
                    let register_server = if now.duration_since(*last_registered) >= register_duration {
                        true
                    } else {
                        false
                    };
                    if register_server {
                        *last_registered = now;
                        // Even though the client uses tokio internally, the client's API is synchronous
                        // so the registration will happen on its own thread. The expectation is that
                        // it will run and either succeed, or it will fail but either way the operation
                        // will have completed before the next timer fires.
                        let server_state = server_state.clone();
                        let discovery_server_url = discovery_server_url.clone();
                        let _ = thread::spawn(move || {
                            use std;
                            let _ = std::panic::catch_unwind(move || {
                                let server_state = trace_read_lock_unwrap!(server_state);
                                if server_state.is_running() {
                                    discovery::register_with_discovery_server(&discovery_server_url, &server_state);
                                }
                            });
                        });
                    }
                    Ok(())
                })
                .map(|_| {
                    info!("Discovery timer task is finished");
                })
                .map_err(|err| {
                    error!("Discovery timer task registration error = {:?}", err);
                });
            tokio::spawn(task);
        } else {
            info!("Server has not set a discovery server url, so no registration will happen");
        }
    }

    /// Creates a polling action that happens continuously on an interval while the server
    /// is running.
    pub fn add_polling_action<F>(&mut self, interval_ms: u64, action: F)
        where F: Fn() + Send + Sync + 'static {
        // If the server is not yet running, the action is queued and is started later
        let server_state = trace_read_lock_unwrap!(self.server_state);
        if server_state.is_abort() {
            error!("Polling action added when server is aborting");
            // DO NOTHING
        } else if !server_state.is_running() {
            self.pending_polling_actions.push((interval_ms, Box::new(action)));
        } else {
            // Start the action immediately
            let _ = PollingAction::spawn(self.server_state.clone(), interval_ms, move || {
                // Call the provided closure with the address space
                action();
            });
        }
    }

    /// Starts any polling actions which were queued ready to start but not yet
    fn start_pending_polling_actions(&mut self) {
        let server_state = self.server_state.clone();
        self.pending_polling_actions
            .drain(..)
            .for_each(|(interval_ms, action)| {
                debug!("Starting a pending polling action at rate of {} ms", interval_ms);
                let _ = PollingAction::spawn(server_state.clone(), interval_ms, move || {
                    // Call the provided action
                    action();
                });
            });
    }

    pub fn new_transport(&self) -> TcpTransport {
        let session = {
            Arc::new(RwLock::new(Session::new(self)))
        };
        // TODO session should be stored in a sessions list so that disconnected sessions can be
        //  reestablished if necessary
        let address_space = self.address_space.clone();
        let message_handler = MessageHandler::new(self.certificate_store.clone(), self.server_state.clone(), session.clone(), address_space.clone());
        TcpTransport::new(self.server_state.clone(), session, address_space, message_handler)
    }

    /// Handles the incoming request
    fn handle_connection(&mut self, socket: TcpStream) {
        trace!("Connection thread spawning");

        // Spawn a thread for the connection
        let connection = Arc::new(RwLock::new(self.new_transport()));
        {
            let mut connections = trace_write_lock_unwrap!(self.connections);
            connections.push(connection.clone());
        }

        // Run adds a session task to the tokio session
        TcpTransport::run(connection, socket);
    }
}
