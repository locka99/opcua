// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides the [`Server`] type and functionality related to it.

use std::{marker::Sync, net::SocketAddr, panic::AssertUnwindSafe, sync::Arc};

use tokio::{
    self,
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::oneshot::{self, Sender},
    time::{interval_at, Duration, Instant},
};

use crate::core::{config::Config, prelude::*};
use crate::crypto::*;
use crate::sync::*;
use crate::types::service_types::ServerState as ServerStateType;

use crate::server::{
    address_space::types::AddressSpace,
    comms::tcp_transport::*,
    comms::transport::Transport,
    config::ServerConfig,
    constants,
    diagnostics::ServerDiagnostics,
    events::audit::AuditLog,
    metrics::ServerMetrics,
    session::SessionManager,
    state::{OperationalLimits, ServerState},
    util::PollingAction,
};

pub type Connections = Vec<Arc<RwLock<TcpTransport>>>;

/// A `Server` represents a running instance of an OPC UA server. There can be more than one `Server`
/// running at any given time providing they do not share the same ports.
///
/// A `Server` is initialised from a [`ServerConfig`]. The `ServerConfig` sets what port the server
/// runs on, the endpoints it supports, the identity tokens it supports, identity tokens and so forth.
/// A single server can offer multiple endpoints with different security policies. A server can
/// also be configured to register itself with a discovery server.
///
/// Once the `Server` is configured, it is run by calling [`run`] which consumes the `Server`.
/// Alternatively if you have reason to maintain access to the server object,
/// you may call the static function [`run_server`] providing the server wrapped as
/// `Arc<RwLock<Server>>`.
///
/// The server's [`AddressSpace`] is initialised with the default OPC UA node set, but may also
/// be extended with additional nodes representing folders, variables, methods etc.
///
/// The server's [`CertificateStore`] manages the server's private key and public certificate. It
/// also manages public certificates of incoming clients and arranges them into trusted and rejected
/// collections.
///
/// [`run`]: #method.run
/// [`run_server`]: #method.run_server
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
    /// Session manager
    session_manager: Arc<RwLock<SessionManager>>,
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
    pub fn new(mut config: ServerConfig) -> Server {
        if !config.is_valid() {
            panic!("Cannot create a server using an invalid configuration.");
        }

        // Set from config
        let application_name = config.application_name.clone();
        let application_uri = UAString::from(&config.application_uri);
        let product_uri = UAString::from(&config.product_uri);
        let start_time = DateTime::now();
        let servers = vec![config.application_uri.clone()];
        let base_endpoint = format!(
            "opc.tcp://{}:{}",
            config.tcp_config.host, config.tcp_config.port
        );
        let max_subscriptions = config.limits.max_subscriptions as usize;
        let max_monitored_items_per_sub = config.limits.max_monitored_items_per_sub as usize;
        let max_monitored_item_queue_size = config.limits.max_monitored_item_queue_size as usize;

        let diagnostics = Arc::new(RwLock::new(ServerDiagnostics::default()));
        let min_publishing_interval_ms = config.limits.min_publishing_interval * 1000.0;
        let min_sampling_interval_ms = config.limits.min_sampling_interval * 1000.0;
        let send_buffer_size = config.limits.send_buffer_size;
        let receive_buffer_size = config.limits.receive_buffer_size;

        // Security, pki auto create cert
        let application_description = if config.create_sample_keypair {
            Some(config.application_description())
        } else {
            None
        };
        let (mut certificate_store, server_certificate, server_pkey) =
            CertificateStore::new_with_x509_data(
                &config.pki_dir,
                false,
                config.certificate_path.as_deref(),
                config.private_key_path.as_deref(),
                application_description,
            );
        if server_certificate.is_none() || server_pkey.is_none() {
            error!("Server is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }

        // Load thumbprints of every user token
        config.read_x509_thumbprints();

        // Servers may choose to auto trust clients to save some messing around with rejected certs.
        // This is strongly not advised in production.
        if config.certificate_validation.trust_client_certs {
            info!("Server has chosen to auto trust client certificates. You do not want to do this in production code.");
            certificate_store.set_trust_unknown_certs(true);
        }
        certificate_store.set_check_time(config.certificate_validation.check_time);

        let config = Arc::new(RwLock::new(config));

        // Set some values in the address space from the server state
        let address_space = Arc::new(RwLock::new(AddressSpace::new()));

        let audit_log = Arc::new(RwLock::new(AuditLog::new(address_space.clone())));

        let server_state = ServerState {
            application_uri,
            product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from(application_name),
            },
            servers,
            base_endpoint,
            state: ServerStateType::Shutdown,
            start_time,
            config,
            server_certificate,
            server_pkey,
            last_subscription_id: 0,
            max_subscriptions,
            max_monitored_items_per_sub,
            max_monitored_item_queue_size,
            min_publishing_interval_ms,
            min_sampling_interval_ms,
            default_keep_alive_count: constants::DEFAULT_KEEP_ALIVE_COUNT,
            max_keep_alive_count: constants::MAX_KEEP_ALIVE_COUNT,
            max_lifetime_count: constants::MAX_KEEP_ALIVE_COUNT * 3,
            diagnostics,
            abort: false,
            audit_log,
            register_nodes_callback: None,
            unregister_nodes_callback: None,
            historical_data_provider: None,
            historical_event_provider: None,
            operational_limits: OperationalLimits::default(),
            send_buffer_size,
            receive_buffer_size,
        };
        let server_state = Arc::new(RwLock::new(server_state));

        {
            let mut address_space = trace_write_lock!(address_space);
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
            session_manager: Arc::new(RwLock::new(SessionManager::default())),
        };

        let mut server_metrics = trace_write_lock!(server_metrics);
        server_metrics.set_server_info(&server);

        server
    }

    /// Runs the server and blocks until it completes either by aborting or by error. Typically
    /// a server should be run on its own thread.
    ///
    /// Calling this function consumes the server.
    pub fn run(self) {
        let server = Arc::new(RwLock::new(self));
        Self::run_server(server);
    }

    /// Runs the supplied server and blocks until it completes either by aborting or
    /// by error.
    pub fn run_server(server: Arc<RwLock<Server>>) {
        let single_threaded_executor = {
            let server = trace_read_lock!(server);
            let server_state = trace_read_lock!(server.server_state);
            let config = trace_read_lock!(server_state.config);
            config.performance.single_threaded_executor
        };
        let server_task = Self::new_server_task(server);
        // Launch
        let mut builder = if !single_threaded_executor {
            tokio::runtime::Builder::new_multi_thread()
        } else {
            tokio::runtime::Builder::new_current_thread()
        };
        let runtime = builder.enable_all().build().unwrap();
        Self::run_server_on_runtime(runtime, server_task, true);
    }

    /// Allow the server to be run on a caller supplied runtime. If block is set, the task
    /// runs to completion (abort or by error), otherwise, the task is spawned and a join handle is
    /// returned by the function. Spawning might be suitable if the runtime is being used for other
    /// async tasks.
    pub fn run_server_on_runtime<F>(
        runtime: tokio::runtime::Runtime,
        server_task: F,
        block: bool,
    ) -> Option<tokio::task::JoinHandle<<F as futures::Future>::Output>>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        if block {
            runtime.block_on(server_task);
            info!("Server has finished");
            None
        } else {
            Some(runtime.spawn(server_task))
        }
    }

    /// Returns the main server task - the loop that waits for connections and processes them.
    pub async fn new_server_task(server: Arc<RwLock<Server>>) {
        // Get the address and discovery url
        let (sock_addr, discovery_server_url) = {
            let server = trace_read_lock!(server);

            // Debug endpoints
            server.log_endpoint_info();

            let sock_addr = server.get_socket_address();
            let server_state = trace_read_lock!(server.server_state);
            let config = trace_read_lock!(server_state.config);

            // Discovery url must be present and valid
            let discovery_server_url =
                if let Some(ref discovery_server_url) = config.discovery_server_url {
                    if is_valid_opc_ua_url(discovery_server_url) {
                        Some(discovery_server_url.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };

            (sock_addr, discovery_server_url)
        };
        match sock_addr {
            None => {
                error!("Cannot resolve server address, check configuration of server");
            }
            Some(sock_addr) => Self::server_task(server, sock_addr, discovery_server_url).await,
        }
    }

    async fn server_task<A: ToSocketAddrs>(
        server: Arc<RwLock<Server>>,
        sock_addr: A,
        discovery_server_url: Option<String>,
    ) {
        // This is returned as the main server task
        info!("Waiting for Connection");
        // Listen for connections (or abort)
        let listener = match TcpListener::bind(&sock_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                panic!("Could not bind to socket {:?}", err)
            }
        };

        let (tx_abort, rx_abort) = oneshot::channel();

        // Put the server into a running state
        {
            let mut server = trace_write_lock!(server);
            // Running
            {
                let mut server_state = trace_write_lock!(server.server_state);
                server_state.start_time = DateTime::now();
                server_state.set_state(ServerStateType::Running);
            }

            // Start a timer that registers the server with a discovery server
            if let Some(ref discovery_server_url) = discovery_server_url {
                server.start_discovery_server_registration_timer(discovery_server_url);
            } else {
                info!("Server has not set a discovery server url, so no registration will happen");
            }

            // Start any pending polling action timers
            server.start_pending_polling_actions();
        }

        // Start a server abort task loop
        Self::start_abort_poll(server.clone(), tx_abort);

        // This isn't nice syntax, but basically there are two async actions
        // going on, one of which has to complete - either the listener breaks out of its
        // loop, or the rx_abort receives an abort message.
        tokio::select! {
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((socket, _addr)) => {
                            // Clear out dead sessions
                            info!("Handling new connection {:?}", socket);
                            // Check for abort
                            let mut server = trace_write_lock!(server);
                            let is_abort = {
                                let server_state = trace_read_lock!(server.server_state);
                                server_state.is_abort()
                            };
                            if is_abort {
                                info!("Server is aborting so it will not accept new connections");
                                break;
                            } else {
                                server.handle_connection(socket);
                            }
                        }
                        Err(e) => {
                            error!("couldn't accept connection to client: {:?}", e);
                        }
                    }
                }
                // Help the rust type inferencer out
                Ok::<_, tokio::io::Error>(())
            } => {}
            _ = rx_abort => {
                info!("abort received");
            }
        }
        info!("main server task is finished");
    }

    /// Returns the current [`ServerState`] for the server.
    ///
    /// [`ServerState`]: ../state/struct.ServerState.html
    pub fn server_state(&self) -> Arc<RwLock<ServerState>> {
        self.server_state.clone()
    }

    /// Returns the `CertificateStore` for the server.
    pub fn certificate_store(&self) -> Arc<RwLock<CertificateStore>> {
        self.certificate_store.clone()
    }

    /// Returns the [`AddressSpace`] for the server.
    ///
    /// [`AddressSpace`]: ../address_space/address_space/struct.AddressSpace.html
    pub fn address_space(&self) -> Arc<RwLock<AddressSpace>> {
        self.address_space.clone()
    }

    /// Returns the [`Connections`] for the server.
    ///
    /// [`Connections`]: ./type.Connections.html
    pub fn connections(&self) -> Arc<RwLock<Connections>> {
        self.connections.clone()
    }

    /// Returns the [`ServerMetrics`] for the server.
    ///
    /// [`ServerMetrics`]: ../metrics/struct.ServerMetrics.html
    pub fn server_metrics(&self) -> Arc<RwLock<ServerMetrics>> {
        self.server_metrics.clone()
    }

    /// Returns the `single_threaded_executor` for the server.
    pub fn single_threaded_executor(&self) -> bool {
        let server_state = trace_read_lock!(self.server_state);
        let config = trace_read_lock!(server_state.config);
        config.performance.single_threaded_executor
    }

    /// Sets a flag telling the running server to abort. The abort will happen asynchronously after
    /// all sessions have disconnected.
    pub fn abort(&mut self) {
        info!("Server has been instructed to abort");
        let mut server_state = trace_write_lock!(self.server_state);
        server_state.abort();
    }

    /// Strip out dead connections, i.e those which have disconnected. Returns `true` if there are
    /// still open connections after this function completes.
    fn remove_dead_connections(&self) -> bool {
        // Go through all connections, removing those that have terminated
        let mut connections = trace_write_lock!(self.connections);
        connections.retain(|transport| {
            // Try to obtain the lock on the transport and the session and check if session is terminated
            // if it is, then we'll use its termination status to sweep it out.
            let lock = transport.try_read();
            if let Some(ref transport) = lock {
                let session_manager = transport.session_manager();
                let session_manager = trace_read_lock!(session_manager);
                !session_manager.sessions_terminated()
            } else {
                true
            }
        });
        !connections.is_empty()
    }

    /// Log information about the endpoints on this server
    fn log_endpoint_info(&self) {
        let server_state = trace_read_lock!(self.server_state);
        let config = trace_read_lock!(server_state.config);
        info!("OPC UA Server: {}", server_state.application_name);
        info!("Base url: {}", server_state.base_endpoint);
        info!("Supported endpoints:");
        for (id, endpoint) in &config.endpoints {
            let users: Vec<String> = endpoint.user_token_ids.iter().cloned().collect();
            let users = users.join(", ");
            info!("Endpoint \"{}\": {}", id, endpoint.path);
            info!("  Security Mode:    {}", endpoint.security_mode);
            info!("  Security Policy:  {}", endpoint.security_policy);
            info!("  Supported user tokens - {}", users);
        }
    }

    /// Returns the server socket address.
    fn get_socket_address(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        let server_state = trace_read_lock!(self.server_state);
        let config = trace_read_lock!(server_state.config);
        // Resolve this host / port to an address (or not)
        let address = format!("{}:{}", config.tcp_config.host, config.tcp_config.port);
        if let Ok(mut addrs_iter) = address.to_socket_addrs() {
            addrs_iter.next()
        } else {
            None
        }
    }

    /// This timer will poll the server to see if it has aborted. It also cleans up dead connections.
    /// If it determines to abort it will signal the tx_abort so that the main listener loop can
    /// be broken at its convenience.
    fn start_abort_poll(server: Arc<RwLock<Server>>, tx_abort: Sender<()>) {
        tokio::spawn(async move {
            let mut timer = interval_at(Instant::now(), Duration::from_millis(1000));
            loop {
                trace!("abort_poll_task.take_while");
                // Check if there are any open sessions
                {
                    let server = trace_read_lock!(server);
                    let has_open_connections = server.remove_dead_connections();
                    let server_state = trace_read_lock!(server.server_state);
                    // Predicate breaks on abort & no open connections
                    if server_state.is_abort() {
                        if has_open_connections {
                            warn!("Abort called while there were still open connections");
                        }
                        info!("Server has aborted so, sending a command to break the listen loop");
                        tx_abort.send(()).unwrap();
                        break;
                    }
                }
                timer.tick().await;
            }
            info!("Abort poll task is finished");
        });
    }

    /// Discovery registration is disabled.
    #[cfg(not(feature = "discovery-server-registration"))]
    fn start_discovery_server_registration_timer(&self, discovery_server_url: &str) {
        info!("Discovery server registration is disabled in code so registration with {} will not happen", discovery_server_url);
    }

    /// Discovery registration runs a timer that triggers every 5 minutes and causes the server
    /// to register itself with a discovery server.
    #[cfg(feature = "discovery-server-registration")]
    fn start_discovery_server_registration_timer(&self, discovery_server_url: &str) {
        use crate::server::discovery;

        let discovery_server_url = discovery_server_url.to_string();
        info!(
            "Server has set a discovery server url {} which will be used to register the server",
            discovery_server_url
        );
        let server_state = self.server_state.clone();

        // The registration timer fires on a duration, so make that duration and pretend the
        // last time it fired was now - duration, so it should instantly fire when polled next.
        let register_duration = Duration::from_secs(5 * 60);
        let last_registered = Instant::now() - register_duration;
        let last_registered = Arc::new(Mutex::new(last_registered));

        tokio::spawn(async move {
            // Polling happens fairly quickly so task can terminate on server abort, however
            // it is looking for the registration duration to have elapsed until it actually does
            // anything.
            let mut timer = interval_at(Instant::now(), Duration::from_millis(1000));
            loop {
                trace!("discovery_server_register.take_while");
                {
                    let server_state = trace_read_lock!(server_state);
                    if !server_state.is_running() || server_state.is_abort() {
                        break;
                    }
                }

                timer.tick().await;

                // Test if registration needs to happen, i.e. if this is first time around,
                // or if duration has elapsed since last attempt.
                trace!("discovery_server_register.for_each");
                let now = Instant::now();
                let mut last_registered = trace_lock!(last_registered);
                if now.duration_since(*last_registered) >= register_duration {
                    *last_registered = now;
                    // Even though the client uses tokio internally, the client's API is synchronous
                    // so the registration will happen on its own thread. The expectation is that
                    // it will run and either succeed, or it will fail but either way the operation
                    // will have completed before the next timer fires.
                    let server_state = server_state.clone();
                    let discovery_server_url = discovery_server_url.clone();
                    let _ = std::thread::spawn(move || {
                        let _ = std::panic::catch_unwind(AssertUnwindSafe(move || {
                            let server_state = trace_read_lock!(server_state);
                            if server_state.is_running() {
                                discovery::register_with_discovery_server(
                                    &discovery_server_url,
                                    &server_state,
                                );
                            }
                        }));
                    });
                }
            }
            info!("Discovery timer task is finished");
        });
    }

    /// Creates a polling action that happens continuously on an interval while the server
    /// is running. For example, a server might run a polling action every 100ms to synchronous
    /// address space state between variables and their physical backends.
    ///
    /// The function that is supplied does not take any arguments. It is expected that the
    /// implementation will move any variables into the function that are required to perform its
    /// action.
    pub fn add_polling_action<F>(&mut self, interval_ms: u64, action: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        // If the server is not yet running, the action is queued and is started later
        let server_state = trace_read_lock!(self.server_state);
        if server_state.is_abort() {
            error!("Polling action added when server is aborting");
        // DO NOTHING
        } else if !server_state.is_running() {
            self.pending_polling_actions
                .push((interval_ms, Box::new(action)));
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
                debug!(
                    "Starting a pending polling action at rate of {} ms",
                    interval_ms
                );
                let _ = PollingAction::spawn(server_state.clone(), interval_ms, move || {
                    // Call the provided action
                    action();
                });
            });
    }

    /// Create a new transport.
    pub fn new_transport(&self) -> TcpTransport {
        TcpTransport::new(
            self.certificate_store.clone(),
            self.server_state.clone(),
            self.address_space.clone(),
            self.session_manager.clone(),
        )
    }

    /// Handles the incoming request
    fn handle_connection(&mut self, socket: TcpStream) {
        trace!("Connection thread spawning");

        // Spawn a task for the connection
        let connection = Arc::new(RwLock::new(self.new_transport()));
        {
            let mut connections = trace_write_lock!(self.connections);
            connections.push(connection.clone());
        }

        // Looping interval has to cope with whatever sampling rate server needs
        let looping_interval_ms = {
            let server_state = trace_read_lock!(self.server_state);
            // Get the minimum interval in ms
            f64::min(
                server_state.min_publishing_interval_ms,
                server_state.min_sampling_interval_ms,
            )
        };

        // Run adds a session task to the tokio session
        TcpTransport::run(connection, socket, looping_interval_ms);
    }
}
