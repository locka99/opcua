use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicU16, AtomicU8},
        Arc,
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use futures::{future::Either, never::Never, stream::FuturesUnordered, FutureExt, StreamExt};
use tokio::{
    net::TcpListener,
    sync::Notify,
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use crate::{
    core::{config::Config, handle::AtomicHandle},
    crypto::CertificateStore,
    server::{node_manager::ServerContext, session::controller::SessionController},
    sync::RwLock,
    types::{DateTime, LocalizedText, ServerState, UAString},
};

use super::{
    authenticator::DefaultAuthenticator,
    builder::ServerBuilder,
    config::ServerConfig,
    discovery::periodic_discovery_server_registration,
    info::ServerInfo,
    node_manager::{NodeManagers, NodeManagersRef, TypeTree},
    server_handle::ServerHandle,
    session::{controller::ControllerCommand, manager::SessionManager},
    subscriptions::SubscriptionCache,
    ServerCapabilities,
};

struct ConnectionInfo {
    command_send: tokio::sync::mpsc::Sender<ControllerCommand>,
}

/// The server struct. This is consumed when run, so you will typically not hold onto this for longer
/// periods of time.
pub struct Server {
    /// Certificate store
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Session manager
    session_manager: Arc<RwLock<SessionManager>>,
    /// Open connections.
    connections: FuturesUnordered<JoinHandle<u32>>,
    /// Map to metadata about each open connection
    connection_map: HashMap<u32, ConnectionInfo>,
    /// Server configuration, fixed after the server is started
    config: Arc<ServerConfig>,
    /// Context for use by connections to access general server state.
    info: Arc<ServerInfo>,
    /// Subscription cache, global because subscriptions outlive sessions.
    subscriptions: Arc<SubscriptionCache>,
    /// List of node managers
    node_managers: NodeManagers,
    /// Cancellation token
    token: CancellationToken,
    /// Notify that is woken up if a new session is added to the session manager.
    session_notify: Arc<Notify>,
}

impl Server {
    pub(crate) fn new_from_builder(builder: ServerBuilder) -> Result<(Self, ServerHandle), String> {
        if !builder.config.is_valid() {
            return Err("Configuration is invalid".to_owned());
        }

        let mut config = builder.config;

        let application_name = config.application_name.clone();
        let application_uri = UAString::from(&config.application_uri);
        let product_uri = UAString::from(&config.product_uri);
        let servers = vec![config.application_uri.clone()];
        /* let base_endpoint = format!(
            "opc.tcp://{}:{}",
            config.tcp_config.host, config.tcp_config.port
        ); */

        // let diagnostics = Arc::new(RwLock::new(ServerDiagnostics::default()));
        let send_buffer_size = config.limits.send_buffer_size;
        let receive_buffer_size = config.limits.receive_buffer_size;

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
            warn!("Server is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.");
        }

        config.read_x509_thumbprints();

        if config.certificate_validation.trust_client_certs {
            info!("Server has chosen to auto trust client certificates. You do not want to do this in production code.");
            certificate_store.set_trust_unknown_certs(true);
        }
        certificate_store.set_check_time(config.certificate_validation.check_time);

        let config = Arc::new(config);

        let service_level = Arc::new(AtomicU8::new(255));

        let type_tree = Arc::new(RwLock::new(TypeTree::new()));

        let info = ServerInfo {
            authenticator: builder
                .authenticator
                .unwrap_or_else(|| Arc::new(DefaultAuthenticator::new(config.user_tokens.clone()))),
            application_uri,
            product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from(application_name),
            },
            start_time: ArcSwap::new(Arc::new(crate::types::DateTime::now())),
            servers,
            config: config.clone(),
            server_certificate,
            server_pkey,
            operational_limits: config.limits.operational.clone(),
            state: ArcSwap::new(Arc::new(ServerState::Shutdown)),
            send_buffer_size,
            receive_buffer_size,
            type_tree: type_tree.clone(),
            subscription_id_handle: AtomicHandle::new(1),
            monitored_item_id_handle: AtomicHandle::new(1),
            secure_channel_id_handle: Arc::new(AtomicHandle::new(1)),
            capabilities: ServerCapabilities::default(),
            service_level: service_level.clone(),
            port: AtomicU16::new(0),
        };

        let certificate_store = Arc::new(RwLock::new(certificate_store));

        let info = Arc::new(info);
        let subscriptions = Arc::new(SubscriptionCache::new(config.limits.subscriptions));

        let node_managers_ref = NodeManagersRef::new_empty();
        let context = ServerContext {
            node_managers: node_managers_ref.clone(),
            subscriptions: subscriptions.clone(),
            info: info.clone(),
            authenticator: info.authenticator.clone(),
            type_tree: type_tree.clone(),
        };

        let mut final_node_managers = Vec::new();
        for nm_builder in builder.node_managers {
            final_node_managers.push(nm_builder.build(context.clone()));
        }

        let node_managers = NodeManagers::new(final_node_managers);
        node_managers_ref.init_from_node_managers(node_managers.clone());

        let session_notify = Arc::new(Notify::new());
        let session_manager = Arc::new(RwLock::new(SessionManager::new(
            info.clone(),
            session_notify.clone(),
        )));

        let handle = ServerHandle::new(
            info.clone(),
            service_level,
            subscriptions.clone(),
            node_managers.clone(),
            session_manager.clone(),
            type_tree.clone(),
            builder.token.clone(),
        );
        Ok((
            Self {
                certificate_store,
                session_manager,
                connections: FuturesUnordered::new(),
                connection_map: HashMap::new(),
                subscriptions,
                config,
                info,
                node_managers,
                token: builder.token,
                session_notify,
            },
            handle,
        ))
    }

    /// Get a reference to the SubscriptionCache containing all subscriptions on the server.
    pub fn subscriptions(&self) -> Arc<SubscriptionCache> {
        self.subscriptions.clone()
    }

    async fn initialize_node_managers(&self, context: &ServerContext) -> Result<(), String> {
        info!("Initializing node managers");
        {
            if self.node_managers.is_empty() {
                return Err("No node managers defined, server is invalid".to_string());
            }

            let mut type_tree = trace_write_lock!(self.info.type_tree);

            for mgr in self.node_managers.iter() {
                mgr.init(&mut *type_tree, context.clone()).await;
            }
        }
        Ok(())
    }

    async fn run_discovery_server_registration(info: Arc<ServerInfo>) -> Never {
        let registered_server = info.registered_server();
        let Some(discovery_server_url) = info.config.discovery_server_url.as_ref() else {
            loop {
                futures::future::pending::<()>().await;
            }
        };
        periodic_discovery_server_registration(
            discovery_server_url,
            registered_server,
            info.config.pki_dir.clone(),
            Duration::from_secs(5 * 60),
        )
        .await
    }

    /// Run the server using a given TCP listener.
    /// Note that the configured TCP endpoint is still used to create the endpoint
    /// descriptions, you must properly set `host` and `port` even when using this.
    ///
    /// This is useful for testing, as you can bind a `TcpListener` to port `0` auto-assign
    /// a port.
    pub async fn run_with(mut self, listener: TcpListener) -> Result<(), String> {
        let context = ServerContext {
            node_managers: self.node_managers.as_weak(),
            subscriptions: self.subscriptions.clone(),
            info: self.info.clone(),
            authenticator: self.info.authenticator.clone(),
            type_tree: self.info.type_tree.clone(),
        };

        self.initialize_node_managers(&context).await?;

        self.info
            .set_state(ServerState::Running, &self.subscriptions);
        self.info.start_time.store(Arc::new(DateTime::now()));

        let addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to bind socket: {e:?}"))?;
        info!("Now listening for connections on {addr}");

        self.info
            .port
            .store(addr.port(), std::sync::atomic::Ordering::Relaxed);

        self.log_endpoint_info();

        let mut connection_counter = 0;

        loop {
            let conn_fut = if self.connections.is_empty() {
                if self.token.is_cancelled() {
                    break;
                }
                Either::Left(futures::future::pending::<Option<Result<u32, JoinError>>>())
            } else {
                Either::Right(self.connections.next())
            };

            tokio::select! {
                conn_res = conn_fut => {
                    match conn_res.unwrap() {
                        Ok(id) => {
                            info!("Connection {} terminated", id);
                            self.connection_map.remove(&id);
                        },
                        Err(e) => error!("Connection panic! {e}")
                    }
                }
                _ = Self::run_subscription_ticks(self.config.subscription_poll_interval_ms, &context) => {}
                _ = Self::run_discovery_server_registration(self.info.clone()) => {}
                _ = Self::run_session_expiry(&self.session_manager, &self.session_notify) => {}
                rs = listener.accept() => {
                    match rs {
                        Ok((socket, addr)) => {
                            info!("Accept new connection from {addr} ({connection_counter})");
                            let conn = SessionController::new(
                                socket,
                                self.session_manager.clone(),
                                self.certificate_store.clone(),
                                self.info.clone(),
                                self.node_managers.clone(),
                                self.subscriptions.clone()
                            );
                            let (send, recv) = tokio::sync::mpsc::channel(5);
                            let handle = tokio::spawn(conn.run(recv).map(move |_| connection_counter));
                            self.connections.push(handle);
                            self.connection_map.insert(connection_counter, ConnectionInfo {
                                command_send: send
                            });
                            connection_counter += 1;
                        }
                        Err(e) => {
                            error!("Failed to accept client connection: {:?}", e);
                        }
                    }
                }
                _ = self.token.cancelled() => {
                    for conn in self.connection_map.values() {
                        let _ = conn.command_send.send(ControllerCommand::Close).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the server. The provided `token` can be used to stop the server gracefully.
    pub async fn run(self) -> Result<(), String> {
        let addr = self.get_socket_address();

        let Some(addr) = addr else {
            error!("Cannot resolve server address, check server configuration");
            return Err("Cannot resolve server address, check server configuration".to_owned());
        };

        info!("Try to bind address at {addr}");
        let listener = match TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Failed to bind socket: {:?}", e);
                return Err(format!("Failed to bind socket: {:?}", e));
            }
        };

        self.run_with(listener).await
    }

    async fn run_subscription_ticks(interval: u64, context: &ServerContext) -> Never {
        if interval == 0 {
            futures::future::pending().await
        } else {
            let context = context.clone();
            let mut tick = tokio::time::interval(Duration::from_millis(interval));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;

                context.subscriptions.periodic_tick(&context).await;
            }
        }
    }

    async fn run_session_expiry(sessions: &RwLock<SessionManager>, notify: &Notify) -> Never {
        loop {
            let ((expiry, expired), notified) = {
                let session_lck = trace_read_lock!(sessions);
                // Make sure to create the notified future while we still hold the lock.
                (session_lck.check_session_expiry(), notify.notified())
            };
            if !expired.is_empty() {
                let mut session_lck = trace_write_lock!(sessions);
                for id in expired {
                    session_lck.expire_session(&id);
                }
            }
            tokio::select! {
                _ = tokio::time::sleep_until(expiry.into()) => {}
                _ = notified => {}
            }
        }
    }

    /// Log information about the endpoints on this server
    fn log_endpoint_info(&self) {
        info!("OPC UA Server: {}", self.info.application_name);
        info!("Base url: {}", self.info.base_endpoint());
        info!("Supported endpoints:");
        for (id, endpoint) in &self.config.endpoints {
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
        // Resolve this host / port to an address (or not)
        let address = format!(
            "{}:{}",
            self.config.tcp_config.host, self.config.tcp_config.port
        );
        if let Ok(mut addrs_iter) = address.to_socket_addrs() {
            addrs_iter.next()
        } else {
            None
        }
    }
}
