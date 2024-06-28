use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{atomic::AtomicU8, Arc},
    time::Duration,
};

use arc_swap::ArcSwap;
use futures::{future::Either, stream::FuturesUnordered, FutureExt, StreamExt};
use tokio::{
    net::TcpListener,
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use crate::{
    async_server::{node_manager::ServerContext, session::controller::SessionController},
    core::handle::AtomicHandle,
    server::prelude::{CertificateStore, Config, DateTime, LocalizedText, ServerState, UAString},
    sync::RwLock,
};

use super::{
    authenticator::DefaultAuthenticator,
    config::ServerConfig,
    info::ServerInfo,
    node_manager::{NodeManager, NodeManagers, TypeTree},
    server_handle::ServerHandle,
    session::{controller::ControllerCommand, manager::SessionManager},
    subscriptions::SubscriptionCache,
    ServerCapabilities,
};

struct ConnectionInfo {
    command_send: tokio::sync::mpsc::Sender<ControllerCommand>,
}

pub struct ServerCore {
    // Certificate store
    certificate_store: Arc<RwLock<CertificateStore>>,
    // Session manager
    session_manager: Arc<RwLock<SessionManager>>,
    // Open connections.
    connections: FuturesUnordered<JoinHandle<u32>>,
    // Map to metadata about each open connection
    connection_map: HashMap<u32, ConnectionInfo>,
    // Server configuration, fixed after the server is started
    config: Arc<ServerConfig>,
    // Context for use by connections to access general server state.
    info: Arc<ServerInfo>,
    // Subscription cache, global because subscriptions outlive sessions.
    subscriptions: Arc<SubscriptionCache>,
    // List of node managers
    node_managers: NodeManagers,
}

impl ServerCore {
    pub fn new(
        mut config: ServerConfig,
        node_managers: Vec<Arc<dyn NodeManager + Send + Sync + 'static>>,
    ) -> Result<(Self, ServerHandle), String> {
        if !config.is_valid() {
            return Err("Configuration is invalid".to_string());
        }

        let application_name = config.application_name.clone();
        let application_uri = UAString::from(&config.application_uri);
        let product_uri = UAString::from(&config.product_uri);
        let servers = vec![config.application_uri.clone()];
        let base_endpoint = format!(
            "opc.tcp://{}:{}",
            config.tcp_config.host, config.tcp_config.port
        );

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

        let info = ServerInfo {
            authenticator: Arc::new(DefaultAuthenticator::new(config.user_tokens.clone())),
            application_uri,
            product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from(application_name),
            },
            base_endpoint,
            start_time: ArcSwap::new(Arc::new(crate::types::DateTime::now())),
            servers,
            config: config.clone(),
            server_certificate,
            server_pkey,
            operational_limits: config.limits.operational.clone(),
            state: ArcSwap::new(Arc::new(ServerState::Shutdown)),
            send_buffer_size,
            receive_buffer_size,
            type_tree: Arc::new(RwLock::new(TypeTree::new())),
            subscription_id_handle: AtomicHandle::new(1),
            monitored_item_id_handle: AtomicHandle::new(1),
            capabilities: ServerCapabilities::default(),
            service_level: service_level.clone(),
        };

        let certificate_store = Arc::new(RwLock::new(certificate_store));

        let info = Arc::new(info);
        let subscriptions = Arc::new(SubscriptionCache::new(config.limits.subscriptions));
        let node_managers = NodeManagers::new(node_managers);
        let session_manager = Arc::new(RwLock::new(SessionManager::new(info.clone())));
        let handle = ServerHandle::new(
            info.clone(),
            service_level,
            subscriptions.clone(),
            node_managers.clone(),
            session_manager.clone(),
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
            },
            handle,
        ))
    }

    pub fn subscriptions(&self) -> Arc<SubscriptionCache> {
        self.subscriptions.clone()
    }

    pub async fn run(mut self, token: CancellationToken) -> Result<(), String> {
        self.log_endpoint_info();
        info!("Initializing node managers");
        {
            if self.node_managers.is_empty() {
                return Err("No node managers defined, server is invalid".to_string());
            }

            let mut type_tree = trace_write_lock!(self.info.type_tree);
            let context = ServerContext {
                node_managers: self.node_managers.as_weak(),
                subscriptions: self.subscriptions.clone(),
                info: self.info.clone(),
            };
            for mgr in self.node_managers.iter() {
                mgr.init(&mut *type_tree, context.clone()).await;
            }
        }

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

        self.info.set_state(ServerState::Running);
        self.info.start_time.store(Arc::new(DateTime::now()));

        // TODO: Start discovery registration, start checking for session timeouts, etc.

        info!("Now listening for connections on {addr}");

        let mut connection_counter = 0;

        loop {
            let conn_fut = if self.connections.is_empty() {
                if token.is_cancelled() {
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
                _ = Self::run_subscription_ticks(self.config.subscription_poll_interval_ms, self.subscriptions.clone()) => {
                    unreachable!()
                }
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
                _ = token.cancelled() => {
                    for conn in self.connection_map.values() {
                        let _ = conn.command_send.send(ControllerCommand::Close).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_subscription_ticks(interval: u64, subscriptions: Arc<SubscriptionCache>) -> Never {
        if interval == 0 {
            futures::future::pending().await
        } else {
            let mut tick = tokio::time::interval(Duration::from_millis(interval));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;

                subscriptions.periodic_tick();
            }
        }
    }

    /// Log information about the endpoints on this server
    fn log_endpoint_info(&self) {
        info!("OPC UA Server: {}", self.info.application_name);
        info!("Base url: {}", self.info.base_endpoint);
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

enum Never {}
