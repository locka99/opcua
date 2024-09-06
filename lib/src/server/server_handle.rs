use std::sync::{atomic::AtomicU8, Arc};

use tokio_util::sync::CancellationToken;

use crate::{
    sync::RwLock,
    types::{AttributeId, DataValue, ServerState, VariableId},
};

use super::{
    info::ServerInfo,
    node_manager::{NodeManagers, TypeTree},
    session::manager::SessionManager,
    SubscriptionCache,
};

/// Reference to a server instance containing tools to modify the server
/// while it is running.
#[derive(Clone)]
pub struct ServerHandle {
    info: Arc<ServerInfo>,
    service_level: Arc<AtomicU8>,
    subscriptions: Arc<SubscriptionCache>,
    node_managers: NodeManagers,
    session_manager: Arc<RwLock<SessionManager>>,
    type_tree: Arc<RwLock<TypeTree>>,
    token: CancellationToken,
}

impl ServerHandle {
    pub(crate) fn new(
        info: Arc<ServerInfo>,
        service_level: Arc<AtomicU8>,
        subscriptions: Arc<SubscriptionCache>,
        node_managers: NodeManagers,
        session_manager: Arc<RwLock<SessionManager>>,
        type_tree: Arc<RwLock<TypeTree>>,
        token: CancellationToken,
    ) -> Self {
        Self {
            info,
            service_level,
            subscriptions,
            node_managers,
            session_manager,
            type_tree,
            token,
        }
    }

    /// Get a reference to the ServerInfo, containing configuration and other shared server data.
    pub fn info(&self) -> &Arc<ServerInfo> {
        &self.info
    }

    /// Get a reference to the subscription cache.
    pub fn subscriptions(&self) -> &Arc<SubscriptionCache> {
        &self.subscriptions
    }

    /// Set the service level, properly notifying subscribed clients of the change.
    pub fn set_service_level(&self, sl: u8) {
        self.service_level
            .store(sl, std::sync::atomic::Ordering::Relaxed);
        self.subscriptions.notify_data_change(
            [(
                DataValue::new_now(sl),
                &VariableId::Server_ServiceLevel.into(),
                AttributeId::Value,
            )]
            .into_iter(),
        );
    }

    /// Get a reference to the node managers on the server.
    pub fn node_managers(&self) -> &NodeManagers {
        &self.node_managers
    }

    /// Get a reference to the session manager, containing all currently active sessions.
    pub fn session_manager(&self) -> &RwLock<SessionManager> {
        &self.session_manager
    }

    /// Get a reference to the type tree, containing shared information about types in the server.
    pub fn type_tree(&self) -> &RwLock<TypeTree> {
        &self.type_tree
    }

    /// Set the server state. Note that this does not do anything beyond just setting
    /// the state and notifying clients.
    pub fn set_server_state(&self, state: ServerState) {
        self.info.set_state(state, &self.subscriptions);
    }

    /// Get the cancellation token.
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    /// Signal the server to stop.
    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn get_namespace_index(&self, namespace: &str) -> Option<u16> {
        self.type_tree.read().namespaces().get_index(namespace)
    }
}
