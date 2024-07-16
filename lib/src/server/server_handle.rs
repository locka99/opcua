use std::sync::{atomic::AtomicU8, Arc};

use crate::{
    sync::RwLock,
    types::{AttributeId, DataValue, VariableId},
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
}

impl ServerHandle {
    pub(crate) fn new(
        info: Arc<ServerInfo>,
        service_level: Arc<AtomicU8>,
        subscriptions: Arc<SubscriptionCache>,
        node_managers: NodeManagers,
        session_manager: Arc<RwLock<SessionManager>>,
        type_tree: Arc<RwLock<TypeTree>>,
    ) -> Self {
        Self {
            info,
            service_level,
            subscriptions,
            node_managers,
            session_manager,
            type_tree,
        }
    }

    pub fn info(&self) -> &Arc<ServerInfo> {
        &self.info
    }

    pub fn subscriptions(&self) -> &Arc<SubscriptionCache> {
        &self.subscriptions
    }

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

    pub fn node_managers(&self) -> &NodeManagers {
        &self.node_managers
    }

    pub fn session_manager(&self) -> &RwLock<SessionManager> {
        &self.session_manager
    }

    pub fn type_tree(&self) -> &RwLock<TypeTree> {
        &self.type_tree
    }
}