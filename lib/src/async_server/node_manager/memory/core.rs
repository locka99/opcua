use std::sync::Arc;

use async_trait::async_trait;

use crate::{async_server::SubscriptionCache, server::address_space::types::AddressSpace};

use super::InMemoryNodeManagerImpl;

pub struct CoreNodeManager {}

#[async_trait]
impl InMemoryNodeManagerImpl for CoreNodeManager {
    async fn build_nodes(
        &self,
        address_space: &mut AddressSpace,
        _subscriptions: Arc<SubscriptionCache>,
    ) {
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        crate::server::address_space::populate_address_space(address_space);
    }

    fn name(&self) -> &str {
        "core"
    }
}

impl CoreNodeManager {
    pub fn new() -> Self {
        Self {}
    }
}
