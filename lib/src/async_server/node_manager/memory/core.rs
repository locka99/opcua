use crate::server::address_space::types::AddressSpace;

use super::InMemoryNodeManagerImpl;

pub struct CoreNodeManager {}

impl InMemoryNodeManagerImpl for CoreNodeManager {
    fn build_nodes(address_space: &mut AddressSpace) {
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        crate::server::address_space::populate_address_space(address_space);
    }
}

impl CoreNodeManager {
    pub fn new() -> Self {
        Self {}
    }
}
