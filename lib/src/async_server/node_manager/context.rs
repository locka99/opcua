use std::sync::Arc;

use crate::{
    async_server::{
        authenticator::{AuthManager, UserToken},
        session::{instance::Session, message_handler::NodeManagers},
    },
    server::prelude::{
        BrowseDescriptionResultMask, ExpandedNodeId, LocalizedText, NodeClass, NodeId,
        QualifiedName,
    },
    sync::RwLock,
};

pub struct RequestContext {
    pub session: Arc<RwLock<Session>>,
    pub authenticator: Arc<dyn AuthManager>,
    pub token: UserToken,
    pub node_managers: NodeManagers,
    pub current_node_manager_index: usize,
}

pub struct ExternalReferenceRequest {
    node_id: NodeId,
    result_mask: BrowseDescriptionResultMask,
    item: Option<NodeMetadata>,
}

impl ExternalReferenceRequest {
    pub fn new(reference: &NodeId, result_mask: BrowseDescriptionResultMask) -> Self {
        Self {
            node_id: reference.clone(),
            result_mask,
            item: None,
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn set(&mut self, reference: NodeMetadata) {
        self.item = Some(reference);
    }

    pub fn result_mask(&self) -> BrowseDescriptionResultMask {
        self.result_mask
    }
}

pub struct NodeMetadata {
    pub node_id: ExpandedNodeId,
    pub type_definition: ExpandedNodeId,
    pub browse_name: QualifiedName,
    pub display_name: LocalizedText,
    pub node_class: NodeClass,
}

impl RequestContext {
    /// Resolve a list of references. Note that this will call into node managers,
    /// be careful about using this if the implementation in other node managers is expensive.
    pub async fn resolve_external_references(
        &self,
        references: &[(&NodeId, BrowseDescriptionResultMask)],
    ) -> Vec<Option<NodeMetadata>> {
        let mut res: Vec<_> = references
            .into_iter()
            .map(|(n, mask)| ExternalReferenceRequest::new(n, *mask))
            .collect();

        for nm in self.node_managers.iter() {
            let mut items: Vec<_> = res
                .iter_mut()
                .filter(|r| nm.owns_node(&r.node_id))
                .collect();

            nm.resolve_external_references(&mut items).await;
        }

        res.into_iter().map(|r| r.item).collect()
    }
}
