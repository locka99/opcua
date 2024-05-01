use std::sync::Arc;

use crate::{
    async_server::{
        authenticator::{AuthManager, UserToken},
        session::{instance::Session, message_handler::NodeManagers},
    },
    server::prelude::{BrowseDescriptionResultMask, NodeId},
    sync::RwLock,
};

use super::{
    view::{ExternalReferenceRequest, NodeMetadata},
    TypeTree,
};

pub struct RequestContext {
    pub session: Arc<RwLock<Session>>,
    pub authenticator: Arc<dyn AuthManager>,
    pub token: UserToken,
    pub current_node_manager_index: usize,
    pub type_tree: Arc<RwLock<TypeTree>>,
}

impl RequestContext {}

/// Resolve a list of references.
pub(crate) async fn resolve_external_references(
    context: &RequestContext,
    node_managers: &NodeManagers,
    references: &[(&NodeId, BrowseDescriptionResultMask)],
) -> Vec<Option<NodeMetadata>> {
    let mut res: Vec<_> = references
        .into_iter()
        .map(|(n, mask)| ExternalReferenceRequest::new(n, *mask))
        .collect();

    for nm in node_managers.iter() {
        let mut items: Vec<_> = res
            .iter_mut()
            .filter(|r| nm.owns_node(r.node_id()))
            .collect();

        nm.resolve_external_references(context, &mut items).await;
    }

    res.into_iter().map(|r| r.into_inner()).collect()
}
