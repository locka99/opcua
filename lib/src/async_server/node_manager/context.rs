use std::sync::Arc;

use crate::{
    async_server::{
        authenticator::{AuthManager, UserToken},
        info::ServerInfo,
        session::instance::Session,
        SubscriptionCache,
    },
    server::prelude::{BrowseDescriptionResultMask, NodeId},
    sync::RwLock,
};

use super::{
    view::{ExternalReferenceRequest, NodeMetadata},
    NodeManagers, TypeTree,
};

pub struct RequestContext {
    pub session: Arc<RwLock<Session>>,
    pub session_id: u32,
    pub authenticator: Arc<dyn AuthManager>,
    pub token: UserToken,
    pub current_node_manager_index: usize,
    pub type_tree: Arc<RwLock<TypeTree>>,
    pub subscriptions: Arc<SubscriptionCache>,
    pub info: Arc<ServerInfo>,
}

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
