use crate::{
    async_server::node_manager::{
        view::{ExternalReferenceRequest, NodeMetadata},
        NodeManagerCollection, RequestContext,
    },
    server::prelude::{BrowseDescriptionResultMask, NodeId},
};

pub async fn get_node_metadata(
    context: &RequestContext,
    node_managers: &impl NodeManagerCollection,
    ids: &[NodeId],
) -> Vec<Option<NodeMetadata>> {
    let mut reqs: Vec<_> = ids
        .iter()
        .map(|n| ExternalReferenceRequest::new(n, BrowseDescriptionResultMask::all()))
        .collect();
    for mgr in node_managers.iter_node_managers() {
        let mut owned: Vec<_> = reqs
            .iter_mut()
            .filter(|n| mgr.owns_node(n.node_id()))
            .collect();

        mgr.resolve_external_references(context, &mut owned).await;
    }

    reqs.into_iter().map(|r| r.into_inner()).collect()
}
