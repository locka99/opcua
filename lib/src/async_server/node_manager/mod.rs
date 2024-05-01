use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    server::prelude::{
        DeleteAtTimeDetails, DeleteEventDetails, DeleteRawModifiedDetails, NodeId,
        ReadAtTimeDetails, ReadEventDetails, ReadProcessedDetails, ReadRawModifiedDetails,
        StatusCode, TimestampsToReturn, UpdateDataDetails, UpdateEventDetails,
        UpdateStructureDataDetails, WriteValue,
    },
    sync::RwLock,
};

mod context;
mod history;
pub mod memory;
mod read;
mod type_tree;
mod view;

use self::view::ExternalReferenceRequest;

pub use {
    context::RequestContext,
    history::{HistoryNode, HistoryResult},
    read::ReadNode,
    type_tree::TypeTree,
    view::{BrowseContinuationPoint, BrowseNode, BrowsePathItem, RegisterNodeItem},
};

pub(crate) use context::resolve_external_references;
pub(crate) use view::ExternalReferencesContPoint;

/// Trait for a type that implements logic for responding to requests.
/// Implementations of this trait may make external calls for node information,
/// or do other complex tasks.
///
/// Note that each request is passed to every node manager concurrently.
/// It is up to each node manager to avoid responding to requests for nodes
/// managed by a different node manager.
///
/// Requests are spawned on the tokio thread pool. Avoid making blocking calls in
/// methods on this trait. If you need to do blocking work use `tokio::spawn_blocking`,
/// though you should use async IO as much as possible.
///
/// For a simpler interface see InMemoryNodeManager, use this trait directly
/// if you need to control how all node information is stored.
#[allow(unused_variables)]
#[async_trait]
pub trait NodeManager {
    /// Return whether this node manager owns the given node, this is used for
    /// propagating service-level errors.
    ///
    /// If a service returns an error, all nodes it owns will get that error,
    /// even if this is a cross node-manager request like Browse.
    fn owns_node(&self, id: &NodeId) -> bool;

    /// Perform any necessary loading of nodes, should populate the type tree if
    /// needed.
    async fn init(&self, type_tree: &mut TypeTree);

    /// Resolve a list of references given by a different node manager.
    async fn resolve_external_references(
        &self,
        context: &RequestContext,
        items: &mut [&mut ExternalReferenceRequest],
    ) {
    }

    // ATTRIBUTES
    /// Execute the Read service. This should populate the `results` vector as needed.
    /// If this node manager does not manage a requested node, it should not do anything about it.
    async fn read(
        &self,
        context: &RequestContext,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        nodes_to_read: &mut [ReadNode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Perform the history read raw modified service. This should write results
    /// to the `nodes` list of type either `HistoryData` or `HistoryModifiedData`
    async fn history_read_raw_modified(
        &self,
        context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [HistoryNode],
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    async fn history_read_processed(
        &self,
        context: &RequestContext,
        details: &ReadProcessedDetails,
        nodes: &mut [HistoryNode],
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    async fn history_read_at_time(
        &self,
        context: &RequestContext,
        details: &ReadAtTimeDetails,
        nodes: &mut [HistoryNode],
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read events service. This should write results
    /// to the `nodes` list of type `HistoryEvent`.
    async fn history_read_events(
        &self,
        context: &RequestContext,
        details: &ReadEventDetails,
        nodes: &mut [HistoryNode],
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the write service. This should write results
    /// to the `results` list. The default result is `BadNodeIdUnknown`
    async fn write(
        &self,
        context: &RequestContext,
        nodes_to_write: &[WriteValue],
        results: &mut [StatusCode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Perform the history update data service.
    async fn history_update_data(
        &self,
        context: &RequestContext,
        _details: &UpdateDataDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history update structure data service.
    async fn history_update_structure_data(
        &self,
        context: &RequestContext,
        details: &UpdateStructureDataDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history update data events service.
    async fn history_update_events(
        &self,
        context: &RequestContext,
        _details: &UpdateEventDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history delete raw modified service.
    async fn history_delete_raw_modified(
        &self,
        context: &RequestContext,
        details: &DeleteRawModifiedDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history delete at time service.
    async fn history_delete_at_time(
        &self,
        context: &RequestContext,
        details: &DeleteAtTimeDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history delete events service.
    async fn history_delete_events(
        &self,
        context: &RequestContext,
        _details: &DeleteEventDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    // VIEW
    /// Perform the Browse or BrowseNext service.
    async fn browse(
        &self,
        context: &RequestContext,
        nodes_to_browse: &mut [BrowseNode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Perform the translate browse paths to node IDs service.
    async fn translate_browse_paths_to_node_ids(
        &self,
        context: &RequestContext,
        nodes: &mut [BrowsePathItem],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Perform the register nodes service. The default behavior for this service is to
    /// do nothing and pretend the nodes were registered.
    /// This should only affect nodes managed by the active node manager.
    async fn register_nodes(
        &self,
        context: &RequestContext,
        nodes: &mut [RegisterNodeItem],
    ) -> Result<(), StatusCode> {
        // Most servers don't actually do anything with node registration, it is reasonable
        // to just pretend the nodes are registered.
        for node in nodes {
            if self.owns_node(node.node_id()) {
                node.set_registered(true);
            }
        }

        Ok(())
    }

    /// Perform the unregister nodes service. The default behavior for this service is to
    /// do nothing.
    async fn unregister_nodes(
        &self,
        context: &RequestContext,
        _nodes: &[NodeId],
    ) -> Result<(), StatusCode> {
        // Again, just do nothing
        Ok(())
    }
}
