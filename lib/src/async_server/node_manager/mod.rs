use async_trait::async_trait;

use crate::server::prelude::{
    DataValue, DeleteAtTimeDetails, DeleteEventDetails, DeleteRawModifiedDetails, NodeId,
    ReadAtTimeDetails, ReadEventDetails, ReadProcessedDetails, ReadRawModifiedDetails, ReadRequest,
    StatusCode, TimestampsToReturn, UpdateDataDetails, UpdateEventDetails,
    UpdateStructureDataDetails, WriteValue,
};

use self::history::HistoryNode;

mod history;

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
#[async_trait]
pub trait NodeManager {
    /// Return whether this node manager owns the given node, this is used for
    /// propagating service-level errors.
    ///
    /// If a service returns an error, all nodes it owns will get that error,
    /// even if this is a cross node-manager request like Browse.
    fn owns_node(&self, id: &NodeId) -> bool;

    // ATTRIBUTES
    /// Execute the Read service. This should populate the `results` vector as needed.
    /// If this node manager does not manage a requested node, it should not do anything about it.
    async fn read(
        &self,
        _request: &ReadRequest,
        _results: &mut [DataValue],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Perform the history read raw modified service. This should write results
    /// to the `nodes` list of type either `HistoryData` or `HistoryModifiedData`
    async fn history_read_raw_modified(
        &self,
        _details: &ReadRawModifiedDetails,
        _nodes: &mut [HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    async fn history_read_processed(
        &self,
        _details: &ReadProcessedDetails,
        _nodes: &mut [HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    async fn history_read_at_time(
        &self,
        _details: &ReadAtTimeDetails,
        _nodes: &mut [HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read events service. This should write results
    /// to the `nodes` list of type `HistoryEvent`.
    async fn history_read_events(
        &self,
        _details: &ReadEventDetails,
        _nodes: &mut [HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the write service. This should write results
    /// to the `results` list. The default result is `BadNodeIdUnknown`
    async fn write(
        &self,
        _nodes_to_write: &[WriteValue],
        _results: &mut [StatusCode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Perform the history update data service.
    async fn history_update_data(&self, _details: &UpdateDataDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history update structure data service.
    async fn history_update_structure_data(
        &self,
        _details: &UpdateStructureDataDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history update data events service.
    async fn history_update_events(&self, _details: &UpdateEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history delete raw modified service.
    async fn history_delete_raw_modified(
        &self,
        _details: &DeleteRawModifiedDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history delete at time service.
    async fn history_delete_at_time(
        &self,
        _details: &DeleteAtTimeDetails,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history delete events service.
    async fn history_delete_events(&self, _details: &DeleteEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    // VIEW
    
    
}
