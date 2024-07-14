use async_trait::async_trait;

use crate::{
    server::{
        address_space::AddressSpace,
        node_manager::{
            AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem, HistoryNode,
            HistoryUpdateNode, MethodCall, MonitoredItemRef, MonitoredItemUpdateRef,
            RegisterNodeItem, RequestContext, ServerContext, WriteNode,
        },
        subscriptions::CreateMonitoredItem,
    },
    sync::RwLock,
    types::{
        DataValue, ExpandedNodeId, MonitoringMode, NodeId, ReadAnnotationDataDetails,
        ReadAtTimeDetails, ReadEventDetails, ReadProcessedDetails, ReadRawModifiedDetails,
        ReadValueId, StatusCode, TimestampsToReturn,
    },
};

use super::NamespaceMetadata;

#[async_trait]
#[allow(unused)]
pub trait InMemoryNodeManagerImpl: Send + Sync + 'static {
    /// Populate the address space.
    async fn build_nodes(&self, address_space: &mut AddressSpace, context: ServerContext);

    /// Name of this node manager, for debug purposes.
    fn name(&self) -> &str;

    fn namespaces(&self) -> Vec<NamespaceMetadata>;

    /// Return whether this node should handle requests to create a node
    /// for the given parent ID. This is only called if no new node ID is
    /// requested, otherwise owns_node is called on the requested node ID.
    fn owns_server_events(&self) -> bool {
        false
    }

    fn handle_new_node(&self, parent_id: &ExpandedNodeId) -> bool {
        false
    }

    async fn register_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &mut [&mut RegisterNodeItem],
    ) -> Result<(), StatusCode> {
        for node in nodes {
            node.set_registered(true);
        }

        Ok(())
    }

    async fn read_values(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&ReadValueId],
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> Vec<DataValue> {
        let address_space = address_space.read();
        nodes
            .iter()
            .map(|n| address_space.read(context, n, max_age, timestamps_to_return))
            .collect()
    }

    /// Create monitored items for the Value attribute, as needed.
    /// This should, at the very least, read the current value of the nodes,
    /// and set appropriate status on the monitored item request, see
    /// default implementation.
    ///
    /// It may also begin sampling as given by the monitored item request.
    async fn create_value_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        let to_read: Vec<_> = items.iter().map(|r| r.item_to_monitor()).collect();
        let values = self
            .read_values(
                context,
                address_space,
                &to_read,
                0.0,
                TimestampsToReturn::Both,
            )
            .await;

        for (value, node) in values.into_iter().zip(items.into_iter()) {
            if value.status() != StatusCode::BadAttributeIdInvalid {
                node.set_initial_value(value);
            }
            node.set_status(StatusCode::Good);
        }
    }

    /// Create monitored items for events.
    ///
    /// This does not need to do anything.
    async fn create_event_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        // This is just a no-op by default.
    }

    /// Handle the SetMonitoringMode request, to pause or resume sampling.
    ///
    /// This will only get monitored items for events or value.
    async fn set_monitoring_mode(
        &self,
        context: &RequestContext,
        mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
    }

    /// Handle modification of monitored items, this may adjust
    /// sampling intervals or filters, and require action to update background
    /// processes.
    async fn modify_monitored_items(
        &self,
        context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
    }

    /// Handle deletion of monitored items.
    async fn delete_monitored_items(&self, context: &RequestContext, items: &[&MonitoredItemRef]) {}

    async fn unregister_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&NodeId],
    ) -> Result<(), StatusCode> {
        // Again, just do nothing
        Ok(())
    }

    /// Perform the history read raw modified service. This should write results
    /// to the `nodes` list of type either `HistoryData` or `HistoryModifiedData`
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_raw_modified(
        &self,
        context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_processed(
        &self,
        context: &RequestContext,
        details: &ReadProcessedDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_at_time(
        &self,
        context: &RequestContext,
        details: &ReadAtTimeDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read events service. This should write results
    /// to the `nodes` list of type `HistoryEvent`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_events(
        &self,
        context: &RequestContext,
        details: &ReadEventDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read annotations data service. This should write
    /// results to the `nodes` list of type `Annotation`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_annotations(
        &self,
        context: &RequestContext,
        details: &ReadAnnotationDataDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the HistoryUpdate service. This should write result
    /// status codes to the `nodes` list as appropriate.
    ///
    /// Nodes are verified to be writable before this is called.
    async fn history_update(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut &mut HistoryUpdateNode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the write service. This should write results
    /// to the `nodes_to_write` list. The default result is `BadNodeIdUnknown`
    ///
    /// Writing is left almost entirely up to the node manager impl. If you do write
    /// values you should call `context.subscriptions.notify_data_change` to trigger
    /// any monitored items subscribed to the updated values.
    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Call a list of methods.
    ///
    /// The methods have already had their arguments verified to have valid length
    /// and the method is verified to exist on the given object. This should try
    /// to execute the methods, and set the result.
    async fn call(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Add a list of nodes.
    ///
    /// This should create the nodes, or set a failed status as appropriate.
    /// If a node was created, the status should be set to Good.
    async fn add_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_add: &mut [&mut AddNodeItem],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Add a list of references.
    ///
    /// This will be given all references where the source _or_
    /// target belongs to this node manager. A reference is
    /// considered successfully added if either source_status
    /// or target_status are Good.
    ///
    /// If you want to explicitly set the reference to failed,
    /// set both source and target status. Note that it may
    /// already have been added in a different node manager, you are
    /// responsible for any cleanup if you do this.
    async fn add_references(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        references_to_add: &mut [&mut AddReferenceItem],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Delete a list of nodes.
    ///
    /// This will be given all nodes that belong to this node manager.
    ///
    /// Typically, you also want to implement `delete_node_references` if
    /// there are other node managers that support deletes.
    async fn delete_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_delete: &mut [&mut DeleteNodeItem],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Delete references for the given list of nodes.
    /// The node manager should respect `delete_target_references`.
    ///
    /// This is not allowed to fail, you should make it impossible to delete
    /// nodes with immutable references.
    async fn delete_node_references(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        to_delete: &[&DeleteNodeItem],
    ) {
    }

    /// Delete a list of references.
    ///
    /// This will be given all references where the source _or_
    /// target belongs to this node manager. A reference is
    /// considered successfully added if either source_status
    /// or target_status are Good.
    ///
    /// If you want to explicitly set the reference to failed,
    /// set both source and target status. Note that it may
    /// already have been deleted in a different node manager, you are
    /// responsible for any cleanup if you do this.
    async fn delete_references(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        references_to_delete: &mut [&mut DeleteReferenceItem],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }
}
