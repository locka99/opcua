use std::{collections::HashMap, sync::atomic::AtomicU32};

use async_trait::async_trait;
use opcua::{
    server::{
        address_space::{
            new_node_from_attributes, AddressSpace, HasNodeId, NodeType, ReferenceDirection,
        },
        node_manager::{
            get_node_metadata,
            memory::{InMemoryNodeManager, InMemoryNodeManagerImpl, NamespaceMetadata},
            AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem, HistoryNode,
            HistoryUpdateNode, MethodCall, MonitoredItemRef, MonitoredItemUpdateRef,
            NodeManagersRef, RequestContext, ServerContext, TypeTree, TypeTreeNode, WriteNode,
        },
        ContinuationPoint, CreateMonitoredItem,
    },
    sync::{Mutex, RwLock},
    trace_read_lock, trace_write_lock,
    types::{
        AttributeId, DataValue, DateTime, ExpandedNodeId, MonitoringMode, NodeClass, NodeId,
        PerformUpdateType, QualifiedName, ReadRawModifiedDetails, ReadValueId, ReferenceTypeId,
        StatusCode, TimestampsToReturn, Variant,
    },
};
use tokio::sync::OnceCell;

#[allow(unused)]
pub type TestNodeManager = InMemoryNodeManager<TestNodeManagerImpl>;

#[derive(Default, Debug)]
pub struct HistoryData {
    // Must be ordered chronologically.
    values: Vec<DataValue>,
}

struct HistoryContinuationPoint {
    index: usize,
}

pub struct TestNodeManagerImpl {
    // In practice you would never store history data in memory, and you would not want
    // a single global lock on all history.
    history_data: RwLock<HashMap<NodeId, HistoryData>>,
    call_info: Mutex<CallInfo>,
    method_cbs: Mutex<
        HashMap<
            NodeId,
            Box<dyn FnMut(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static>,
        >,
    >,
    node_id_generator: AtomicU32,
    namespace_index: u16,
    node_managers: OnceCell<NodeManagersRef>,
}

/// Information about calls made to the node manager impl, for verifying in tests.
#[derive(Default)]
pub struct CallInfo {
    pub value_monitored_items: Vec<NodeId>,
    pub read_values: Vec<NodeId>,
    pub register_nodes: Vec<NodeId>,
    pub set_monitoring_mode: Vec<NodeId>,
    pub modify_monitored_items: Vec<NodeId>,
    pub event_monitored_items: Vec<NodeId>,
    pub delete_monitored_items: Vec<NodeId>,
    pub unregister_nodes: Vec<NodeId>,
    pub history_read_raw_modified: Vec<NodeId>,
    pub history_update: Vec<NodeId>,
    pub write: Vec<(NodeId, AttributeId)>,
    pub call: Vec<NodeId>,
    pub add_nodes: Vec<String>,
    pub add_references: Vec<(NodeId, NodeId, NodeId)>,
    pub delete_nodes: Vec<NodeId>,
    pub delete_references: Vec<(NodeId, NodeId, NodeId)>,
}

#[async_trait]
impl InMemoryNodeManagerImpl for TestNodeManagerImpl {
    async fn build_nodes(&self, _address_space: &mut AddressSpace, context: ServerContext) {
        self.node_managers
            .set(context.node_managers)
            .map_err(|_| ())
            .expect("Node manager initialized more than once");
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![NamespaceMetadata {
            is_namespace_subset: Some(false),
            namespace_uri: "urn:rustopcuatestserver".to_owned(),
            namespace_index: self.namespace_index,
            ..Default::default()
        }]
    }

    fn name(&self) -> &str {
        "test"
    }

    fn handle_new_node(&self, parent_id: &ExpandedNodeId) -> bool {
        // Let this node manager handle all new nodes without a specified node id.
        parent_id.server_index == 0
    }

    async fn history_read_raw_modified(
        &self,
        _context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut &mut HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for node in nodes.iter() {
                call_info
                    .history_read_raw_modified
                    .push(node.node_id().clone());
            }
        }
        self.history_read_raw_modified(details, nodes);
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
        {
            let mut call_info = self.call_info.lock();
            for node in nodes.iter() {
                call_info.read_values.push(node.node_id.clone());
            }
        }

        let address_space = address_space.read();
        nodes
            .iter()
            .map(|n| address_space.read(context, n, max_age, timestamps_to_return))
            .collect()
    }

    async fn create_value_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        {
            let mut call_info = self.call_info.lock();
            for node in items.iter() {
                call_info
                    .value_monitored_items
                    .push(node.item_to_monitor().node_id.clone());
            }
        }
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

    async fn create_event_monitored_items(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        let mut call_info = self.call_info.lock();
        for node in items.iter() {
            call_info
                .event_monitored_items
                .push(node.item_to_monitor().node_id.clone());
        }
    }

    async fn set_monitoring_mode(
        &self,
        _context: &RequestContext,
        _mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
        let mut call_info = self.call_info.lock();
        for it in items.iter() {
            call_info.event_monitored_items.push(it.node_id().clone());
        }
    }

    async fn modify_monitored_items(
        &self,
        _context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
        let mut call_info = self.call_info.lock();
        for it in items.iter() {
            call_info.modify_monitored_items.push(it.node_id().clone());
        }
    }

    async fn delete_monitored_items(&self, _context: &RequestContext, items: &[&MonitoredItemRef]) {
        let mut call_info = self.call_info.lock();
        for it in items.iter() {
            call_info.delete_monitored_items.push(it.node_id().clone());
        }
    }

    async fn unregister_nodes(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        nodes: &[&NodeId],
    ) -> Result<(), StatusCode> {
        let mut call_info = self.call_info.lock();
        for id in nodes {
            call_info.unregister_nodes.push((*id).clone());
        }
        Ok(())
    }

    async fn history_update(
        &self,
        _context: &RequestContext,
        nodes: &mut [&mut &mut HistoryUpdateNode],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for node in nodes.iter() {
                call_info.history_update.push(match node.details() {
                    opcua::server::node_manager::HistoryUpdateDetails::UpdateData(d) => {
                        d.node_id.clone()
                    }
                    opcua::server::node_manager::HistoryUpdateDetails::UpdateStructureData(d) => {
                        d.node_id.clone()
                    }
                    opcua::server::node_manager::HistoryUpdateDetails::UpdateEvent(d) => {
                        d.node_id.clone()
                    }
                    opcua::server::node_manager::HistoryUpdateDetails::DeleteRawModified(d) => {
                        d.node_id.clone()
                    }
                    opcua::server::node_manager::HistoryUpdateDetails::DeleteAtTime(d) => {
                        d.node_id.clone()
                    }
                    opcua::server::node_manager::HistoryUpdateDetails::DeleteEvent(d) => {
                        d.node_id.clone()
                    }
                });
            }
        }

        for node in nodes.into_iter() {
            self.history_update_node(node)?;
        }

        Ok(())
    }

    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for node in nodes_to_write.iter() {
                call_info.write.push((
                    node.value().node_id.clone(),
                    AttributeId::from_u32(node.value().attribute_id)
                        .unwrap_or(AttributeId::DisplayName),
                ));
            }
        }
        let mut address_space = trace_write_lock!(address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for write in nodes_to_write {
            let (node, attribute_id, index_range) =
                match address_space.validate_node_write(context, write.value(), &type_tree) {
                    Ok(v) => v,
                    Err(e) => {
                        write.set_status(e);
                        continue;
                    }
                };

            if matches!(attribute_id, AttributeId::Value)
                && node.node_class() == NodeClass::Variable
            {
                let NodeType::Variable(var) = node else {
                    write.set_status(StatusCode::BadAttributeIdInvalid);
                    continue;
                };
                if let Err(e) = var.set_value(
                    index_range,
                    write.value().value.value.clone().unwrap_or(Variant::Empty),
                ) {
                    write.set_status(e);
                    continue;
                }

                if var.historizing() {
                    let mut history_data = trace_write_lock!(self.history_data);
                    let values = history_data
                        .entry(write.value().node_id.clone())
                        .or_default();
                    values.values.push(var.value(
                        TimestampsToReturn::Both,
                        opcua::types::NumericRange::None,
                        &QualifiedName::null(),
                        0.0,
                    ));
                }
            } else {
                if let Err(e) = node.as_mut_node().set_attribute(
                    attribute_id,
                    write.value().value.value.clone().unwrap_or(Variant::Empty),
                ) {
                    write.set_status(e);
                    continue;
                }
            }

            write.set_status(StatusCode::Good);

            // This is a little lazy, ideally avoid calling this method in a loop, instead create an iterator
            // over values.
            context.subscriptions.notify_data_change(
                [(
                    write.value().value.clone(),
                    &write.value().node_id,
                    attribute_id,
                )]
                .into_iter(),
            );
        }

        Ok(())
    }

    async fn call(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for m in methods_to_call.iter() {
                call_info.call.push(m.method_id().clone());
            }
        }

        let mut cbs = self.method_cbs.lock();
        for method in methods_to_call {
            let Some(cb) = cbs.get_mut(method.method_id()) else {
                method.set_status(StatusCode::BadMethodInvalid);
                continue;
            };
            let res = (*cb)(method.arguments());
            match res {
                Ok(r) => {
                    method.set_outputs(r);
                    method.set_status(StatusCode::Good);
                }
                Err(e) => method.set_status(e),
            }
        }

        Ok(())
    }

    async fn add_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_add: &mut [&mut AddNodeItem],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for m in nodes_to_add.iter() {
                call_info.add_nodes.push(m.browse_name().name.to_string());
            }
        }
        let parent_ids: Vec<_> = nodes_to_add
            .iter()
            .map(|n| n.parent_node_id().node_id.clone())
            .collect();
        let parent_nodes = get_node_metadata(
            context,
            self.node_managers
                .get()
                .expect("Node manager not initialized"),
            &parent_ids,
        )
        .await;

        let mut address_space = trace_write_lock!(address_space);
        let mut type_tree = trace_write_lock!(context.type_tree);
        for (idx, node) in nodes_to_add.into_iter().enumerate() {
            let node_id = if node.requested_new_node_id().is_null() {
                self.next_node_id()
            } else {
                node.requested_new_node_id().clone()
            };

            if address_space.node_exists(&node_id) {
                node.set_result(NodeId::null(), StatusCode::BadNodeIdExists);
                continue;
            }

            let Some(Some(parent)) = parent_nodes.get(idx) else {
                node.set_result(NodeId::null(), StatusCode::BadParentNodeIdInvalid);
                continue;
            };

            let mut refs = Vec::new();

            // Valid the type definition
            if !node.type_definition_id().is_null() {
                let Some(ty) = type_tree.get(&node.type_definition_id().node_id) else {
                    node.set_result(NodeId::null(), StatusCode::BadTypeDefinitionInvalid);
                    continue;
                };

                let valid = match node.node_class() {
                    opcua::types::NodeClass::Object => ty == NodeClass::ObjectType,
                    opcua::types::NodeClass::Variable => ty == NodeClass::VariableType,
                    _ => false,
                };

                if !valid {
                    node.set_result(NodeId::null(), StatusCode::BadTypeDefinitionInvalid);
                    continue;
                }

                let ref_type_id = ReferenceTypeId::HasTypeDefinition.into();

                refs.push((
                    &node.type_definition_id().node_id,
                    ref_type_id,
                    ReferenceDirection::Forward,
                ));
            }

            if !matches!(
                type_tree.get(node.reference_type_id()),
                Some(NodeClass::ReferenceType)
            ) {
                node.set_result(NodeId::null(), StatusCode::BadReferenceTypeIdInvalid);
                continue;
            }

            let is_type = matches!(
                node.node_class(),
                NodeClass::DataType
                    | NodeClass::ObjectType
                    | NodeClass::ReferenceType
                    | NodeClass::VariableType
            );

            // There are restrictions on where and how types may be added.
            if is_type {
                // The parent is a type of the same kind.
                let valid = type_tree
                    .get(&parent.node_id.node_id)
                    .is_some_and(|nc| nc == node.node_class());
                if !valid {
                    node.set_result(NodeId::null(), StatusCode::BadParentNodeIdInvalid);
                    continue;
                }
            }

            refs.push((
                &parent.node_id.node_id,
                node.reference_type_id().clone(),
                ReferenceDirection::Inverse,
            ));
            // Technically node managers are supposed to create all nodes required by the type definition here.
            // In practice this is very server dependent, no servers allow you to create arbitrary nodes.
            // For now we just ignore this requirement.

            let res = new_node_from_attributes(
                node_id.clone(),
                node.browse_name().clone(),
                node.node_class(),
                node.node_attributes().clone(),
            );

            match res {
                Ok(n) => self.insert_node_inner(
                    &mut address_space,
                    &mut type_tree,
                    n,
                    &parent.node_id.node_id,
                    refs,
                ),
                Err(e) => {
                    node.set_result(NodeId::null(), e);
                    continue;
                }
            }

            node.set_result(node_id, StatusCode::Good);
        }

        Ok(())
    }

    async fn add_references(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        references_to_add: &mut [&mut AddReferenceItem],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for m in references_to_add.iter() {
                call_info.add_references.push((
                    m.source_node_id().clone(),
                    m.reference_type_id().clone(),
                    m.target_node_id().node_id.clone(),
                ));
            }
        }
        let node_pairs: Vec<_> = references_to_add
            .iter()
            .flat_map(|n| {
                [
                    n.source_node_id().clone(),
                    n.target_node_id().node_id.clone(),
                ]
                .into_iter()
            })
            .collect();
        let nodes = get_node_metadata(
            context,
            self.node_managers
                .get()
                .expect("Node manager not initialized"),
            &node_pairs,
        )
        .await;
        let mut address_space = trace_write_lock!(address_space);
        let type_tree = trace_read_lock!(context.type_tree);
        for (idx, rf) in references_to_add.iter_mut().enumerate() {
            let Some(Some(start_node)) = nodes.get(idx * 2) else {
                if rf.source_node_id().namespace == self.namespace_index {
                    rf.set_source_result(StatusCode::BadSourceNodeIdInvalid);
                }
                continue;
            };
            let Some(Some(end_node)) = nodes.get(idx * 2 + 1) else {
                if rf.target_node_id().node_id.namespace == self.namespace_index {
                    rf.set_target_result(StatusCode::BadSourceNodeIdInvalid);
                }
                continue;
            };

            if !type_tree
                .get(rf.reference_type_id())
                .is_some_and(|nc| nc == NodeClass::ReferenceType)
            {
                if rf.source_node_id().namespace == self.namespace_index {
                    rf.set_source_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                if rf.target_node_id().node_id.namespace == self.namespace_index {
                    rf.set_target_result(StatusCode::BadReferenceTypeIdInvalid);
                }
            }

            // Most node managers will do a lot of validation here, to prevent cycles,
            // and make sure the reference is used correctly.
            if rf.is_forward() {
                address_space.insert_reference(
                    &start_node.node_id.node_id,
                    &end_node.node_id.node_id,
                    rf.reference_type_id(),
                )
            } else {
                address_space.insert_reference(
                    &end_node.node_id.node_id,
                    &start_node.node_id.node_id,
                    rf.reference_type_id(),
                )
            }

            if rf.source_node_id().namespace == self.namespace_index {
                rf.set_source_result(StatusCode::Good);
            }
            if rf.target_node_id().node_id.namespace == self.namespace_index {
                rf.set_target_result(StatusCode::Good);
            }
        }

        Ok(())
    }

    async fn delete_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_delete: &mut [&mut DeleteNodeItem],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for m in nodes_to_delete.iter() {
                call_info.delete_nodes.push(m.node_id().clone());
            }
        }

        let mut address_space = trace_write_lock!(address_space);
        let mut type_tree = trace_write_lock!(context.type_tree);
        for node in nodes_to_delete {
            if address_space
                .delete(node.node_id(), node.delete_target_references())
                .is_none()
            {
                node.set_result(StatusCode::BadNodeIdInvalid);
                continue;
            }

            type_tree.remove(node.node_id());
            node.set_result(StatusCode::Good);
        }

        Ok(())
    }

    async fn delete_references(
        &self,
        _context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        references_to_delete: &mut [&mut DeleteReferenceItem],
    ) -> Result<(), StatusCode> {
        {
            let mut call_info = self.call_info.lock();
            for m in references_to_delete.iter() {
                call_info.delete_references.push((
                    m.source_node_id().clone(),
                    m.reference_type_id().clone(),
                    m.target_node_id().node_id.clone(),
                ));
            }
        }

        let mut address_space = trace_write_lock!(address_space);
        for rf in references_to_delete {
            if !address_space.delete_reference(
                rf.source_node_id(),
                &rf.target_node_id().node_id,
                rf.reference_type_id(),
            ) {
                if rf.source_node_id().namespace == self.namespace_index {
                    rf.set_source_result(StatusCode::BadNodeIdInvalid);
                }
                if rf.target_node_id().node_id.namespace == self.namespace_index {
                    rf.set_target_result(StatusCode::BadNodeIdInvalid);
                }

                continue;
            }

            if rf.source_node_id().namespace == self.namespace_index {
                rf.set_source_result(StatusCode::Good);
            }
            if rf.target_node_id().node_id.namespace == self.namespace_index {
                rf.set_target_result(StatusCode::Good);
            }
        }

        Ok(())
    }
}

struct RawValue {
    value: Variant,
    timestamp: DateTime,
    status: StatusCode,
    orig_idx: usize,
}

impl TestNodeManagerImpl {
    #[allow(unused)]
    pub fn new(namespace_index: u16) -> Self {
        Self {
            history_data: Default::default(),
            call_info: Default::default(),
            method_cbs: Default::default(),
            node_id_generator: AtomicU32::new(1),
            namespace_index,
            node_managers: OnceCell::new(),
        }
    }

    #[allow(unused)]
    pub fn add_method_cb(
        &self,
        node_id: NodeId,
        cb: impl FnMut(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static,
    ) {
        let mut cbs = self.method_cbs.lock();
        cbs.insert(node_id, Box::new(cb));
    }

    fn history_read_raw_modified(
        &self,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut &mut HistoryNode],
    ) {
        let is_forward = match (details.start_time.is_null(), details.end_time.is_null()) {
            (true, true) => true,
            (true, false) => true,
            (false, true) => false,
            (false, false) => details.start_time < details.end_time,
        };

        let per_node = if details.num_values_per_node == 0 {
            10_000
        } else {
            details.num_values_per_node.min(10_000)
        } as usize;

        let history = trace_read_lock!(self.history_data);

        // At this point all nodes are validated to be history enabled
        for node in nodes {
            let Some(data) = history.get(node.node_id()) else {
                node.set_status(StatusCode::Good);
                node.set_result(&opcua::types::HistoryData {
                    data_values: Some(Vec::new()),
                });
                continue;
            };

            let start_time = details.start_time.checked_ticks();
            let end_time = details.end_time.checked_ticks();

            // Compute start index. If a continuation point is specified the server
            // is allowed to just ignore the `details` parameter. See 11.6.3
            let start_index = if let Some(cp) = node.continuation_point() {
                let Some(cp) = cp.get::<HistoryContinuationPoint>() else {
                    node.set_status(StatusCode::BadContinuationPointInvalid);
                    continue;
                };
                // Technically using a different set of details for a read with continuation point is invalid.
                // We _could_ validate this here, but we don't have to.
                cp.index
            } else {
                // Find where we should start reading.
                let time = if is_forward { start_time } else { end_time };
                let r = data.values.binary_search_by(|v| {
                    let ticks = v
                        .source_timestamp
                        .as_ref()
                        .map(|v| v.checked_ticks())
                        .unwrap_or_default();
                    ticks.cmp(&time)
                });
                // If OK, this is the index of the value that matched.
                // Otherwise it will be the index _after_, which is correct for reading forward.
                match r {
                    Ok(idx) => idx,
                    Err(idx) => idx,
                }
            };

            // Note the behavior here. For forward reads, start_index is the _next_ value we will read,
            // i.e. if the start_index is 1, we skip 1 node (index 0), and begin reading from node at index 1.
            // For backward reads, it's the index of the _last_ value read, or completely outside the history data.
            let values: Vec<_> = if is_forward {
                data.values
                    .iter()
                    .skip(start_index)
                    .take(per_node)
                    .cloned()
                    .collect()
            } else {
                data.values
                    .iter()
                    .rev()
                    .skip(data.values.len() - start_index)
                    .take(per_node)
                    .cloned()
                    .collect()
            };

            node.set_status(StatusCode::Good);
            node.set_result(&opcua::types::HistoryData {
                data_values: Some(values),
            });
            if is_forward {
                let end_index = start_index.saturating_add(per_node);
                if end_index < data.values.len() {
                    node.set_next_continuation_point(Some(ContinuationPoint::new(Box::new(
                        HistoryContinuationPoint { index: end_index },
                    ))));
                }
            } else {
                let end_index = start_index.saturating_sub(per_node);
                if end_index > 0 {
                    node.set_next_continuation_point(Some(ContinuationPoint::new(Box::new(
                        HistoryContinuationPoint { index: end_index },
                    ))));
                }
            };
        }
    }

    fn history_update_node(&self, node: &mut HistoryUpdateNode) -> Result<(), StatusCode> {
        let details = match node.details() {
            opcua::server::node_manager::HistoryUpdateDetails::UpdateData(d) => d,
            _ => return Err(StatusCode::BadHistoryOperationUnsupported),
        };

        if details.perform_insert_replace == PerformUpdateType::Remove {
            return Err(StatusCode::BadInvalidArgument);
        }

        let mut data = trace_write_lock!(self.history_data);

        let values = data.entry(details.node_id.clone()).or_default();

        let mode = details.perform_insert_replace;

        // This is a little fiddly, it would be easy in an actually indexed store,
        // but when keeping it just sequentially in memory it's a lot harder.

        // First, sort the values in ascending order.
        let ln = details
            .update_values
            .as_ref()
            .map(|v| v.len())
            .unwrap_or_default();

        let mut to_update = Vec::with_capacity(ln);
        let mut results = vec![StatusCode::Good; ln];

        for (idx, value) in details
            .update_values
            .clone()
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            if let Some(v) = value.source_timestamp {
                to_update.push(RawValue {
                    value: value.value.unwrap_or(Variant::Empty),
                    timestamp: v,
                    status: value.status.unwrap_or(StatusCode::Good),
                    orig_idx: idx,
                });
            } else {
                results[idx] = StatusCode::BadInvalidTimestamp;
            }
        }
        to_update.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let now = DateTime::now();
        let mut index = 0;
        for value in to_update {
            while index < values.values.len()
                && values.values[index].source_timestamp.as_ref().unwrap() < &value.timestamp
            {
                index += 1;
            }
            let data_value = DataValue {
                value: Some(value.value),
                status: Some(value.status),
                server_timestamp: Some(now),
                source_timestamp: Some(value.timestamp),
                ..Default::default()
            };

            if index < values.values.len()
                && values.values[index].source_timestamp.as_ref().unwrap() == &value.timestamp
            {
                if mode == PerformUpdateType::Insert {
                    results[value.orig_idx] = StatusCode::BadEntryExists;
                } else {
                    values.values.remove(index);
                    results[value.orig_idx] = StatusCode::GoodEntryReplaced;
                    values.values.insert(index, data_value);
                }
            } else {
                if mode == PerformUpdateType::Replace {
                    results[value.orig_idx] = StatusCode::BadNoEntryExists;
                } else {
                    results[value.orig_idx] = StatusCode::GoodEntryInserted;
                    values.values.insert(index, data_value);
                }
            }
        }

        node.set_operation_results(Some(results));
        node.set_status(StatusCode::Good);

        Ok(())
    }

    pub fn next_node_id(&self) -> NodeId {
        let val = self
            .node_id_generator
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        NodeId::new(self.namespace_index, val)
    }

    #[allow(unused)]
    pub fn add_history(&self, node_id: &NodeId, values: impl Iterator<Item = DataValue>) {
        let mut hist = trace_write_lock!(self.history_data);
        let data = hist.entry(node_id.clone()).or_default();

        data.values.extend(values);
    }

    #[allow(unused)]
    pub fn add_node<'a>(
        &self,
        address_space: &RwLock<AddressSpace>,
        type_tree: &RwLock<TypeTree>,
        node: NodeType,
        parent_id: &'a NodeId,
        reference_type_id: &'a NodeId,
        type_def: Option<&'a NodeId>,
        mut refs: Vec<(&'a NodeId, NodeId, ReferenceDirection)>,
    ) {
        if let Some(type_def) = type_def {
            refs.push((
                type_def,
                ReferenceTypeId::HasTypeDefinition.into(),
                ReferenceDirection::Forward,
            ));
        }
        refs.push((
            parent_id,
            reference_type_id.clone(),
            ReferenceDirection::Inverse,
        ));
        let mut address_space = trace_write_lock!(address_space);
        let mut type_tree = trace_write_lock!(type_tree);
        self.insert_node_inner(&mut address_space, &mut type_tree, node, parent_id, refs);
    }

    #[allow(unused)]
    pub fn add_references<'a>(
        &self,
        address_space: &RwLock<AddressSpace>,
        source: &'a NodeId,
        refs: Vec<(&'a NodeId, NodeId, ReferenceDirection)>,
    ) {
        let mut address_space = trace_write_lock!(address_space);
        for (target, ty, dir) in refs {
            if matches!(dir, ReferenceDirection::Forward) {
                address_space.insert_reference(&source, target, ty);
            } else {
                address_space.insert_reference(target, &source, ty);
            }
        }
    }

    fn insert_node_inner(
        &self,
        address_space: &mut AddressSpace,
        type_tree: &mut TypeTree,
        node: NodeType,
        parent_id: &NodeId,
        refs: Vec<(&NodeId, NodeId, ReferenceDirection)>,
    ) {
        let node_id = node.node_id().clone();
        let node_class = node.node_class();
        let browse_name = node.as_node().browse_name().clone();

        address_space.insert(node, None::<&[(_, &NodeId, _)]>);
        for (target, ty, dir) in refs {
            if matches!(dir, ReferenceDirection::Forward) {
                address_space.insert_reference(&node_id, target, ty);
            } else {
                address_space.insert_reference(target, &node_id, ty);
            }
        }

        let is_type = matches!(
            node_class,
            NodeClass::DataType
                | NodeClass::ObjectType
                | NodeClass::ReferenceType
                | NodeClass::VariableType
        );

        // If the node is a new node in the type hierarchy, add it there.
        if is_type {
            type_tree.add_type_node(&node_id, &parent_id, node_class);
        } else if let Some(type_node) = type_tree.get_node(&parent_id) {
            let (browse_path, ty) = match type_node {
                TypeTreeNode::Type(_) => (vec![browse_name.clone()], parent_id.clone()),
                TypeTreeNode::Property(p) => (
                    p.path
                        .iter()
                        .cloned()
                        .chain([browse_name.clone()].into_iter())
                        .collect(),
                    p.type_id.clone(),
                ),
            };
            let path_ref: Vec<_> = browse_path.iter().collect();
            type_tree.add_type_property(&node_id, &ty, &path_ref, node_class);
        }
    }
}
