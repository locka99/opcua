use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::sync::OnceCell;

use crate::{
    server::{
        address_space::{read_node_value, AddressSpace, NodeBase, NodeType},
        node_manager::{
            MethodCall, MonitoredItemRef, MonitoredItemUpdateRef, NodeManagersRef,
            ParsedReadValueId, RequestContext, ServerContext, SyncSampler, TypeTree, WriteNode,
        },
        CreateMonitoredItem,
    },
    sync::RwLock,
    types::{
        AttributeId, DataValue, MonitoringMode, NodeId, NumericRange, StatusCode,
        TimestampsToReturn, Variant,
    },
};

use super::{InMemoryNodeManager, InMemoryNodeManagerImpl, NamespaceMetadata};

pub type SimpleNodeManager = InMemoryNodeManager<SimpleNodeManagerImpl>;

impl SimpleNodeManager {
    pub fn new_simple(
        namespace: NamespaceMetadata,
        name: &str,
    ) -> InMemoryNodeManager<SimpleNodeManagerImpl> {
        InMemoryNodeManager::new(SimpleNodeManagerImpl::new(namespace, name))
    }
}

type WriteCB = Arc<dyn Fn(DataValue, NumericRange) -> StatusCode + Send + Sync + 'static>;
type ReadCB = Arc<
    dyn Fn(NumericRange, TimestampsToReturn, f64) -> Result<DataValue, StatusCode>
        + Send
        + Sync
        + 'static,
>;
type MethodCB = Arc<dyn Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static>;

/// Node manager designed to deal with simple, entirely in-memory, synchronous OPC-UA servers.
///
/// Use this if
///
///  - Your node hierarchy is known and small enough to fit in memory.
///  - No read, write, or method call operations are async or particularly time consuming.
///  - and you don't need to be able to write attributes other than `Value`.
pub struct SimpleNodeManagerImpl {
    write_cbs: RwLock<HashMap<NodeId, WriteCB>>,
    read_cbs: RwLock<HashMap<NodeId, ReadCB>>,
    method_cbs: RwLock<HashMap<NodeId, MethodCB>>,
    namespace: NamespaceMetadata,
    node_managers: OnceCell<NodeManagersRef>,
    name: String,
    samplers: SyncSampler,
}

#[async_trait]
impl InMemoryNodeManagerImpl for SimpleNodeManagerImpl {
    async fn build_nodes(&self, _address_space: &mut AddressSpace, context: ServerContext) {
        self.node_managers
            .set(context.node_managers)
            .map_err(|_| ())
            .expect("Node manager initialized more than once");
        self.samplers.run(
            Duration::from_millis(
                context
                    .info
                    .config
                    .limits
                    .subscriptions
                    .min_sampling_interval_ms as u64,
            ),
            context.subscriptions.clone(),
        );
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![self.namespace.clone()]
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn read_values(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&ParsedReadValueId],
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> Vec<DataValue> {
        let address_space = address_space.read();
        let cbs = trace_read_lock!(self.read_cbs);

        nodes
            .iter()
            .map(|n| {
                self.read_node_value(
                    &*cbs,
                    context,
                    &address_space,
                    n,
                    max_age,
                    timestamps_to_return,
                )
            })
            .collect()
    }

    async fn create_value_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        let cbs = trace_read_lock!(self.read_cbs);

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
            let rf = &node.item_to_monitor().node_id;

            if let Some(cb) = cbs.get(rf).cloned() {
                let tss = node.timestamps_to_return();
                let index_range = node.item_to_monitor().index_range.clone();

                self.samplers.add_sampler(
                    node.item_to_monitor().node_id.clone(),
                    AttributeId::Value,
                    move || {
                        Some(
                            // TODO: Make everything take index range by reference.
                            match cb(index_range.clone(), tss, 0.0) {
                                Err(e) => DataValue {
                                    status: Some(e),
                                    ..Default::default()
                                },
                                Ok(v) => v,
                            },
                        )
                    },
                    node.monitoring_mode(),
                    node.handle(),
                    Duration::from_millis(node.sampling_interval() as u64),
                )
            }
        }
    }

    async fn modify_monitored_items(
        &self,
        _context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
        for it in items {
            self.samplers.update_sampler(
                it.node_id(),
                it.attribute(),
                it.handle(),
                Duration::from_millis(it.update().revised_sampling_interval as u64),
            );
        }
    }

    async fn set_monitoring_mode(
        &self,
        _context: &RequestContext,
        mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
        for it in items {
            self.samplers
                .set_sampler_mode(it.node_id(), it.attribute(), it.handle(), mode);
        }
    }

    async fn delete_monitored_items(&self, _context: &RequestContext, items: &[&MonitoredItemRef]) {
        for it in items {
            self.samplers
                .remove_sampler(it.node_id(), it.attribute(), it.handle());
        }
    }

    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        let mut address_space = trace_write_lock!(address_space);
        let type_tree = trace_read_lock!(context.type_tree);
        let cbs = trace_read_lock!(self.write_cbs);

        for write in nodes_to_write {
            self.write_node_value(&*cbs, context, &mut address_space, &type_tree, *write);
        }

        Ok(())
    }

    async fn call(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        let cbs = trace_read_lock!(self.method_cbs);
        for method in methods_to_call {
            if let Some(cb) = cbs.get(method.method_id()) {
                match cb(method.arguments()) {
                    Ok(r) => {
                        method.set_outputs(r);
                        method.set_status(StatusCode::Good);
                    }
                    Err(e) => method.set_status(e),
                }
            }
        }

        Ok(())
    }
}

impl SimpleNodeManagerImpl {
    pub fn new(namespace: NamespaceMetadata, name: &str) -> Self {
        Self {
            write_cbs: Default::default(),
            read_cbs: Default::default(),
            method_cbs: Default::default(),
            namespace,
            name: name.to_owned(),
            node_managers: Default::default(),
            samplers: SyncSampler::new(),
        }
    }

    fn read_node_value(
        &self,
        cbs: &HashMap<NodeId, ReadCB>,
        context: &RequestContext,
        address_space: &AddressSpace,
        node_to_read: &ParsedReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let mut result_value = DataValue::null();
        // Check that the read is permitted.
        let node = match address_space.validate_node_read(context, node_to_read) {
            Ok(n) => n,
            Err(e) => {
                result_value.status = Some(e);
                return result_value;
            }
        };

        // If there is a callback registered, call that, otherwise read it from the node hierarchy.
        if let Some(cb) = cbs.get(&node_to_read.node_id) {
            match cb(
                node_to_read.index_range.clone(),
                timestamps_to_return,
                max_age,
            ) {
                Err(e) => {
                    return DataValue {
                        status: Some(e),
                        ..Default::default()
                    }
                }
                Ok(v) => v,
            }
        } else {
            // If it can't be found, read it from the node hierarchy.
            read_node_value(node, context, node_to_read, max_age, timestamps_to_return)
        }
    }

    fn write_node_value(
        &self,
        cbs: &HashMap<NodeId, WriteCB>,
        context: &RequestContext,
        address_space: &mut AddressSpace,
        type_tree: &TypeTree,
        write: &mut WriteNode,
    ) {
        let node = match address_space.validate_node_write(context, write.value(), &type_tree) {
            Ok(v) => v,
            Err(e) => {
                write.set_status(e);
                return;
            }
        };

        let (NodeType::Variable(var), AttributeId::Value) = (node, write.value().attribute_id)
        else {
            write.set_status(StatusCode::BadNotWritable);
            return;
        };

        let Some(cb) = cbs.get(var.node_id()) else {
            write.set_status(StatusCode::BadNotWritable);
            return;
        };

        write.set_status(cb(
            write.value().value.clone(),
            write.value().index_range.clone(),
        ));
    }

    pub fn add_write_callback(
        &self,
        id: NodeId,
        cb: impl Fn(DataValue, NumericRange) -> StatusCode + Send + Sync + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.write_cbs);
        cbs.insert(id, Arc::new(cb));
    }

    pub fn add_read_callback(
        &self,
        id: NodeId,
        cb: impl Fn(NumericRange, TimestampsToReturn, f64) -> Result<DataValue, StatusCode>
            + Send
            + Sync
            + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.read_cbs);
        cbs.insert(id, Arc::new(cb));
    }

    pub fn add_method_callback(
        &self,
        id: NodeId,
        cb: impl Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.method_cbs);
        cbs.insert(id, Arc::new(cb));
    }
}
