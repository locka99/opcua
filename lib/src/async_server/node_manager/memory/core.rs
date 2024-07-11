use std::time::Duration;

use async_trait::async_trait;
use hashbrown::HashMap;
use tokio::sync::OnceCell;

use crate::{
    async_server::{
        address_space::read_node_value,
        node_manager::{NodeManagersRef, RequestContext, ServerContext, SyncSampler},
        subscriptions::CreateMonitoredItem,
        ServerCapabilities,
    },
    server::{
        address_space::types::AddressSpace,
        prelude::{
            AccessRestrictionType, DataValue, IdType, Identifier, ObjectId, ReadValueId,
            ReferenceTypeId, StatusCode, TimestampsToReturn, VariableId, Variant,
        },
    },
    sync::RwLock,
};

use super::{InMemoryNodeManager, InMemoryNodeManagerImpl, NamespaceMetadata};

/// Node manager impl for the core namespace.
pub struct CoreNodeManagerImpl {
    sampler: SyncSampler,
    node_managers: OnceCell<NodeManagersRef>,
}

/// Node manager for the core namespace.
pub type CoreNodeManager = InMemoryNodeManager<CoreNodeManagerImpl>;

impl CoreNodeManager {
    pub fn new_core() -> Self {
        Self::new(CoreNodeManagerImpl::new())
    }
}

/*
The core node manager serves as an example for how you can create a simple
node manager based on the in-memory node manager.

In this case the data is largely static, so all we need to really
implement is Read, leaving the responsibility for notifying any subscriptions
of changes to these to the one doing the modifying.
*/

#[async_trait]
impl InMemoryNodeManagerImpl for CoreNodeManagerImpl {
    async fn build_nodes(&self, address_space: &mut AddressSpace, context: ServerContext) {
        crate::async_server::address_space::populate_address_space(address_space);
        self.add_aggregates(address_space, &context.info.capabilities);
        let interval = context
            .info
            .config
            .limits
            .subscriptions
            .min_sampling_interval_ms
            .floor() as u64;
        let sampler_interval = if interval > 0 { interval } else { 100 };
        self.sampler.run(
            Duration::from_millis(sampler_interval),
            context.subscriptions.clone(),
        );
        self.node_managers
            .set(context.node_managers.clone())
            .map_err(|_| ())
            .expect("Init called more than once");
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![NamespaceMetadata {
            is_namespace_subset: Some(false),
            // TODO: Should be possible to fill this
            namespace_publication_date: None,
            namespace_version: None,
            namespace_uri: "http://opcfoundation.org/UA/".to_owned(),
            static_node_id_types: Some(vec![IdType::Numeric]),
            namespace_index: 0,
            ..Default::default()
        }]
    }

    fn name(&self) -> &str {
        "core"
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
            .map(|n| {
                self.read_node_value(context, &address_space, n, max_age, timestamps_to_return)
            })
            .collect()
    }

    async fn create_value_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        let address_space = address_space.read();
        for node in items {
            let value = self.read_node_value(
                context,
                &address_space,
                node.item_to_monitor(),
                0.0,
                node.timestamps_to_return(),
            );
            if value.status() != StatusCode::BadAttributeIdInvalid {
                node.set_initial_value(value);
            }
            node.set_status(StatusCode::Good);
        }
    }
}

impl CoreNodeManagerImpl {
    pub fn new() -> Self {
        Self {
            sampler: SyncSampler::new(),
            node_managers: OnceCell::new(),
        }
    }

    fn read_node_value(
        &self,
        context: &RequestContext,
        address_space: &AddressSpace,
        node_to_read: &ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let mut result_value = DataValue::null();
        // Check that the read is permitted.
        let (node, attribute_id, index_range) =
            match address_space.validate_node_read(context, node_to_read) {
                Ok(n) => n,
                Err(e) => {
                    result_value.status = Some(e);
                    return result_value;
                }
            };
        // Try to read a special value, that is obtained from somewhere else.
        // A custom node manager might read this from some device, or get them
        // in some other way.

        // In this case, the values are largely read from configuration.
        if let Some(v) = self.read_server_value(context, node_to_read) {
            v
        } else {
            // If it can't be found, read it from the node hierarchy.
            read_node_value(
                node,
                attribute_id,
                index_range,
                context,
                node_to_read,
                max_age,
                timestamps_to_return,
            )
        }
    }

    fn read_server_value(&self, context: &RequestContext, node: &ReadValueId) -> Option<DataValue> {
        if node.node_id.namespace != 0 {
            return None;
        }
        let Identifier::Numeric(identifier) = node.node_id.identifier else {
            return None;
        };
        let Ok(var_id) = VariableId::try_from(identifier) else {
            return None;
        };

        let limits = &context.info.config.limits;
        let hist_cap = &context.info.capabilities.history;

        let v: Variant = match var_id {
            VariableId::Server_ServerCapabilities_MaxArrayLength => {
                (limits.max_array_length as u32).into()
            }
            VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints => {
                (limits.max_browse_continuation_points as u32).into()
            }
            VariableId::Server_ServerCapabilities_MaxByteStringLength => {
                (limits.max_byte_string_length as u32).into()
            }
            VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints => {
                (limits.max_history_continuation_points as u32).into()
            }
            VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints => {
                (limits.max_query_continuation_points as u32).into()
            }
            VariableId::Server_ServerCapabilities_MaxStringLength => {
                (limits.max_string_length as u32).into()
            }
            VariableId::Server_ServerCapabilities_MinSupportedSampleRate => {
                (limits.subscriptions.min_sampling_interval_ms as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall => {
                (limits.operational.max_monitored_items_per_call as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse => {
                (limits.operational.max_nodes_per_browse as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData => {
                (limits.operational.max_nodes_per_history_read_data as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents => {
                (limits.operational.max_nodes_per_history_read_events as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData => {
                (limits.operational.max_nodes_per_history_update as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents => {
                (limits.operational.max_nodes_per_history_update as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall => {
                (limits.operational.max_nodes_per_method_call as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement => {
                (limits.operational.max_nodes_per_node_management as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead => {
                (limits.operational.max_nodes_per_read as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes => {
                (limits.operational.max_nodes_per_register_nodes as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds => {
                (limits.operational.max_nodes_per_translate_browse_paths_to_node_ids as u32).into()
            }
            VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite => {
                (limits.operational.max_nodes_per_write as u32).into()
            }
            VariableId::Server_ServerCapabilities_ServerProfileArray => {
                context.info.capabilities.profiles.clone().into()
            }

            // History capabilities
            VariableId::HistoryServerCapabilities_AccessHistoryDataCapability => {
                hist_cap.access_history_data.into()
            }
            VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability => {
                hist_cap.access_history_events.into()
            }
            VariableId::HistoryServerCapabilities_DeleteAtTimeCapability => {
                hist_cap.delete_at_time.into()
            }
            VariableId::HistoryServerCapabilities_DeleteEventCapability => {
                hist_cap.delete_event.into()
            }
            VariableId::HistoryServerCapabilities_DeleteRawCapability => {
                hist_cap.delete_raw.into()
            }
            VariableId::HistoryServerCapabilities_InsertAnnotationCapability => {
                hist_cap.insert_annotation.into()
            }
            VariableId::HistoryServerCapabilities_InsertDataCapability => {
                hist_cap.insert_data.into()
            }
            VariableId::HistoryServerCapabilities_InsertEventCapability => {
                hist_cap.insert_event.into()
            }
            VariableId::HistoryServerCapabilities_MaxReturnDataValues => {
                hist_cap.max_return_data_values.into()
            }
            VariableId::HistoryServerCapabilities_MaxReturnEventValues => {
                hist_cap.max_return_event_values.into()
            }
            VariableId::HistoryServerCapabilities_ReplaceDataCapability => {
                hist_cap.replace_data.into()
            }
            VariableId::HistoryServerCapabilities_ReplaceEventCapability => {
                hist_cap.replace_event.into()
            }
            VariableId::HistoryServerCapabilities_ServerTimestampSupported => {
                hist_cap.server_timestamp_supported.into()
            }
            VariableId::HistoryServerCapabilities_UpdateDataCapability => {
                hist_cap.update_data.into()
            }
            VariableId::HistoryServerCapabilities_UpdateEventCapability => {
                hist_cap.update_event.into()
            }

            // Misc server status
            VariableId::Server_ServiceLevel => {
                context.info.service_level.load(std::sync::atomic::Ordering::Relaxed).into()
            }

            // Namespace metadata
            VariableId::OPCUANamespaceMetadata_IsNamespaceSubset => {
                false.into()
            }
            VariableId::OPCUANamespaceMetadata_DefaultAccessRestrictions => {
                AccessRestrictionType::None.bits().into()
            }
            VariableId::OPCUANamespaceMetadata_NamespaceUri => {
                "http://opcfoundation.org/UA/".to_owned().into()
            }
            VariableId::OPCUANamespaceMetadata_StaticNodeIdTypes => {
                vec![IdType::Numeric as u8].into()
            }

            VariableId::Server_NamespaceArray => {
                // This actually calls into other node managers to obtain the value, in fact
                // it calls into _this_ node manager as well.
                // Be careful to avoid holding exclusive locks in a way that causes a deadlock
                // when doing this. Here we hold a read lock on the address space,
                // but in this case it doesn't matter.
                let Some(node_managers) = self.node_managers.get().map(|n| n.iter()) else {
                    return None;
                };
                let nss: HashMap<_, _> = node_managers.flat_map(|n| n.namespaces_for_user(context)).map(|ns| (ns.namespace_index, ns.namespace_uri)).collect();
                // Make sure that holes are filled with empty strings, so that the
                // namespace array actually has correct indices.
                let Some(&max) = nss.keys().max() else {
                    return None;
                };
                let namespaces: Vec<_> = (0..(max + 1)).map(|idx| nss.get(&idx).cloned().unwrap_or_default()).collect();
                namespaces.into()
            }

            _ => return None,
        };

        Some(DataValue {
            value: Some(v),
            status: Some(StatusCode::Good),
            source_timestamp: Some(**context.info.start_time.load()),
            server_timestamp: Some(**context.info.start_time.load()),
            ..Default::default()
        })
    }

    fn add_aggregates(&self, address_space: &mut AddressSpace, capabilities: &ServerCapabilities) {
        for aggregate in &capabilities.history.aggregates {
            address_space.insert_reference(
                &ObjectId::HistoryServerCapabilities_AggregateFunctions.into(),
                &aggregate,
                ReferenceTypeId::Organizes,
            )
        }
    }
}
