use async_trait::async_trait;

use crate::{
    async_server::node_manager::{RequestContext, ServerContext},
    server::{
        address_space::types::AddressSpace,
        prelude::{
            DataValue, Identifier, ReadValueId, StatusCode, TimestampsToReturn, VariableId, Variant,
        },
    },
    sync::RwLock,
};

use super::InMemoryNodeManagerImpl;

pub struct CoreNodeManager {}

#[async_trait]
impl InMemoryNodeManagerImpl for CoreNodeManager {
    async fn build_nodes(&self, address_space: &mut AddressSpace, _context: ServerContext) {
        crate::server::address_space::populate_address_space(address_space);
    }

    fn namespaces(&self) -> Vec<(&str, u16)> {
        vec![("http://opcfoundation.org/UA/", 0)]
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
                let mut result_value = DataValue::null();
                let (node, attribute_id, index_range) =
                    match address_space.validate_node_read(context, n) {
                        Ok(n) => n,
                        Err(e) => {
                            result_value.status = Some(e);
                            return result_value;
                        }
                    };
                if let Some(v) = self.read_server_value(context, n) {
                    v
                } else {
                    address_space.read_node_value(
                        node,
                        attribute_id,
                        index_range,
                        context,
                        n,
                        max_age,
                        timestamps_to_return,
                    )
                }
            })
            .collect()
    }
}

impl CoreNodeManager {
    pub fn new() -> Self {
        Self {}
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

        let v: Variant = match var_id {
            // VariableId::Server_ServerCapabilities_LocaleIdArray
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
            VariableId::Server_ServiceLevel => {
                255u8.into()
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
}
