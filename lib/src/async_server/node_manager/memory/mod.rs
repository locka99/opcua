use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    server::prelude::{
        AddressSpace, AttributeId, BrowseDescriptionResultMask, DataTypeId, DataValue,
        ExpandedNodeId, NodeClass, NodeId, NodeType, NumericRange, ObjectTypeId, QualifiedName,
        ReadValueId, ReferenceDescription, ReferenceTypeId, StatusCode, TimestampsToReturn,
        VariableTypeId,
    },
    sync::RwLock,
};

use super::{BrowseNode, DefaultTypeTree, NodeManager, ReadNode};

#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

pub struct InMemoryNodeManager {
    address_space: Arc<RwLock<AddressSpace>>,
    type_tree: Arc<RwLock<DefaultTypeTree>>,
    namespaces: HashMap<u16, String>,
}

impl InMemoryNodeManager {
    // TODO: Too specific
    pub fn new() -> Self {
        let address_space = AddressSpace::new();
        let mut type_tree = DefaultTypeTree::new();
        let mut queue: VecDeque<NodeId> = VecDeque::with_capacity(20);
        queue.push_back(ObjectTypeId::BaseObjectType.into());
        queue.push_back(DataTypeId::BaseDataType.into());
        queue.push_back(VariableTypeId::BaseVariableType.into());
        queue.push_back(ReferenceTypeId::References.into());
        while let Some(node) = queue.pop_front() {
            for reference in address_space
                .find_references(&node, Some((ReferenceTypeId::HasSubtype, false)))
                .into_iter()
                .flatten()
            {
                let Some(node_type) = address_space.find(&reference.target_node) else {
                    continue;
                };
                let node_class = node_type.node_class();
                type_tree.add_node(&reference.target_node, &node, node_class);
                queue.push_back(reference.target_node);
            }
        }

        Self {
            type_tree: Arc::new(RwLock::new(type_tree)),
            namespaces: address_space
                .namespaces()
                .iter()
                .enumerate()
                .map(|(n, val)| (n as u16, val.to_owned()))
                .collect(),
            address_space: Arc::new(RwLock::new(address_space)),
        }
    }

    fn browse_node(
        address_space: &AddressSpace,
        type_tree: &DefaultTypeTree,
        node: &mut BrowseNode,
    ) {
        let reference_type_id = if node.reference_type_id().is_null() {
            None
        } else if let Ok(reference_type_id) = node.reference_type_id().as_reference_type_id() {
            Some((reference_type_id, node.include_subtypes()))
        } else {
            None
        };

        let (references, inverse_ref_idx) = address_space.find_references_by_direction(
            &node.node_id(),
            node.browse_direction(),
            reference_type_id,
        );

        let mut cont_point = BrowseContinuationPoint::default();

        for (idx, reference) in references.into_iter().enumerate() {
            if reference.target_node.is_null() {
                warn!(
                    "Target node in reference from {} of type {} is null",
                    node.node_id(),
                    reference.reference_type
                );
                continue;
            }
            let target_node = address_space.find_node(&reference.target_node);
            let Some(target_node) = target_node else {
                warn!(
                    "Target node {} in reference from {} of type {} does not exist",
                    reference.target_node,
                    node.node_id(),
                    reference.reference_type
                );
                continue;
            };
            let target_node = target_node.as_node();

            let type_definition = if node
                .result_mask()
                .contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION)
            {
                // Type definition NodeId of the TargetNode. Type definitions are only available
                // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                // shall be returned.
                match target_node.node_class() {
                    NodeClass::Object | NodeClass::Variable => {
                        let type_defs = address_space.find_references(
                            &target_node.node_id(),
                            Some((ReferenceTypeId::HasTypeDefinition, false)),
                        );
                        if let Some(type_defs) = type_defs {
                            ExpandedNodeId::new(type_defs[0].target_node.clone())
                        } else {
                            ExpandedNodeId::null()
                        }
                    }
                    _ => ExpandedNodeId::null(),
                }
            } else {
                ExpandedNodeId::null()
            };

            let ref_desc = ReferenceDescription {
                reference_type_id: reference.reference_type.clone(),
                is_forward: idx < inverse_ref_idx,
                node_id: ExpandedNodeId::new(target_node.node_id().clone()),
                browse_name: target_node.browse_name().clone(),
                display_name: target_node.display_name().clone(),
                node_class: target_node.node_class(),
                type_definition,
            };

            if node.matches_filter(type_tree, &ref_desc) {
                if node.remaining() > 0 {
                    node.add_unchecked(ref_desc);
                } else {
                    cont_point.nodes.push_back(ref_desc);
                }
            }
        }

        if !cont_point.nodes.is_empty() {
            node.set_next_continuation_point(Box::new(cont_point));
        }
    }

    fn read_node_value(
        address_space: &AddressSpace,
        node_to_read: &ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let mut result_value = DataValue::null();
        let Some(node) = address_space.find(&node_to_read.node_id) else {
            debug!(
                "read_node_value result for read node id {}, attribute {} cannot find node",
                node_to_read.node_id, node_to_read.attribute_id
            );
            result_value.status = Some(StatusCode::BadNodeIdUnknown);
            return result_value;
        };

        let Ok(attribute_id) = AttributeId::from_u32(node_to_read.attribute_id) else {
            debug!(
                "read_node_value result for read node id {}, attribute {} is invalid/2",
                node_to_read.node_id, node_to_read.attribute_id
            );
            result_value.status = Some(StatusCode::BadAttributeIdInvalid);
            return result_value;
        };

        let index_range = match node_to_read
            .index_range
            .as_ref()
            .parse::<NumericRange>()
            .map_err(|_| StatusCode::BadIndexRangeInvalid)
        {
            Ok(index_range) => index_range,
            Err(err) => {
                result_value.status = Some(err);
                return result_value;
            }
        };

        // TODO: Access controll
        if attribute_id != AttributeId::Value && index_range != NumericRange::None {
            result_value.status = Some(StatusCode::BadIndexRangeDataMismatch);
            return result_value;
        }

        if !Self::is_supported_data_encoding(&node_to_read.data_encoding) {
            debug!(
                "read_node_value result for read node id {}, attribute {} is invalid data encoding",
                node_to_read.node_id, node_to_read.attribute_id
            );
            result_value.status = Some(StatusCode::BadDataEncodingInvalid);
            return result_value;
        }

        let Some(attribute) = node.as_node().get_attribute_max_age(
            timestamps_to_return,
            attribute_id,
            index_range,
            &node_to_read.data_encoding,
            max_age,
        ) else {
            result_value.status = Some(StatusCode::BadAttributeIdInvalid);
            return result_value;
        };

        // TODO: Handle UserAccessLevel
        result_value.value = attribute.value;
        result_value.status = attribute.status;
        if matches!(node, NodeType::Variable(_)) && attribute_id == AttributeId::Value {
            match timestamps_to_return {
                TimestampsToReturn::Source => {
                    result_value.source_timestamp = attribute.source_timestamp;
                    result_value.source_picoseconds = attribute.source_picoseconds;
                }
                TimestampsToReturn::Server => {
                    result_value.server_timestamp = attribute.server_timestamp;
                    result_value.server_picoseconds = attribute.server_picoseconds;
                }
                TimestampsToReturn::Both => {
                    result_value.source_timestamp = attribute.source_timestamp;
                    result_value.source_picoseconds = attribute.source_picoseconds;
                    result_value.server_timestamp = attribute.server_timestamp;
                    result_value.server_picoseconds = attribute.server_picoseconds;
                }
                TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                    // Nothing needs to change
                }
            }
        }

        result_value
    }

    fn is_supported_data_encoding(data_encoding: &QualifiedName) -> bool {
        if data_encoding.is_null() {
            true
        } else {
            data_encoding.namespace_index == 0 && data_encoding.name.eq("Default Binary")
        }
    }
}

#[async_trait]
impl NodeManager for InMemoryNodeManager {
    fn owns_node(&self, id: &NodeId) -> bool {
        self.namespaces.contains_key(&id.namespace)
    }

    async fn browse(&self, nodes_to_browse: &mut [BrowseNode]) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(self.type_tree);
        for node in nodes_to_browse {
            if node.node_id().is_null() || !address_space.node_exists(node.node_id()) {
                continue;
            }

            node.set_status(StatusCode::Good);

            if let Some(mut point) = node.take_continuation_point::<BrowseContinuationPoint>() {
                loop {
                    if node.remaining() <= 0 {
                        break;
                    }
                    let Some(ref_desc) = point.nodes.pop_back() else {
                        break;
                    };
                    // Node is already filtered.
                    node.add_unchecked(ref_desc);
                }
                if !point.nodes.is_empty() {
                    node.set_next_continuation_point(point);
                }
            } else {
                Self::browse_node(&address_space, &*type_tree, node);
            }
        }

        Ok(())
    }

    async fn read(
        &self,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        nodes_to_read: &mut [ReadNode],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);

        for node in nodes_to_read {
            if !self.owns_node(&node.node().node_id) {
                continue;
            }

            node.set_result(Self::read_node_value(
                &*address_space,
                &node.node(),
                max_age,
                timestamps_to_return,
            ));
        }

        Ok(())
    }
}
