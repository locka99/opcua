use std::{collections::VecDeque, sync::Arc};

use async_trait::async_trait;

use crate::{
    server::{
        address_space::{
            node::{HasNodeId, NodeType},
            references::ReferenceDirection,
        },
        prelude::{
            AttributeId, BrowseDescriptionResultMask, BrowseDirection, DataValue, ExpandedNodeId,
            NodeClass, NodeId, NumericRange, QualifiedName, ReadValueId, ReferenceDescription,
            ReferenceTypeId, StatusCode, TimestampsToReturn, UserAccessLevel, Variant,
        },
    },
    sync::RwLock,
};

use super::{BrowseNode, DefaultTypeTree, NodeManager, ReadNode, RequestContext};

use crate::async_server::address_space::AddressSpace;

#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

pub struct InMemoryNodeManager {
    address_space: Arc<RwLock<AddressSpace>>,
    type_tree: Arc<RwLock<DefaultTypeTree>>,
    namespaces: hashbrown::HashMap<u16, String>,
}

impl InMemoryNodeManager {
    // TODO: Too specific
    pub fn new() -> Self {
        let mut address_space = AddressSpace::new();
        let mut type_tree = DefaultTypeTree::new();

        address_space.add_namespace("http://opcfoundation.org/UA/", 0);

        crate::server::address_space::populate_address_space(&mut address_space);

        address_space.load_into_type_tree(&mut type_tree);

        Self {
            type_tree: Arc::new(RwLock::new(type_tree)),
            namespaces: address_space.namespaces().clone(),
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

        let mut cont_point = BrowseContinuationPoint::default();

        let source_node_id = node.node_id().clone();

        info!("Browse node: {reference_type_id:?}, {source_node_id}");

        for reference in address_space.find_references(
            &source_node_id,
            reference_type_id,
            type_tree,
            node.browse_direction(),
        ) {
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

            let target_node_id = target_node.node_id();

            let type_definition = if node
                .result_mask()
                .contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION)
            {
                // Type definition NodeId of the TargetNode. Type definitions are only available
                // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                // shall be returned.
                match target_node.node_class() {
                    NodeClass::Object | NodeClass::Variable => {
                        let mut type_defs = address_space.find_references(
                            &target_node_id,
                            Some((ReferenceTypeId::HasTypeDefinition, false)),
                            type_tree,
                            BrowseDirection::Forward,
                        );
                        if let Some(type_def) = type_defs.next() {
                            ExpandedNodeId::new(type_def.target_node.clone())
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
                is_forward: matches!(reference.direction, ReferenceDirection::Forward),
                node_id: ExpandedNodeId::new(target_node_id),
                browse_name: target_node.browse_name().clone(),
                display_name: target_node.display_name().clone(),
                node_class: target_node.node_class(),
                type_definition,
            };

            if node.matches_filter(type_tree, &ref_desc) {
                if node.remaining() > 0 {
                    info!("Browse return node {ref_desc:?}");
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

    fn user_access_level(
        context: &RequestContext,
        node: &NodeType,
        attribute_id: AttributeId,
    ) -> UserAccessLevel {
        let user_access_level = if let NodeType::Variable(ref node) = node {
            node.user_access_level()
        } else {
            UserAccessLevel::CURRENT_READ
        };
        context.authenticator.effective_user_access_level(
            &context.token,
            user_access_level,
            &node.node_id(),
            attribute_id,
        )
    }

    fn is_readable(context: &RequestContext, node: &NodeType, attribute_id: AttributeId) -> bool {
        // TODO session for current user
        // Check for access level, user access level
        Self::user_access_level(context, node, attribute_id).contains(UserAccessLevel::CURRENT_READ)
    }

    fn read_node_value(
        context: &RequestContext,
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

        let Ok(index_range) = node_to_read.index_range.as_ref().parse::<NumericRange>() else {
            result_value.status = Some(StatusCode::BadIndexRangeInvalid);
            return result_value;
        };

        if !Self::is_readable(context, node, attribute_id) {
            result_value.status = Some(StatusCode::BadNotReadable);
            return result_value;
        }

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

        let value = if attribute_id == AttributeId::UserAccessLevel {
            match attribute.value {
                Some(Variant::Byte(val)) => {
                    let access_level = UserAccessLevel::from_bits_truncate(val);
                    let access_level = context.authenticator.effective_user_access_level(
                        &context.token,
                        access_level,
                        &node.node_id(),
                        attribute_id,
                    );
                    Some(Variant::from(access_level.bits()))
                }
                Some(v) => Some(v),
                _ => None,
            }
        } else {
            attribute.value
        };

        result_value.value = value;
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

    async fn browse(
        &self,
        _context: &RequestContext,
        nodes_to_browse: &mut [BrowseNode],
    ) -> Result<(), StatusCode> {
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
        context: &RequestContext,
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
                context,
                &*address_space,
                &node.node(),
                max_age,
                timestamps_to_return,
            ));
        }

        Ok(())
    }
}
