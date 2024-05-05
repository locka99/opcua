mod core;

pub use core::CoreNodeManager;

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

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

use super::{
    view::{AddReferenceResult, ExternalReference, ExternalReferenceRequest, NodeMetadata},
    BrowseNode, BrowsePathItem, NodeManager, ReadNode, RegisterNodeItem, RequestContext, TypeTree,
};

use crate::async_server::address_space::AddressSpace;

#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

#[async_trait]
#[allow(unused)]
pub trait InMemoryNodeManagerImpl: Send + Sync + 'static {
    fn build_nodes(address_space: &mut AddressSpace);

    fn name(&self) -> &str;

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

    async fn unregister_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&NodeId],
    ) -> Result<(), StatusCode> {
        // Again, just do nothing
        Ok(())
    }
}

pub struct InMemoryNodeManager<TImpl: InMemoryNodeManagerImpl> {
    address_space: Arc<RwLock<AddressSpace>>,
    namespaces: hashbrown::HashMap<u16, String>,
    inner: TImpl,
}

impl<TImpl: InMemoryNodeManagerImpl> InMemoryNodeManager<TImpl> {
    pub fn new(inner: TImpl) -> Self {
        let mut address_space = AddressSpace::new();

        TImpl::build_nodes(&mut address_space);

        Self {
            namespaces: address_space.namespaces().clone(),
            address_space: Arc::new(RwLock::new(address_space)),
            inner,
        }
    }

    fn get_reference(
        address_space: &AddressSpace,
        type_tree: &TypeTree,
        target_node: &NodeType,
        result_mask: BrowseDescriptionResultMask,
    ) -> NodeMetadata {
        let target_node = target_node.as_node();

        let target_node_id = target_node.node_id();

        let type_definition =
            if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION) {
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

        NodeMetadata {
            node_id: ExpandedNodeId::new(target_node_id),
            browse_name: target_node.browse_name().clone(),
            display_name: target_node.display_name().clone(),
            node_class: target_node.node_class(),
            type_definition,
        }
    }

    /// Browses a single node, returns any external references found.
    fn browse_node<'a>(
        address_space: &'a AddressSpace,
        type_tree: &TypeTree,
        node: &mut BrowseNode,
        namespaces: &hashbrown::HashMap<u16, String>,
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
                if namespaces.contains_key(&reference.target_node.namespace) {
                    warn!(
                        "Target node {} in reference from {} of type {} does not exist",
                        reference.target_node,
                        node.node_id(),
                        reference.reference_type
                    );
                } else {
                    node.push_external_reference(ExternalReference::new(
                        reference.target_node.into(),
                        reference.reference_type.clone(),
                        reference.direction,
                    ))
                }

                continue;
            };

            let r_node =
                Self::get_reference(address_space, type_tree, target_node, node.result_mask());

            let ref_desc = ReferenceDescription {
                reference_type_id: reference.reference_type.clone(),
                is_forward: matches!(reference.direction, ReferenceDirection::Forward),
                node_id: r_node.node_id,
                browse_name: r_node.browse_name,
                display_name: r_node.display_name,
                node_class: r_node.node_class,
                type_definition: r_node.type_definition,
            };

            if let AddReferenceResult::Full(c) = node.add(type_tree, ref_desc) {
                cont_point.nodes.push_back(c);
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

    fn translate_browse_paths(
        address_space: &AddressSpace,
        type_tree: &TypeTree,
        context: &RequestContext,
        namespaces: &hashbrown::HashMap<u16, String>,
        item: &mut BrowsePathItem,
    ) {
        if let Some(name) = item.unmatched_browse_name() {
            let is_full_match = address_space
                .find_node(item.node_id())
                .is_some_and(|n| name.is_null() || &n.as_node().browse_name() == name);
            if !is_full_match {
                return;
            } else {
                item.set_browse_name_matched(context.current_node_manager_index);
            }
        }

        let mut matching_nodes = HashSet::new();
        matching_nodes.insert(item.node_id());
        let mut next_matching_nodes = HashSet::new();
        let mut results = Vec::new();

        let mut depth = 0;
        for element in item.path() {
            depth += 1;
            for node_id in matching_nodes.drain() {
                let reference_filter = {
                    if element.reference_type_id.is_null() {
                        None
                    } else {
                        Some((element.reference_type_id.clone(), element.include_subtypes))
                    }
                };

                for rf in address_space.find_references(
                    &node_id,
                    reference_filter,
                    type_tree,
                    if element.is_inverse {
                        BrowseDirection::Inverse
                    } else {
                        BrowseDirection::Forward
                    },
                ) {
                    if !next_matching_nodes.contains(rf.target_node) {
                        let Some(node) = address_space.find_node(rf.target_node) else {
                            if !namespaces.contains_key(&rf.target_node.namespace) {
                                results.push((
                                    rf.target_node,
                                    depth,
                                    Some(element.target_name.clone()),
                                ));
                            }
                            continue;
                        };

                        if element.target_name.is_null()
                            || node.as_node().browse_name() == element.target_name
                        {
                            next_matching_nodes.insert(rf.target_node);
                            results.push((rf.target_node, depth, None));
                        }
                    }
                }
            }
            std::mem::swap(&mut matching_nodes, &mut next_matching_nodes);
        }

        for res in results {
            item.add_element(res.0.clone(), res.1, res.2);
        }
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> NodeManager for InMemoryNodeManager<TImpl> {
    fn owns_node(&self, id: &NodeId) -> bool {
        self.namespaces.contains_key(&id.namespace)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn init(&self, type_tree: &mut TypeTree) {
        let address_space = trace_read_lock!(self.address_space);

        address_space.load_into_type_tree(type_tree);
    }

    async fn resolve_external_references(
        &self,
        context: &RequestContext,
        items: &mut [&mut ExternalReferenceRequest],
    ) {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for item in items.into_iter() {
            let target_node = address_space.find_node(&item.node_id());

            let Some(target_node) = target_node else {
                continue;
            };

            item.set(Self::get_reference(
                &*address_space,
                &*type_tree,
                target_node,
                item.result_mask(),
            ));
        }
    }

    async fn browse(
        &self,
        context: &RequestContext,
        nodes_to_browse: &mut [BrowseNode],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for node in nodes_to_browse.iter_mut() {
            if node.node_id().is_null() {
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
                Self::browse_node(&address_space, &*type_tree, node, &self.namespaces);
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

    async fn translate_browse_paths_to_node_ids(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut BrowsePathItem],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for node in nodes {
            Self::translate_browse_paths(
                &*address_space,
                &*type_tree,
                context,
                &self.namespaces,
                node,
            );
        }

        Ok(())
    }

    async fn register_nodes(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut RegisterNodeItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .register_nodes(context, &self.address_space, nodes)
            .await
    }

    async fn unregister_nodes(
        &self,
        context: &RequestContext,
        nodes: &[&NodeId],
    ) -> Result<(), StatusCode> {
        self.inner
            .unregister_nodes(context, &self.address_space, nodes)
            .await
    }
}
