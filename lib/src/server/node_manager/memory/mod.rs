mod core;
mod diagnostics;
mod implementation;
mod simple;

pub use core::{CoreNodeManager, CoreNodeManagerBuilder, CoreNodeManagerImpl};
pub use diagnostics::{DiagnosticsNodeManager, DiagnosticsNodeManagerBuilder, NamespaceMetadata};
pub use implementation::*;
pub use simple::*;

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::{
    server::{
        address_space::{
            read_node_value, user_access_level, EventNotifier, NodeType, ReferenceDirection,
            UserAccessLevel,
        },
        subscriptions::CreateMonitoredItem,
        SubscriptionCache,
    },
    sync::RwLock,
    types::{
        argument::Argument, AttributeId, BrowseDescriptionResultMask, BrowseDirection, DataValue,
        DateTime, ExpandedNodeId, MonitoringMode, NodeClass, NodeId, NumericRange, QualifiedName,
        ReadAnnotationDataDetails, ReadAtTimeDetails, ReadEventDetails, ReadProcessedDetails,
        ReadRawModifiedDetails, ReferenceDescription, ReferenceTypeId, StatusCode,
        TimestampsToReturn, Variant,
    },
};

use super::{
    build::NodeManagerBuilder,
    view::{AddReferenceResult, ExternalReference, ExternalReferenceRequest, NodeMetadata},
    AddNodeItem, AddReferenceItem, BrowseNode, BrowsePathItem, DeleteNodeItem, DeleteReferenceItem,
    DynNodeManager, HistoryNode, HistoryUpdateDetails, HistoryUpdateNode, MethodCall,
    MonitoredItemRef, MonitoredItemUpdateRef, NodeManager, ReadNode, RegisterNodeItem,
    RequestContext, ServerContext, TypeTree, WriteNode,
};

use crate::server::address_space::AddressSpace;

#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

pub struct InMemoryNodeManager<TImpl> {
    address_space: Arc<RwLock<AddressSpace>>,
    namespaces: HashMap<u16, String>,
    inner: TImpl,
}

pub struct InMemoryNodeManagerBuilder<T> {
    impl_builder: T,
}

impl<T: InMemoryNodeManagerImplBuilder> InMemoryNodeManagerBuilder<T> {
    pub fn new(impl_builder: T) -> Self {
        Self { impl_builder }
    }
}

impl<T: InMemoryNodeManagerImplBuilder> NodeManagerBuilder for InMemoryNodeManagerBuilder<T> {
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager> {
        let mut address_space = AddressSpace::new();
        let inner = self.impl_builder.build(context, &mut address_space);
        Arc::new(InMemoryNodeManager::new(inner, address_space))
    }
}

impl<TImpl: InMemoryNodeManagerImpl> InMemoryNodeManager<TImpl> {
    pub(crate) fn new(inner: TImpl, address_space: AddressSpace) -> Self {
        Self {
            namespaces: address_space.namespaces().clone(),
            address_space: Arc::new(RwLock::new(address_space)),
            inner,
        }
    }

    pub fn inner(&self) -> &TImpl {
        &self.inner
    }

    pub fn address_space(&self) -> &Arc<RwLock<AddressSpace>> {
        &self.address_space
    }

    pub fn namespaces(&self) -> &HashMap<u16, String> {
        &self.namespaces
    }

    pub fn set_attributes<'a>(
        &self,
        subscriptions: &SubscriptionCache,
        values: impl Iterator<Item = (&'a NodeId, AttributeId, Variant)>,
    ) -> Result<(), StatusCode> {
        let mut address_space = trace_write_lock!(self.address_space);
        let mut output = Vec::new();

        for (id, attribute_id, value) in values {
            let Some(node) = address_space.find_mut(id) else {
                return Err(StatusCode::BadNodeIdUnknown);
            };

            let node_mut = node.as_mut_node();
            node_mut.set_attribute(attribute_id, value)?;
            // Don't notify on changes to event notifier, subscribing to that
            // specific attribute means subscribing to events.
            if attribute_id != AttributeId::EventNotifier {
                output.push((id, attribute_id));
            }
        }

        subscriptions.maybe_notify(
            output.into_iter(),
            |node_id, attribute_id, index_range, data_encoding| {
                let Some(node) = address_space.find(node_id) else {
                    return None;
                };
                let node_ref = node.as_node();

                node_ref.get_attribute(
                    TimestampsToReturn::Both,
                    attribute_id,
                    index_range.clone(),
                    data_encoding,
                )
            },
        );

        Ok(())
    }

    pub fn set_attribute(
        &self,
        subscriptions: &SubscriptionCache,
        id: &NodeId,
        attribute_id: AttributeId,
        value: Variant,
    ) -> Result<(), StatusCode> {
        self.set_attributes(subscriptions, [(id, attribute_id, value)].into_iter())
    }

    pub fn set_values<'a>(
        &self,
        subscriptions: &SubscriptionCache,
        values: impl Iterator<Item = (&'a NodeId, Option<NumericRange>, DataValue)>,
    ) -> Result<(), StatusCode> {
        let mut address_space = trace_write_lock!(self.address_space);
        let now = DateTime::now();
        let mut output = Vec::new();

        for (id, index_range, value) in values {
            let Some(node) = address_space.find_mut(id) else {
                return Err(StatusCode::BadNodeIdUnknown);
            };

            match node {
                NodeType::Variable(v) => {
                    if let Some(range) = index_range {
                        let status = value.status();
                        let source_timestamp = value.source_timestamp.unwrap_or(now);
                        let server_timestamp = value.server_timestamp.unwrap_or(now);
                        v.set_value_range(
                            value.value.unwrap_or_default(),
                            range,
                            status,
                            &server_timestamp,
                            &source_timestamp,
                        )?
                    } else {
                        v.set_data_value(value)
                    }
                }
                NodeType::VariableType(v) => v.set_value(value.value.unwrap_or_default()),
                _ => return Err(StatusCode::BadAttributeIdInvalid),
            }

            output.push((id, AttributeId::Value));
        }

        subscriptions.maybe_notify(
            output.into_iter(),
            |node_id, attribute_id, index_range, data_encoding| {
                let Some(node) = address_space.find(node_id) else {
                    return None;
                };
                let node_ref = node.as_node();

                node_ref.get_attribute(
                    TimestampsToReturn::Both,
                    attribute_id,
                    index_range.clone(),
                    data_encoding,
                )
            },
        );

        Ok(())
    }

    pub fn set_value(
        &self,
        subscriptions: &SubscriptionCache,
        id: &NodeId,
        index_range: Option<NumericRange>,
        value: DataValue,
    ) -> Result<(), StatusCode> {
        self.set_values(subscriptions, [(id, index_range, value)].into_iter())
    }

    fn get_reference<'a>(
        address_space: &AddressSpace,
        type_tree: &TypeTree,
        target_node: &'a NodeType,
        result_mask: BrowseDescriptionResultMask,
    ) -> NodeMetadata {
        let node_ref = target_node.as_node();

        let target_node_id = node_ref.node_id().clone();

        let type_definition =
            if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION) {
                // Type definition NodeId of the TargetNode. Type definitions are only available
                // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                // shall be returned.
                match node_ref.node_class() {
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
            browse_name: node_ref.browse_name().clone(),
            display_name: node_ref.display_name().clone(),
            node_class: node_ref.node_class(),
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
                .is_some_and(|n| name.is_null() || n.as_node().browse_name() == name);
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
                            || node.as_node().browse_name() == &element.target_name
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

    fn validate_history_read_nodes<'a, 'b>(
        &self,
        context: &RequestContext,
        nodes: &'b mut [&'a mut HistoryNode],
        is_for_events: bool,
    ) -> Vec<&'b mut &'a mut HistoryNode> {
        let address_space = trace_read_lock!(self.address_space);
        let mut valid = Vec::with_capacity(nodes.len());

        for history_node in nodes {
            let Some(node) = address_space.find(history_node.node_id()) else {
                history_node.set_status(StatusCode::BadNodeIdUnknown);
                continue;
            };

            if is_for_events {
                // TODO: History read for events should forward to a global callback
                // for the server node.
                let NodeType::Object(object) = node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                if !object
                    .event_notifier()
                    .contains(EventNotifier::HISTORY_READ)
                {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                }
            } else {
                let NodeType::Variable(_) = node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                let user_access_level = user_access_level(context, node);

                if !user_access_level.contains(UserAccessLevel::HISTORY_READ) {
                    history_node.set_status(StatusCode::BadUserAccessDenied);
                    continue;
                }
            }

            valid.push(history_node);
        }

        valid
    }

    fn validate_history_write_nodes<'a, 'b>(
        &self,
        context: &RequestContext,
        nodes: &'b mut [&'a mut HistoryUpdateNode],
    ) -> Vec<&'b mut &'a mut HistoryUpdateNode> {
        let address_space = trace_read_lock!(self.address_space);
        let mut valid = Vec::with_capacity(nodes.len());

        for history_node in nodes {
            let Some(node) = address_space.find(history_node.details().node_id()) else {
                history_node.set_status(StatusCode::BadNodeIdUnknown);
                continue;
            };

            let is_for_events = matches!(
                history_node.details(),
                HistoryUpdateDetails::DeleteEvent(_) | HistoryUpdateDetails::UpdateEvent(_)
            );

            if is_for_events {
                // TODO: History read for events should forward to a global callback
                // for the server node.
                let NodeType::Object(object) = node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                if !object
                    .event_notifier()
                    .contains(EventNotifier::HISTORY_WRITE)
                {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                }
            } else {
                let NodeType::Variable(_) = node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                let user_access_level = user_access_level(context, node);

                if !user_access_level.contains(UserAccessLevel::HISTORY_WRITE) {
                    history_node.set_status(StatusCode::BadUserAccessDenied);
                    continue;
                }
            }

            valid.push(history_node);
        }

        valid
    }

    fn validate_method_calls<'a, 'b>(
        &self,
        context: &RequestContext,
        methods: &'b mut [&'a mut MethodCall],
    ) -> Vec<&'b mut &'a mut MethodCall> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);
        let mut valid = Vec::with_capacity(methods.len());

        for method in methods {
            let Some(method_ref) = address_space
                .find_references(
                    method.object_id(),
                    Some((ReferenceTypeId::HasComponent, false)),
                    &type_tree,
                    BrowseDirection::Forward,
                )
                .find(|r| r.target_node == method.method_id())
            else {
                method.set_status(StatusCode::BadMethodInvalid);
                continue;
            };

            let Some(NodeType::Method(method_node)) = address_space.find(method_ref.target_node)
            else {
                method.set_status(StatusCode::BadMethodInvalid);
                continue;
            };

            if !method_node.user_executable()
                || !context
                    .authenticator
                    .is_user_executable(&context.token, method.method_id())
            {
                method.set_status(StatusCode::BadUserAccessDenied);
                continue;
            }

            let input_arguments = address_space.find_node_by_browse_name(
                method.method_id(),
                Some((ReferenceTypeId::HasProperty, false)),
                &type_tree,
                BrowseDirection::Forward,
                "InputArguments",
            );

            // If there are no input arguments, it means the method takes no inputs.
            let Some(input_arguments) = input_arguments else {
                if method.arguments().is_empty() {
                    valid.push(method);
                } else {
                    method.set_status(StatusCode::BadTooManyArguments);
                }
                continue;
            };

            // If the input arguments object is invalid, we pass it along anyway and leave it up to
            // the implementation to validate.
            let NodeType::Variable(arg_var) = input_arguments else {
                warn!(
                    "InputArguments for method with ID {} has incorrect node class",
                    method.method_id()
                );
                valid.push(method);
                continue;
            };

            let Some(Variant::Array(input_arguments_value)) = arg_var
                .value(
                    TimestampsToReturn::Neither,
                    NumericRange::None,
                    &QualifiedName::null(),
                    0.0,
                )
                .value
            else {
                warn!(
                    "InputArguments for method with ID {} has incorrect type",
                    method.method_id()
                );
                valid.push(method);
                continue;
            };

            let options = context.info.decoding_options();
            let num_args = input_arguments_value.values.len();
            let arguments: Vec<_> = input_arguments_value
                .values
                .into_iter()
                .filter_map(|v| match v {
                    Variant::ExtensionObject(o) => o.decode_inner::<Argument>(&options).ok(),
                    _ => None,
                })
                .collect();
            if arguments.len() != num_args {
                warn!(
                    "InputArguments for method with ID {} has invalid arguments",
                    method.method_id()
                );
                valid.push(method);
                continue;
            };

            if arguments.len() < method.arguments().len() {
                method.set_status(StatusCode::BadTooManyArguments);
                continue;
            }

            valid.push(method);
        }

        valid
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

    async fn init(&self, type_tree: &mut TypeTree, context: ServerContext) {
        let mut address_space = trace_write_lock!(self.address_space);

        self.inner.init(&mut address_space, context).await;

        address_space.load_into_type_tree(type_tree);
    }

    fn namespaces_for_user(&self, _context: &RequestContext) -> Vec<NamespaceMetadata> {
        self.inner.namespaces()
    }

    fn handle_new_node(&self, parent_id: &ExpandedNodeId) -> bool {
        self.inner.handle_new_node(parent_id)
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
        nodes_to_read: &mut [&mut ReadNode],
    ) -> Result<(), StatusCode> {
        let mut read_values = Vec::new();
        {
            let address_space = trace_read_lock!(self.address_space);
            for node in nodes_to_read {
                if node.node().attribute_id == AttributeId::Value {
                    read_values.push(node);
                    continue;
                }

                node.set_result(address_space.read(
                    context,
                    &node.node(),
                    max_age,
                    timestamps_to_return,
                ));
            }
        }

        if !read_values.is_empty() {
            let ids: Vec<_> = read_values.iter().map(|r| r.node()).collect();
            let values = self
                .inner
                .read_values(
                    context,
                    &self.address_space,
                    &ids,
                    max_age,
                    timestamps_to_return,
                )
                .await;
            for (read, value) in read_values.iter_mut().zip(values) {
                read.set_result(value);
            }
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

    async fn create_monitored_items(
        &self,
        context: &RequestContext,
        items: &mut [&mut CreateMonitoredItem],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let mut value_items = Vec::new();
        let mut event_items = Vec::new();

        for node in items {
            if node.item_to_monitor().attribute_id == AttributeId::Value {
                value_items.push(node);
                continue;
            }

            let n = match address_space.validate_node_read(context, node.item_to_monitor()) {
                Ok(n) => n,
                Err(e) => {
                    node.set_status(e);
                    continue;
                }
            };

            let read_result = read_node_value(
                n,
                context,
                node.item_to_monitor(),
                0.0,
                node.timestamps_to_return(),
            );

            // Event monitored items are global, so all we need to do is to validate that the
            // node allows subscribing to events.
            if node.item_to_monitor().attribute_id == AttributeId::EventNotifier {
                let Some(Variant::Byte(notifier)) = &read_result.value else {
                    node.set_status(StatusCode::BadAttributeIdInvalid);
                    continue;
                };
                let notifier = EventNotifier::from_bits_truncate(*notifier);
                if !notifier.contains(EventNotifier::SUBSCRIBE_TO_EVENTS) {
                    node.set_status(StatusCode::BadAttributeIdInvalid);
                    continue;
                }

                // No further action beyond just validation.
                node.set_status(StatusCode::Good);
                event_items.push(node);
                continue;
            }

            // This specific status code here means that the value does not exist, so it is
            // more appropriate to not set an initial value.
            if read_result.status() != StatusCode::BadAttributeIdInvalid {
                node.set_initial_value(read_result);
            }

            node.set_status(StatusCode::Good);
        }
        drop(address_space);

        if !value_items.is_empty() {
            self.inner
                .create_value_monitored_items(context, &self.address_space, &mut value_items)
                .await;
        }

        if !event_items.is_empty() {
            self.inner
                .create_event_monitored_items(context, &self.address_space, &mut event_items)
                .await;
        }

        Ok(())
    }

    async fn modify_monitored_items(
        &self,
        context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
        let items: Vec<_> = items
            .iter()
            .filter(|it| {
                matches!(
                    it.attribute(),
                    AttributeId::Value | AttributeId::EventNotifier
                )
            })
            .copied()
            .collect();
        self.inner.modify_monitored_items(context, &items).await;
    }

    async fn set_monitoring_mode(
        &self,
        context: &RequestContext,
        mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
        let items: Vec<_> = items
            .iter()
            .filter(|it| {
                matches!(
                    it.attribute(),
                    AttributeId::Value | AttributeId::EventNotifier
                )
            })
            .copied()
            .collect();
        self.inner.set_monitoring_mode(context, mode, &items).await;
    }

    async fn delete_monitored_items(&self, context: &RequestContext, items: &[&MonitoredItemRef]) {
        let items: Vec<_> = items
            .iter()
            .filter(|it| {
                matches!(
                    it.attribute(),
                    AttributeId::Value | AttributeId::EventNotifier
                )
            })
            .copied()
            .collect();
        self.inner.delete_monitored_items(context, &items).await;
    }

    async fn history_read_raw_modified(
        &self,
        context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_raw_modified(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_processed(
        &self,
        context: &RequestContext,
        details: &ReadProcessedDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_processed(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_at_time(
        &self,
        context: &RequestContext,
        details: &ReadAtTimeDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_at_time(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_events(
        &self,
        context: &RequestContext,
        details: &ReadEventDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_events(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_annotations(
        &self,
        context: &RequestContext,
        details: &ReadAnnotationDataDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_annotations(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn write(
        &self,
        context: &RequestContext,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        self.inner
            .write(context, &self.address_space, nodes_to_write)
            .await
    }

    async fn history_update(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut HistoryUpdateNode],
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_write_nodes(context, nodes);
        self.inner.history_update(context, &mut nodes).await
    }

    async fn call(
        &self,
        context: &RequestContext,
        methods_to_call: &mut [&mut MethodCall],
    ) -> Result<(), StatusCode> {
        let mut to_call = self.validate_method_calls(context, methods_to_call);
        self.inner
            .call(context, &self.address_space, &mut to_call)
            .await
    }

    /// Add a list of nodes.
    ///
    /// This should create the nodes, or set a failed status as appropriate.
    /// If a node was created, the status should be set to Good.
    async fn add_nodes(
        &self,
        context: &RequestContext,
        nodes_to_add: &mut [&mut AddNodeItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .add_nodes(context, &self.address_space, nodes_to_add)
            .await
    }

    async fn add_references(
        &self,
        context: &RequestContext,
        references_to_add: &mut [&mut AddReferenceItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .add_references(context, &self.address_space, references_to_add)
            .await
    }

    async fn delete_nodes(
        &self,
        context: &RequestContext,
        nodes_to_delete: &mut [&mut DeleteNodeItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .delete_nodes(context, &self.address_space, nodes_to_delete)
            .await
    }

    async fn delete_node_references(
        &self,
        context: &RequestContext,
        to_delete: &[&DeleteNodeItem],
    ) {
        self.inner
            .delete_node_references(context, &self.address_space, to_delete)
            .await
    }

    async fn delete_references(
        &self,
        context: &RequestContext,
        references_to_delete: &mut [&mut DeleteReferenceItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .delete_references(context, &self.address_space, references_to_delete)
            .await
    }
}
