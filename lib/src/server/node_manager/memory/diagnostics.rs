use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;

use crate::{
    server::{
        address_space::AccessLevel,
        node_manager::{
            as_opaque_node_id,
            build::NodeManagerBuilder,
            from_opaque_node_id,
            view::{AddReferenceResult, NodeMetadata},
            BrowseNode, DynNodeManager, NodeManager, NodeManagersRef, ReadNode, RequestContext,
            ServerContext, SyncSampler, TypeTree,
        },
    },
    types::{
        AccessLevelExType, AccessRestrictionType, AttributeId, BrowseDirection, DataTypeId,
        DataValue, DateTime, ExpandedNodeId, ExtensionObject, IdType, LocalizedText, NodeClass,
        NodeId, NumericRange, ObjectId, ObjectTypeId, QualifiedName, ReferenceDescription,
        ReferenceTypeId, RolePermissionType, StatusCode, TimestampsToReturn, VariableTypeId,
        Variant,
    },
};

/// Node manager handling nodes in the server hierarchy that are not part of the
/// core namespace, and that are somehow dynamic. This includes the node for each namespace,
/// session diagnostics, etc.
pub struct DiagnosticsNodeManager {
    sampler: SyncSampler,
    node_managers: NodeManagersRef,
    namespace_index: u16,
}

/*
The diagnostics node manager is a simple example of a node manager that
obtains its structure from somewhere else. Specifically in this case,
the structure is virtual, and obtained from the current server state.

In order to allow this the node manager cannot be based on the in-memory node manager,
which allows for static hierarchies only.

We want to produce consistent node IDs without a cache, so we use opaque node IDs to
make identifiers that describe where to find the data. That way we can handle Read's
of nodes without explicitly storing each node ID.
*/

#[derive(Default, Clone, Debug)]
pub struct NamespaceMetadata {
    pub default_access_restrictions: AccessRestrictionType,
    pub default_role_permissions: Option<Vec<RolePermissionType>>,
    pub default_user_role_permissions: Option<Vec<RolePermissionType>>,
    pub is_namespace_subset: Option<bool>,
    pub namespace_publication_date: Option<DateTime>,
    pub namespace_uri: String,
    pub namespace_version: Option<String>,
    pub static_node_id_types: Option<Vec<IdType>>,
    pub static_numeric_node_id_range: Option<Vec<NumericRange>>,
    pub static_string_node_id_pattern: Option<String>,
    pub namespace_index: u16,
}

#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

#[derive(Serialize, Deserialize)]
struct NamespaceNode {
    namespace: String,
    property: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum DiagnosticsNode {
    Namespace(NamespaceNode),
}

pub struct DiagnosticsNodeManagerBuilder;

impl NodeManagerBuilder for DiagnosticsNodeManagerBuilder {
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager> {
        Arc::new(DiagnosticsNodeManager::new(context))
    }
}

impl DiagnosticsNodeManager {
    pub(crate) fn new(context: ServerContext) -> Self {
        let namespace_index = {
            let mut type_tree = context.type_tree.write();
            type_tree
                .namespaces_mut()
                .add_namespace(context.info.application_uri.as_ref())
        };
        Self {
            sampler: SyncSampler::new(),
            node_managers: context.node_managers.clone(),
            namespace_index,
        }
    }

    fn namespaces(&self, context: &RequestContext) -> BTreeMap<String, NamespaceMetadata> {
        self.node_managers
            .iter()
            .flat_map(move |nm| nm.namespaces_for_user(context))
            .map(|ns| (ns.namespace_uri.clone(), ns))
            .collect()
    }

    fn namespace_node_metadata(&self, ns: &NamespaceMetadata) -> NodeMetadata {
        NodeMetadata {
            node_id: ExpandedNodeId::new(
                as_opaque_node_id(
                    &DiagnosticsNode::Namespace(NamespaceNode {
                        namespace: ns.namespace_uri.clone(),
                        property: None,
                    }),
                    self.namespace_index,
                )
                .unwrap(),
            ),
            type_definition: ExpandedNodeId::new(ObjectTypeId::NamespaceMetadataType),
            browse_name: QualifiedName::new(ns.namespace_index, ns.namespace_uri.clone()),
            display_name: LocalizedText::new("", &ns.namespace_uri),
            node_class: NodeClass::Object,
        }
    }

    fn browse_namespaces(
        &self,
        node_to_browse: &mut BrowseNode,
        type_tree: &TypeTree,
        namespaces: &BTreeMap<String, NamespaceMetadata>,
    ) {
        // Only hierarchical references in this case, so we can check for that first.
        if !matches!(
            node_to_browse.browse_direction(),
            BrowseDirection::Forward | BrowseDirection::Both
        ) {
            return;
        }

        if !node_to_browse.allows_reference_type(&ReferenceTypeId::HasComponent.into(), type_tree) {
            return;
        }

        let mut cp = BrowseContinuationPoint::default();

        for namespace in namespaces.values() {
            // Handled by the core node manager
            if namespace.namespace_index == 0 {
                continue;
            }
            let metadata = self.namespace_node_metadata(namespace);
            let ref_desc = ReferenceDescription {
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                is_forward: true,
                node_id: metadata.node_id,
                browse_name: metadata.browse_name,
                display_name: metadata.display_name,
                node_class: metadata.node_class,
                type_definition: metadata.type_definition,
            };

            if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, ref_desc) {
                cp.nodes.push_back(c);
            }
        }

        if !cp.nodes.is_empty() {
            node_to_browse.set_next_continuation_point(Box::new(cp));
        }
    }

    fn browse_namespace_metadata_node(
        &self,
        node_to_browse: &mut BrowseNode,
        type_tree: &TypeTree,
        meta: &NamespaceMetadata,
    ) {
        let mut cp = BrowseContinuationPoint::default();

        if matches!(
            node_to_browse.browse_direction(),
            BrowseDirection::Forward | BrowseDirection::Both
        ) {
            if node_to_browse.allows_reference_type(&ReferenceTypeId::HasProperty.into(), type_tree)
                && node_to_browse.allows_node_class(NodeClass::Variable)
            {
                for prop in [
                    "DefaultAccessRestrictions",
                    "DefaultRolePermissions",
                    "DefaultUserRolePermissions",
                    "IsNamespaceSubset",
                    "NamespacePublicationDate",
                    "NamespaceUri",
                    "NamespaceVersion",
                    "StaticNodeIdTypes",
                    "StaticNumericNodeIdRange",
                    "StaticStringNodeIdPattern",
                ] {
                    let ref_desc = ReferenceDescription {
                        reference_type_id: ReferenceTypeId::HasProperty.into(),
                        is_forward: true,
                        node_id: ExpandedNodeId::new(
                            as_opaque_node_id(
                                &DiagnosticsNode::Namespace(NamespaceNode {
                                    namespace: meta.namespace_uri.clone(),
                                    property: Some(prop.to_owned()),
                                }),
                                self.namespace_index,
                            )
                            .unwrap(),
                        ),
                        type_definition: ExpandedNodeId::new(VariableTypeId::PropertyType),
                        browse_name: QualifiedName::new(0, prop),
                        display_name: LocalizedText::new("", prop),
                        node_class: NodeClass::Variable,
                    };
                    if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, ref_desc) {
                        cp.nodes.push_back(c);
                    }
                }
            }

            if node_to_browse
                .allows_reference_type(&ReferenceTypeId::HasTypeDefinition.into(), type_tree)
            {
                let ref_desc = ReferenceDescription {
                    reference_type_id: ReferenceTypeId::HasTypeDefinition.into(),
                    is_forward: true,
                    node_id: ObjectTypeId::NamespaceMetadataType.into(),
                    browse_name: QualifiedName::new(0, "NamespaceMetadataType"),
                    display_name: LocalizedText::new("", "NamespaceMetadataType"),
                    node_class: NodeClass::ObjectType,
                    type_definition: ExpandedNodeId::null(),
                };
                if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, ref_desc) {
                    cp.nodes.push_back(c);
                }
            }
        }

        if matches!(
            node_to_browse.browse_direction(),
            BrowseDirection::Inverse | BrowseDirection::Both
        ) {
            let ref_desc = ReferenceDescription {
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                is_forward: false,
                node_id: ObjectId::Server_Namespaces.into(),
                browse_name: QualifiedName::new(0, "Namespaces"),
                display_name: LocalizedText::new("", "Namespaces"),
                node_class: NodeClass::Object,
                type_definition: ObjectTypeId::NamespacesType.into(),
            };
            if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, ref_desc) {
                cp.nodes.push_back(c);
            }
        }

        if !cp.nodes.is_empty() {
            node_to_browse.set_next_continuation_point(Box::new(cp));
        }
    }

    fn browse_namespace_property_node(
        &self,
        node_to_browse: &mut BrowseNode,
        type_tree: &TypeTree,
        meta: &NamespaceMetadata,
    ) {
        let mut cp = BrowseContinuationPoint::default();

        if matches!(
            node_to_browse.browse_direction(),
            BrowseDirection::Forward | BrowseDirection::Both
        ) {
            let ref_desc = ReferenceDescription {
                reference_type_id: ReferenceTypeId::HasTypeDefinition.into(),
                is_forward: true,
                node_id: VariableTypeId::PropertyType.into(),
                browse_name: QualifiedName::new(0, "PropertyType"),
                display_name: LocalizedText::new("", "PropertyType"),
                node_class: NodeClass::VariableType,
                type_definition: ExpandedNodeId::null(),
            };
            if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, ref_desc) {
                cp.nodes.push_back(c);
            }
        }

        if matches!(
            node_to_browse.browse_direction(),
            BrowseDirection::Inverse | BrowseDirection::Both
        ) {
            let metadata = self.namespace_node_metadata(meta);
            let ref_desc = ReferenceDescription {
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                is_forward: false,
                node_id: metadata.node_id,
                browse_name: metadata.browse_name,
                display_name: metadata.display_name,
                node_class: metadata.node_class,
                type_definition: metadata.type_definition,
            };

            if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, ref_desc) {
                cp.nodes.push_back(c);
            }
        }

        if !cp.nodes.is_empty() {
            node_to_browse.set_next_continuation_point(Box::new(cp));
        }
    }

    fn browse_namespace_node(
        &self,
        node_to_browse: &mut BrowseNode,
        type_tree: &TypeTree,
        namespaces: &BTreeMap<String, NamespaceMetadata>,
        ns_node: &NamespaceNode,
    ) {
        let Some(namespace) = namespaces.get(&ns_node.namespace) else {
            node_to_browse.set_status(StatusCode::BadNodeIdUnknown);
            return;
        };

        if ns_node.property.is_some() {
            self.browse_namespace_property_node(node_to_browse, type_tree, namespace);
        } else {
            self.browse_namespace_metadata_node(node_to_browse, type_tree, namespace);
        }
    }

    fn read_namespace_metadata_node(
        &self,
        start_time: DateTime,
        node_to_read: &mut ReadNode,
        namespace: &NamespaceMetadata,
    ) {
        let v: Variant = match node_to_read.node().attribute_id {
            AttributeId::NodeId => as_opaque_node_id(
                &DiagnosticsNode::Namespace(NamespaceNode {
                    namespace: namespace.namespace_uri.clone(),
                    property: None,
                }),
                self.namespace_index,
            )
            .unwrap()
            .into(),
            AttributeId::NodeClass => (NodeClass::Object as i32).into(),
            AttributeId::BrowseName => {
                QualifiedName::new(namespace.namespace_index, &namespace.namespace_uri).into()
            }
            AttributeId::DisplayName => LocalizedText::new("", &namespace.namespace_uri).into(),
            AttributeId::EventNotifier => 0u8.into(),
            AttributeId::WriteMask | AttributeId::UserWriteMask => 0u32.into(),
            _ => {
                node_to_read.set_error(StatusCode::BadAttributeIdInvalid);
                return;
            }
        };

        node_to_read.set_result(DataValue {
            value: Some(v),
            status: Some(StatusCode::Good),
            source_timestamp: Some(start_time.clone()),
            source_picoseconds: None,
            server_timestamp: Some(start_time.clone()),
            server_picoseconds: None,
        });
    }

    fn read_namespace_property_node(
        &self,
        start_time: DateTime,
        node_to_read: &mut ReadNode,
        namespace: &NamespaceMetadata,
        prop: &str,
    ) {
        if !matches!(
            prop,
            "DefaultAccessRestrictions"
                | "DefaultRolePermissions"
                | "DefaultUserRolePermissions"
                | "IsNamespaceSubset"
                | "NamespacePublicationDate"
                | "NamespaceUri"
                | "NamespaceVersion"
                | "StaticNodeIdTypes"
                | "StaticNumericNodeIdRange"
                | "StaticStringNodeIdPattern"
        ) {
            node_to_read.set_error(StatusCode::BadNodeIdUnknown);
            return;
        }

        let v: Variant = match node_to_read.node().attribute_id {
            AttributeId::NodeId => as_opaque_node_id(
                &DiagnosticsNode::Namespace(NamespaceNode {
                    namespace: namespace.namespace_uri.clone(),
                    property: Some(prop.to_owned()),
                }),
                self.namespace_index,
            )
            .unwrap()
            .into(),
            AttributeId::NodeClass => (NodeClass::Object as i32).into(),
            AttributeId::BrowseName => QualifiedName::new(0, prop).into(),
            AttributeId::DisplayName => LocalizedText::new("", prop).into(),
            AttributeId::Value => match prop {
                "DefaultAccessRestrictions" => namespace.default_access_restrictions.bits().into(),
                "DefaultRolePermissions" => namespace
                    .default_role_permissions
                    .as_ref()
                    .map(|r| {
                        r.iter()
                            .map(|v| {
                                ExtensionObject::from_encodable(
                                    ObjectId::RolePermissionType_Encoding_DefaultBinary,
                                    v,
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .into(),
                "DefaultUserRolePermissions" => namespace
                    .default_user_role_permissions
                    .as_ref()
                    .map(|r| {
                        r.iter()
                            .map(|v| {
                                ExtensionObject::from_encodable(
                                    ObjectId::RolePermissionType_Encoding_DefaultBinary,
                                    v,
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .into(),
                "IsNamespaceSubset" => namespace.is_namespace_subset.into(),
                "NamespacePublicationDate" => namespace.namespace_publication_date.into(),
                "NamespaceUri" => namespace.namespace_uri.clone().into(),
                "NamespaceVersion" => namespace.namespace_version.clone().into(),
                "StaticNodeIdTypes" => namespace
                    .static_node_id_types
                    .as_ref()
                    .map(|r| r.iter().map(|v| (*v) as u8).collect::<Vec<_>>())
                    .into(),
                "StaticNumericNodeIdRange" => namespace
                    .static_numeric_node_id_range
                    .as_ref()
                    .map(|r| r.iter().map(|v| v.as_string()).collect::<Vec<_>>())
                    .into(),
                "StaticStringNodeIdPattern" => {
                    namespace.static_string_node_id_pattern.clone().into()
                }
                _ => {
                    node_to_read.set_error(StatusCode::BadNodeIdUnknown);
                    return;
                }
            },
            AttributeId::DataType => match prop {
                "DefaultAccessRestrictions" => {
                    Variant::NodeId(Box::new(DataTypeId::AccessRestrictionType.into()))
                }
                "DefaultRolePermissions" | "DefaultUserRolePermissions" => {
                    Variant::NodeId(Box::new(DataTypeId::RolePermissionType.into()))
                }
                "IsNamespaceSubset" => Variant::NodeId(Box::new(DataTypeId::Boolean.into())),
                "NamespacePublicationDate" => {
                    Variant::NodeId(Box::new(DataTypeId::DateTime.into()))
                }
                "NamespaceUri" | "NamespaceVersion" | "StaticStringNodeIdPattern" => {
                    Variant::NodeId(Box::new(DataTypeId::String.into()))
                }
                "StaticNodeIdTypes" => Variant::NodeId(Box::new(DataTypeId::IdType.into())),
                "StaticNumericNodeIdRange" => {
                    Variant::NodeId(Box::new(DataTypeId::NumericRange.into()))
                }
                _ => {
                    node_to_read.set_error(StatusCode::BadNodeIdUnknown);
                    return;
                }
            },
            AttributeId::ValueRank => match prop {
                "DefaultRolePermissions" | "DefaultUserRolePermissions" | "StaticNodeIdTypes" => {
                    1.into()
                }
                _ => (-1).into(),
            },
            AttributeId::ArrayDimensions => match prop {
                "DefaultRolePermissions" | "DefaultUserRolePermissions" | "StaticNodeIdTypes" => {
                    vec![0u32].into()
                }
                _ => Variant::Empty,
            },
            AttributeId::AccessLevel | AttributeId::UserAccessLevel => {
                AccessLevel::CURRENT_READ.bits().into()
            }
            AttributeId::AccessLevelEx => AccessLevelExType::CurrentRead.bits().into(),
            AttributeId::MinimumSamplingInterval => 0.0.into(),
            AttributeId::Historizing => false.into(),
            AttributeId::WriteMask | AttributeId::UserWriteMask => 0u32.into(),
            _ => {
                node_to_read.set_error(StatusCode::BadAttributeIdInvalid);
                return;
            }
        };

        node_to_read.set_result(DataValue {
            value: Some(v),
            status: Some(StatusCode::Good),
            source_timestamp: Some(start_time.clone()),
            source_picoseconds: None,
            server_timestamp: Some(start_time.clone()),
            server_picoseconds: None,
        });
    }

    fn read_namespace_node(
        &self,
        start_time: DateTime,
        node_to_read: &mut ReadNode,
        namespaces: &BTreeMap<String, NamespaceMetadata>,
        ns_node: &NamespaceNode,
    ) {
        let Some(namespace) = namespaces.get(&ns_node.namespace) else {
            node_to_read.set_error(StatusCode::BadNodeIdUnknown);
            return;
        };

        if let Some(prop) = &ns_node.property {
            self.read_namespace_property_node(start_time, node_to_read, namespace, prop);
        } else {
            self.read_namespace_metadata_node(start_time, node_to_read, namespace);
        }
    }
}

#[async_trait]
impl NodeManager for DiagnosticsNodeManager {
    fn owns_node(&self, id: &NodeId) -> bool {
        id.namespace == self.namespace_index
    }

    fn name(&self) -> &str {
        "diagnostics"
    }

    fn namespaces_for_user(&self, context: &RequestContext) -> Vec<NamespaceMetadata> {
        vec![NamespaceMetadata {
            namespace_uri: context.info.application_uri.as_ref().to_owned(),
            is_namespace_subset: Some(false),
            static_node_id_types: Some(vec![IdType::Opaque]),
            namespace_index: self.namespace_index,
            ..Default::default()
        }]
    }

    async fn init(&self, _type_tree: &mut TypeTree, context: ServerContext) {
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
    }

    async fn browse(
        &self,
        context: &RequestContext,
        nodes_to_browse: &mut [BrowseNode],
    ) -> Result<(), StatusCode> {
        let mut lazy_namespaces = None::<BTreeMap<String, NamespaceMetadata>>;
        let type_tree = trace_read_lock!(context.type_tree);

        for node in nodes_to_browse {
            if let Some(mut point) = node.take_continuation_point::<BrowseContinuationPoint>() {
                if node.remaining() <= 0 {
                    break;
                }
                let Some(ref_desc) = point.nodes.pop_back() else {
                    break;
                };
                // Node is already filtered.
                node.add_unchecked(ref_desc);
                continue;
            }

            if node.node_id().namespace == 0 {
                let namespaces = lazy_namespaces.get_or_insert_with(|| self.namespaces(context));
                let Ok(obj_id) = node.node_id().as_object_id() else {
                    continue;
                };
                match obj_id {
                    ObjectId::Server_Namespaces => {
                        self.browse_namespaces(node, &type_tree, namespaces);
                    }
                    _ => continue,
                }
            } else if node.node_id().namespace == self.namespace_index {
                let Some(node_desc) = from_opaque_node_id::<DiagnosticsNode>(node.node_id()) else {
                    node.set_status(StatusCode::BadNodeIdUnknown);
                    continue;
                };
                match node_desc {
                    DiagnosticsNode::Namespace(ns) => {
                        let namespaces =
                            lazy_namespaces.get_or_insert_with(|| self.namespaces(context));
                        self.browse_namespace_node(node, &type_tree, namespaces, &ns);
                    }
                }
            }
        }

        Ok(())
    }

    async fn read(
        &self,
        context: &RequestContext,
        _max_age: f64,
        _timestamps_to_return: TimestampsToReturn,
        nodes_to_read: &mut [&mut ReadNode],
    ) -> Result<(), StatusCode> {
        let mut lazy_namespaces = None::<BTreeMap<String, NamespaceMetadata>>;
        let start_time = **context.info.start_time.load();

        for node in nodes_to_read {
            let Some(node_desc) = from_opaque_node_id::<DiagnosticsNode>(&node.node().node_id)
            else {
                node.set_error(StatusCode::BadNodeIdUnknown);
                continue;
            };
            match node_desc {
                DiagnosticsNode::Namespace(ns) => {
                    let namespaces =
                        lazy_namespaces.get_or_insert_with(|| self.namespaces(context));
                    self.read_namespace_node(start_time, node, namespaces, &ns);
                }
            }
        }
        Ok(())
    }
}
