use std::collections::VecDeque;

use hashbrown::{Equivalent, HashMap, HashSet};

use crate::{
    async_server::node_manager::{RequestContext, TypeTree},
    server::{
        address_space::{
            node::{HasNodeId, NodeType},
            references::ReferenceDirection,
        },
        prelude::{
            AttributeId, BrowseDirection, DataValue, NodeClass, NodeId, NumericRange,
            QualifiedName, ReadValueId, ReferenceTypeId, StatusCode, TimestampsToReturn,
            UserAccessLevel, Variant,
        },
    },
};

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Reference {
    pub reference_type: NodeId,
    pub target_node: NodeId,
}

// Note, must have same hash and eq implementation as Reference.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
struct ReferenceKey<'a> {
    pub reference_type: &'a NodeId,
    pub target_node: &'a NodeId,
}

impl<'a> Equivalent<Reference> for ReferenceKey<'a> {
    fn equivalent(&self, key: &Reference) -> bool {
        &key.reference_type == self.reference_type && &key.target_node == self.target_node
    }
}

impl<'a> From<&'a Reference> for ReferenceKey<'a> {
    fn from(value: &'a Reference) -> Self {
        Self {
            reference_type: &value.reference_type,
            target_node: &value.target_node,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct ReferenceRef<'a> {
    pub reference_type: &'a NodeId,
    pub target_node: &'a NodeId,
    pub direction: ReferenceDirection,
}

// Note that there is a potentially significant benefit to using hashbrown directly here,
// (which is what the std HashMap is built on!), since it lets us remove references from
// the hash sets without cloning given node IDs.

pub struct References {
    /// References by source node ID.
    by_source: HashMap<NodeId, HashSet<Reference>>,
    /// References by target node ID.
    by_target: HashMap<NodeId, HashSet<Reference>>,
}

impl References {
    pub fn new() -> Self {
        Self {
            by_source: HashMap::new(),
            by_target: HashMap::new(),
        }
    }

    pub fn insert<'a, T, S>(
        &mut self,
        source: &NodeId,
        references: &'a [(&'a NodeId, &S, ReferenceDirection)],
    ) where
        T: Into<NodeType>,
        S: Into<NodeId> + Clone,
    {
        for (target, typ, direction) in references {
            let typ: NodeId = (*typ).clone().into();
            match direction {
                ReferenceDirection::Forward => self.insert_reference(source, target, typ),
                ReferenceDirection::Inverse => self.insert_reference(target, source, typ),
            }
        }
    }

    pub fn insert_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) {
        if source_node == target_node {
            panic!(
                "Node id from == node id to {}, self reference is not allowed",
                source_node
            );
        }

        let forward_refs = match self.by_source.get_mut(source_node) {
            Some(r) => r,
            None => self.by_source.entry(source_node.clone()).or_default(),
        };

        let reference_type = reference_type.into();

        if !forward_refs.insert(Reference {
            reference_type: reference_type.clone(),
            target_node: target_node.clone(),
        }) {
            // If the reference is already added, no reason to try adding it to the inverse.
            return;
        }

        let inverse_refs = match self.by_target.get_mut(target_node) {
            Some(r) => r,
            None => self.by_target.entry(target_node.clone()).or_default(),
        };

        inverse_refs.insert(Reference {
            reference_type: reference_type,
            target_node: source_node.clone(),
        });
    }

    pub fn insert_references<'a>(
        &mut self,
        references: impl Iterator<Item = (&'a NodeId, &'a NodeId, impl Into<NodeId>)>,
    ) {
        for (source, target, typ) in references {
            self.insert_reference(source, target, typ);
        }
    }

    pub fn delete_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) -> bool {
        let mut found = false;
        let reference_type = reference_type.into();
        let rf = ReferenceKey {
            reference_type: &reference_type,
            target_node: target_node,
        };
        found |= self
            .by_source
            .get_mut(source_node)
            .map(|f| f.remove(&rf))
            .unwrap_or_default();

        let rf = ReferenceKey {
            reference_type: &reference_type,
            target_node: &source_node,
        };

        found |= self
            .by_target
            .get_mut(target_node)
            .map(|f| f.remove(&rf))
            .unwrap_or_default();

        found
    }

    pub fn delete_node_references(&mut self, source_node: &NodeId) -> bool {
        let mut found = false;
        // Remove any forward references and their inverse.
        found |= if let Some(refs) = self.by_source.remove(source_node) {
            for referenced in refs {
                self.by_target.get_mut(&referenced.target_node).map(|n| {
                    n.remove(&ReferenceKey {
                        reference_type: &referenced.reference_type,
                        target_node: source_node,
                    })
                });
            }
            true
        } else {
            false
        };

        // Remove any inverse references and their original.
        found |= if let Some(refs) = self.by_target.remove(source_node) {
            for referenced in refs {
                self.by_source.get_mut(&referenced.target_node).map(|n| {
                    n.remove(&ReferenceKey {
                        reference_type: &referenced.reference_type,
                        target_node: source_node,
                    })
                });
            }
            true
        } else {
            false
        };

        found
    }

    pub fn has_reference(
        &self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) -> bool {
        let reference_type = reference_type.into();
        self.by_source
            .get(source_node)
            .map(|n| {
                n.contains(&ReferenceKey {
                    reference_type: &reference_type,
                    target_node,
                })
            })
            .unwrap_or_default()
    }

    pub fn find_references<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b TypeTree,
        direction: BrowseDirection,
    ) -> impl Iterator<Item = ReferenceRef<'a>> + 'b {
        ReferenceIterator::new(
            source_node,
            direction,
            self,
            filter.map(|f| (f.0.into(), f.1)),
            type_tree,
        )
    }
}

// Handy feature to let us easily return a concrete type from `find_references`.
struct ReferenceIterator<'a, 'b> {
    filter: Option<(NodeId, bool)>,
    type_tree: &'b TypeTree,
    iter_s: Option<hashbrown::hash_set::Iter<'a, Reference>>,
    iter_t: Option<hashbrown::hash_set::Iter<'a, Reference>>,
}

impl<'a, 'b> Iterator for ReferenceIterator<'a, 'b> {
    type Item = ReferenceRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(inner) = self.next_inner() else {
                return None;
            };

            if let Some(filter) = &self.filter {
                if !filter.1 && inner.reference_type != &filter.0
                    || filter.1
                        && !self
                            .type_tree
                            .is_subtype_of(&inner.reference_type, &filter.0)
                {
                    continue;
                }
            }

            break Some(inner);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut lower = 0;
        let mut upper = None;
        if let Some(iter_s) = &self.iter_s {
            let (lower_i, upper_i) = iter_s.size_hint();
            lower = lower_i;
            upper = upper_i;
        }

        if let Some(iter_t) = &self.iter_s {
            let (lower_i, upper_i) = iter_t.size_hint();
            lower += lower_i;
            upper = match (upper, upper_i) {
                (Some(l), Some(r)) => Some(l + r),
                _ => None,
            }
        }

        (lower, upper)
    }
}

impl<'a, 'b> ReferenceIterator<'a, 'b> {
    pub fn new(
        source_node: &'b NodeId,
        direction: BrowseDirection,
        references: &'a References,
        filter: Option<(NodeId, bool)>,
        type_tree: &'b TypeTree,
    ) -> Self {
        Self {
            filter,
            type_tree,
            iter_s: matches!(direction, BrowseDirection::Both | BrowseDirection::Forward)
                .then(|| references.by_source.get(source_node))
                .flatten()
                .map(|r| r.iter()),
            iter_t: matches!(direction, BrowseDirection::Both | BrowseDirection::Inverse)
                .then(|| references.by_target.get(source_node))
                .flatten()
                .map(|r| r.iter()),
        }
    }

    fn next_inner(&mut self) -> Option<ReferenceRef<'a>> {
        if let Some(iter_s) = &mut self.iter_s {
            match iter_s.next() {
                Some(r) => {
                    return Some(ReferenceRef {
                        reference_type: &r.reference_type,
                        target_node: &r.target_node,
                        direction: ReferenceDirection::Forward,
                    })
                }
                None => self.iter_s = None,
            }
        }

        if let Some(iter_t) = &mut self.iter_t {
            match iter_t.next() {
                Some(r) => {
                    return Some(ReferenceRef {
                        reference_type: &r.reference_type,
                        target_node: &r.target_node,
                        direction: ReferenceDirection::Inverse,
                    })
                }
                None => self.iter_t = None,
            }
        }

        None
    }
}

/// Represents an in-memory address space.
pub struct AddressSpace {
    node_map: HashMap<NodeId, NodeType>,
    namespaces: HashMap<u16, String>,
    references: References,
}

impl AddressSpace {
    pub fn new() -> Self {
        Self {
            node_map: HashMap::new(),
            namespaces: HashMap::new(),
            references: References::new(),
        }
    }

    pub fn load_into_type_tree(&self, type_tree: &mut TypeTree) {
        let mut found_ids = VecDeque::new();
        // Populate types first so that we have reference types to browse in the next stage.
        for node in self.node_map.values() {
            let nc = node.node_class();
            if !matches!(
                nc,
                NodeClass::DataType
                    | NodeClass::ObjectType
                    | NodeClass::VariableType
                    | NodeClass::ReferenceType
            ) {
                continue;
            }

            let node_id = node.node_id();

            let parent = self.references.by_target.get(&node_id).and_then(|refs| {
                refs.iter()
                    .find(|r| &r.reference_type == &ReferenceTypeId::HasSubtype.into())
            });
            // If a node somehow lacks a super-type, insert it as a child of the relevant base type.
            let parent_id = if let Some(parent) = parent {
                parent.target_node.clone()
            } else {
                continue;
            };

            type_tree.add_type_node(&node_id, &parent_id, nc);
            found_ids.push_back((node_id.clone(), node_id, Vec::new(), nc));
        }

        // Recursively browse each discovered type for non-type children
        while let Some((node, root_type, path, node_class)) = found_ids.pop_front() {
            for child in self.find_references(
                &node,
                Some((ReferenceTypeId::HierarchicalReferences, true)),
                type_tree,
                BrowseDirection::Forward,
            ) {
                if child
                    .reference_type
                    .as_reference_type_id()
                    .unwrap_or(ReferenceTypeId::HasSubtype)
                    == ReferenceTypeId::HasSubtype
                {
                    continue;
                }
                let Some(node_type) = self.node_map.get(child.target_node) else {
                    continue;
                };

                let nc = node_type.node_class();

                if matches!(
                    nc,
                    NodeClass::DataType
                        | NodeClass::ObjectType
                        | NodeClass::VariableType
                        | NodeClass::ReferenceType
                ) {
                    continue;
                }
                let mut path = path.clone();
                path.push(node_type.as_node().browse_name());

                found_ids.push_back((child.target_node.clone(), root_type.clone(), path, nc));
            }

            if !path.is_empty() {
                type_tree.add_type_property(&node, &root_type, &path, node_class);
            }
        }
    }

    pub fn add_namespace(&mut self, namespace: &str, index: u16) {
        self.namespaces.insert(index, namespace.to_string());
    }

    pub fn insert<'a, T, S>(
        &mut self,
        node: T,
        references: Option<&'a [(&'a NodeId, &S, ReferenceDirection)]>,
    ) -> bool
    where
        T: Into<NodeType>,
        S: Into<NodeId> + Clone,
    {
        let node_type = node.into();
        let node_id = node_type.node_id();

        self.assert_namespace(&node_id);

        if self.node_exists(&node_id) {
            error!("This node {} already exists", node_id);
            false
        } else {
            self.node_map.insert(node_id.clone(), node_type);
            // If references are supplied, add them now
            if let Some(references) = references {
                self.references.insert::<T, S>(&node_id, references);
            }
            true
        }
    }

    pub fn namespace_index(&self, namespace: &str) -> Option<u16> {
        self.namespaces
            .iter()
            .find(|(_, ns)| namespace == ns.as_str())
            .map(|(i, _)| *i)
    }

    fn assert_namespace(&self, node_id: &NodeId) {
        if !self.namespaces.contains_key(&node_id.namespace) {
            panic!("Namespace index {} not in address space", node_id.namespace);
        }
    }

    pub fn node_exists(&self, node_id: &NodeId) -> bool {
        self.node_map.contains_key(node_id)
    }

    pub fn insert_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) {
        self.references
            .insert_reference(source_node, target_node, reference_type)
    }

    pub fn insert_references<'a>(
        &mut self,
        references: impl Iterator<Item = (&'a NodeId, &'a NodeId, impl Into<NodeId>)>,
    ) {
        self.references.insert_references(references)
    }

    pub fn delete_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) -> bool {
        self.references
            .delete_reference(source_node, target_node, reference_type)
    }

    pub fn delete_node_references(&mut self, source_node: &NodeId) -> bool {
        self.references.delete_node_references(source_node)
    }

    pub fn has_reference(
        &self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) -> bool {
        self.references
            .has_reference(source_node, target_node, reference_type)
    }

    pub fn find_references<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b TypeTree,
        direction: BrowseDirection,
    ) -> impl Iterator<Item = ReferenceRef<'a>> + 'b {
        self.references
            .find_references(source_node, filter, type_tree, direction)
    }

    pub fn find_node_by_browse_name<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b TypeTree,
        direction: BrowseDirection,
        browse_name: impl Into<QualifiedName>,
    ) -> Option<&'a NodeType> {
        let name = browse_name.into();
        for rf in self.find_references(source_node, filter, type_tree, direction) {
            let node = self.find_node(&rf.target_node);
            if let Some(node) = node {
                if node.as_node().browse_name() == name {
                    return Some(node);
                }
            }
        }
        None
    }

    pub fn namespaces(&self) -> &HashMap<u16, String> {
        &self.namespaces
    }

    /// Find node by something that can be turned into a node id and return a reference to it.
    pub fn find<N>(&self, node_id: N) -> Option<&NodeType>
    where
        N: Into<NodeId>,
    {
        self.find_node(&node_id.into())
    }

    /// Find node by something that can be turned into a node id and return a mutable reference to it.
    pub fn find_mut<N>(&mut self, node_id: N) -> Option<&mut NodeType>
    where
        N: Into<NodeId>,
    {
        self.find_node_mut(&node_id.into())
    }

    /// Finds a node by its node id and returns a reference to it.
    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeType> {
        self.node_map.get(node_id)
    }

    /// Finds a node by its node id and returns a mutable reference to it.
    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeType> {
        self.node_map.get_mut(node_id)
    }

    fn is_readable(context: &RequestContext, node: &NodeType, attribute_id: AttributeId) -> bool {
        Self::user_access_level(context, node, attribute_id).contains(UserAccessLevel::CURRENT_READ)
    }

    fn is_supported_data_encoding(data_encoding: &QualifiedName) -> bool {
        if data_encoding.is_null() {
            true
        } else {
            data_encoding.namespace_index == 0 && data_encoding.name.eq("Default Binary")
        }
    }

    pub fn user_access_level(
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

    pub fn read_node_value(
        &self,
        context: &RequestContext,
        node_to_read: &ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        is_valid_request: &mut bool,
    ) -> DataValue {
        let mut result_value = DataValue::null();
        let Some(node) = self.find(&node_to_read.node_id) else {
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
            result_value.status = Some(StatusCode::BadUserAccessDenied);
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

        *is_valid_request = true;

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

        let value = if attribute_id == AttributeId::UserExecutable {
            match value {
                Some(Variant::Boolean(val)) => Some(Variant::from(
                    val && context
                        .authenticator
                        .is_user_executable(&context.token, &node.node_id()),
                )),
                r => r,
            }
        } else {
            value
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
}
