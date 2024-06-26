use std::collections::VecDeque;

use hashbrown::{Equivalent, HashMap, HashSet};

use crate::{
    async_server::node_manager::{RequestContext, TypeTree},
    server::prelude::{
        AttributeId, BrowseDirection, DataValue, NodeClass, NodeId, NumericRange, QualifiedName,
        ReadValueId, ReferenceTypeId, StatusCode, TimestampsToReturn, Variant,
    },
};

use super::{HasNodeId, NodeType, UserAccessLevel};

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Reference {
    pub reference_type: NodeId,
    pub target_node: NodeId,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ReferenceDirection {
    Forward,
    Inverse,
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

            let parent = self.references.by_target.get(node_id).and_then(|refs| {
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

                found_ids.push_back((child.target_node.clone(), root_type, path, nc));
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
        let node_id = node_type.node_id().clone();

        self.assert_namespace(&node_id);

        if self.node_exists(&node_id) {
            error!("This node {} already exists", node_id);
            false
        } else {
            // If references are supplied, add them now
            if let Some(references) = references {
                self.references.insert::<T, S>(&node_id, references);
            }
            self.node_map.insert(node_id, node_type);

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
            let node = self.find_node(rf.target_node);
            if let Some(node) = node {
                if node.as_node().browse_name() == &name {
                    return Some(node);
                }
            }
        }
        None
    }

    pub fn find_node_by_browse_path<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b TypeTree,
        direction: BrowseDirection,
        browse_path: &[QualifiedName],
    ) -> Option<&'a NodeType> {
        let Some(mut node) = self.find_node(&source_node) else {
            return None;
        };
        let filter: Option<(NodeId, bool)> = filter.map(|(id, c)| (id.into(), c));
        for path_elem in browse_path {
            let mut found = false;
            for rf in self.find_references(node.node_id(), filter.clone(), type_tree, direction) {
                let child = self.find_node(rf.target_node);
                if let Some(child) = child {
                    if child.as_node().browse_name() == path_elem {
                        node = child;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return None;
            }
        }
        Some(node)
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

    pub fn validate_node_read<'a>(
        &'a self,
        context: &RequestContext,
        node_to_read: &ReadValueId,
    ) -> Result<(&'a NodeType, AttributeId, NumericRange), StatusCode> {
        info!("Validate read {:?}", node_to_read);
        let Some(node) = self.find(&node_to_read.node_id) else {
            debug!(
                "read_node_value result for read node id {}, attribute {} cannot find node",
                node_to_read.node_id, node_to_read.attribute_id
            );
            return Err(StatusCode::BadNodeIdUnknown);
        };

        let Ok(attribute_id) = AttributeId::from_u32(node_to_read.attribute_id) else {
            debug!(
                "read_node_value result for read node id {}, attribute {} is invalid/2",
                node_to_read.node_id, node_to_read.attribute_id
            );
            return Err(StatusCode::BadAttributeIdInvalid);
        };

        let Ok(index_range) = node_to_read.index_range.as_ref().parse::<NumericRange>() else {
            return Err(StatusCode::BadIndexRangeInvalid);
        };

        if !Self::is_readable(context, node, attribute_id) {
            return Err(StatusCode::BadUserAccessDenied);
        }

        if attribute_id != AttributeId::Value && index_range != NumericRange::None {
            return Err(StatusCode::BadIndexRangeDataMismatch);
        }

        if !Self::is_supported_data_encoding(&node_to_read.data_encoding) {
            debug!(
                "read_node_value result for read node id {}, attribute {} is invalid data encoding",
                node_to_read.node_id, node_to_read.attribute_id
            );
            return Err(StatusCode::BadDataEncodingInvalid);
        }

        Ok((node, attribute_id, index_range))
    }

    pub fn read_node_value(
        &self,
        node: &NodeType,
        attribute_id: AttributeId,
        index_range: NumericRange,
        context: &RequestContext,
        node_to_read: &ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let mut result_value = DataValue::null();

        info!("Read {:?} from {}", attribute_id, node.node_id());

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

    pub fn read(
        &self,
        context: &RequestContext,
        node_to_read: &ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let (node, attribute_id, index_range) = match self.validate_node_read(context, node_to_read)
        {
            Ok(n) => n,
            Err(e) => {
                return DataValue {
                    status: Some(e),
                    ..Default::default()
                };
            }
        };

        self.read_node_value(
            node,
            attribute_id,
            index_range,
            context,
            node_to_read,
            max_age,
            timestamps_to_return,
        )
    }

    pub fn delete(&mut self, node_id: &NodeId, delete_target_references: bool) -> Option<NodeType> {
        let n = self.node_map.remove(node_id);
        let source = self.references.by_source.remove(node_id);
        // Remove any outgoing references
        if delete_target_references {
            for rf in source.into_iter().flatten() {
                if let Some(rec) = self.references.by_target.get_mut(&rf.target_node) {
                    rec.remove(&ReferenceKey {
                        reference_type: &rf.reference_type,
                        target_node: node_id,
                    });
                }
            }
        }

        let target = self.references.by_target.remove(node_id);

        // Optionally remove forwards references pointing at this node.
        if delete_target_references {
            for rf in target.into_iter().flatten() {
                if let Some(rec) = self.references.by_source.get_mut(&rf.target_node) {
                    rec.remove(&ReferenceKey {
                        reference_type: &rf.reference_type,
                        target_node: node_id,
                    });
                }
            }
        }

        n
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        async_server::node_manager::TypeTree,
        server::{
            address_space::types::{
                MethodBuilder, NodeBase, NodeType, Object, ObjectBuilder, ObjectTypeBuilder,
                Variable, VariableBuilder,
            },
            prelude::{
                argument::Argument, Array, BrowseDirection, DataTypeId, DecodingOptions,
                EventNotifier, LocalizedText, NodeClass, NodeId, NumericRange, ObjectId,
                ObjectTypeId, QualifiedName, ReferenceTypeId, TimestampsToReturn, UAString,
                Variant, VariantTypeId,
            },
        },
    };

    use super::AddressSpace;

    fn make_sample_address_space() -> AddressSpace {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        crate::server::address_space::populate_address_space(&mut address_space);
        add_sample_vars_to_address_space(&mut address_space);
        address_space
    }

    fn add_sample_vars_to_address_space(address_space: &mut AddressSpace) {
        address_space.add_namespace("urn:test", 1);
        let ns = 1;

        // Create a sample folder under objects folder
        let sample_folder_id = NodeId::next_numeric(ns);
        ObjectBuilder::new(&sample_folder_id, "Sample", "Sample")
            .organized_by(ObjectId::ObjectsFolder)
            .insert(address_space);

        // Add some variables to our sample folder
        let vars = vec![
            Variable::new(&NodeId::new(ns, "v1"), "v1", "v1", 30i32),
            Variable::new(&NodeId::new(ns, 300), "v2", "v2", true),
            Variable::new(&NodeId::new(ns, "v3"), "v3", "v3", "Hello world"),
            Variable::new(&NodeId::new(ns, "v4"), "v4", "v4", 100.123f64),
        ];
        for var in vars {
            let node_id = var.node_id().clone();
            address_space.insert::<_, NodeId>(var, None);
            address_space.insert_reference(
                &sample_folder_id,
                &node_id,
                ReferenceTypeId::HasComponent,
            );
        }
    }

    #[test]
    fn find_root_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find_node(&NodeId::new(0, 84));
        assert!(node_type.is_some());

        let node = node_type.unwrap().as_node();
        assert_eq!(node.node_id(), &NodeId::new(0, 84));
        assert_eq!(node.node_id(), &ObjectId::RootFolder.into());
    }

    #[test]
    fn find_objects_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find(ObjectId::ObjectsFolder);
        assert!(node_type.is_some());
    }

    #[test]
    fn find_types_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find(ObjectId::TypesFolder);
        assert!(node_type.is_some());
    }

    #[test]
    fn find_views_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find(ObjectId::ViewsFolder);
        assert!(node_type.is_some());
    }

    #[test]
    fn find_common_nodes() {
        let address_space = make_sample_address_space();
        let nodes: Vec<NodeId> = vec![
            ObjectId::RootFolder.into(),
            ObjectId::ObjectsFolder.into(),
            ObjectId::TypesFolder.into(),
            ObjectId::ViewsFolder.into(),
            ObjectId::DataTypesFolder.into(),
            DataTypeId::BaseDataType.into(),
            // Types
            DataTypeId::Boolean.into(),
            DataTypeId::ByteString.into(),
            DataTypeId::DataValue.into(),
            DataTypeId::DateTime.into(),
            DataTypeId::DiagnosticInfo.into(),
            DataTypeId::Enumeration.into(),
            DataTypeId::ExpandedNodeId.into(),
            DataTypeId::Guid.into(),
            DataTypeId::LocalizedText.into(),
            DataTypeId::NodeId.into(),
            DataTypeId::Number.into(),
            DataTypeId::QualifiedName.into(),
            DataTypeId::StatusCode.into(),
            DataTypeId::String.into(),
            DataTypeId::Structure.into(),
            DataTypeId::XmlElement.into(),
            DataTypeId::Double.into(),
            DataTypeId::Float.into(),
            DataTypeId::Integer.into(),
            DataTypeId::SByte.into(),
            DataTypeId::Int16.into(),
            DataTypeId::Int32.into(),
            DataTypeId::Int64.into(),
            DataTypeId::Byte.into(),
            DataTypeId::UInt16.into(),
            DataTypeId::UInt32.into(),
            DataTypeId::UInt64.into(),
            ObjectId::OPCBinarySchema_TypeSystem.into(),
            ObjectTypeId::DataTypeSystemType.into(),
            // Refs
            ObjectId::ReferenceTypesFolder.into(),
            ReferenceTypeId::References.into(),
            ReferenceTypeId::HierarchicalReferences.into(),
            ReferenceTypeId::HasChild.into(),
            ReferenceTypeId::HasSubtype.into(),
            ReferenceTypeId::Organizes.into(),
            ReferenceTypeId::NonHierarchicalReferences.into(),
            ReferenceTypeId::HasTypeDefinition.into(),
        ];
        for n in nodes {
            assert!(address_space.find_node(&n).is_some());
        }
    }

    #[test]
    fn object_attributes() {
        let on = NodeId::new(1, "o1");
        let o = Object::new(&on, "Browse01", "Display01", EventNotifier::empty());
        assert_eq!(o.node_class(), NodeClass::Object);
        assert_eq!(o.node_id(), &on);
        assert_eq!(o.browse_name(), &QualifiedName::new(0, "Browse01"));
        assert_eq!(o.display_name(), &LocalizedText::new("", "Display01"));
    }

    #[test]
    fn find_node_by_id() {
        let address_space = make_sample_address_space();
        let ns = 1;

        assert!(!address_space.node_exists(&NodeId::null()));
        assert!(!address_space.node_exists(&NodeId::new(11, "v3")));

        assert!(address_space.node_exists(&NodeId::new(ns, "v1")));
        assert!(address_space.node_exists(&NodeId::new(ns, 300)));
        assert!(address_space.node_exists(&NodeId::new(ns, "v3")));
    }

    #[test]
    fn find_references() {
        let address_space = make_sample_address_space();

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::root_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &TypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(references.len(), 3);

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::root_folder_id(),
                None::<(NodeId, bool)>,
                &TypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(references.len(), 4);

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::objects_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &TypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(references.len(), 2);

        let r1 = &references[0];
        assert_eq!(r1.reference_type, &ReferenceTypeId::Organizes.into());
        let child_node_id = r1.target_node.clone();

        let child = address_space.find_node(&child_node_id);
        assert!(child.is_some());
    }

    #[test]
    fn find_inverse_references() {
        let address_space = make_sample_address_space();

        //println!("{:#?}", address_space);
        let references: Vec<_> = address_space
            .find_references(
                &NodeId::root_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &TypeTree::new(),
                BrowseDirection::Inverse,
            )
            .collect();
        assert!(references.is_empty());

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::objects_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &TypeTree::new(),
                BrowseDirection::Inverse,
            )
            .collect();
        assert_eq!(references.len(), 1);
    }

    #[test]
    fn find_reference_subtypes() {
        let address_space = make_sample_address_space();
        let mut type_tree = TypeTree::new();
        address_space.load_into_type_tree(&mut type_tree);

        let reference_types = vec![
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HierarchicalReferences,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasChild),
            (ReferenceTypeId::References, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::References, ReferenceTypeId::Organizes),
            (ReferenceTypeId::References, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::References, ReferenceTypeId::HasProperty),
            (ReferenceTypeId::References, ReferenceTypeId::HasComponent),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasEventSource),
            (ReferenceTypeId::References, ReferenceTypeId::HasNotifier),
            (ReferenceTypeId::References, ReferenceTypeId::GeneratesEvent),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::AlwaysGeneratesEvent,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasEncoding),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HasModellingRule,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasDescription),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HasTypeDefinition,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasChild,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasSubtype,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::Organizes,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::Aggregates,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasProperty,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasComponent,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasEventSource,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasNotifier,
            ),
            (ReferenceTypeId::HasChild, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasComponent),
            (
                ReferenceTypeId::HasChild,
                ReferenceTypeId::HasHistoricalConfiguration,
            ),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasProperty),
            (
                ReferenceTypeId::HasChild,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasComponent),
            (
                ReferenceTypeId::Aggregates,
                ReferenceTypeId::HasHistoricalConfiguration,
            ),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasProperty),
            (
                ReferenceTypeId::Aggregates,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (
                ReferenceTypeId::HasComponent,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (
                ReferenceTypeId::HasEventSource,
                ReferenceTypeId::HasNotifier,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasNotifier,
            ),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::NonHierarchicalReferences,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::GeneratesEvent,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::AlwaysGeneratesEvent,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasEncoding,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasModellingRule,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasDescription,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasTypeDefinition,
            ),
            (
                ReferenceTypeId::GeneratesEvent,
                ReferenceTypeId::AlwaysGeneratesEvent,
            ),
        ];

        // Make sure that subtypes match when subtypes are to be compared and doesn't when they should
        // not be compared.
        reference_types.iter().for_each(|r| {
            let r1 = r.0.into();
            let r2 = r.1.into();
            assert!(type_tree.is_subtype_of(&r2, &r1));
        });
    }

    /// This test is to ensure that adding a Variable with a value of Array to address space sets the
    /// ValueRank and ArrayDimensions attributes correctly.
    #[test]
    fn array_as_variable() {
        // 1 dimensional array with 100 element
        let values = (0..100)
            .map(|i| Variant::Int32(i))
            .collect::<Vec<Variant>>();

        // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
        let node_id = NodeId::new(2, 1);
        let v = Variable::new(&node_id, "x", "x", (VariantTypeId::Int32, values));

        let value_rank = v.value_rank();
        assert_eq!(value_rank, 1);
        let array_dimensions = v.array_dimensions().unwrap();
        assert_eq!(array_dimensions, vec![100u32]);
    }

    /// This test is to ensure that adding a Variable with a value of Array to address space sets the
    /// ValueRank and ArrayDimensions attributes correctly.
    #[test]
    fn multi_dimension_array_as_variable() {
        // 2 dimensional array with 10x10 elements

        let values = (0..100)
            .map(|i| Variant::Int32(i))
            .collect::<Vec<Variant>>();
        let mda = Array::new_multi(VariantTypeId::Int32, values, vec![10u32, 10u32]).unwrap();
        assert!(mda.is_valid());

        // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
        let node_id = NodeId::new(2, 1);
        let v = Variable::new(&node_id, "x", "x", mda);

        let value_rank = v.value_rank();
        assert_eq!(value_rank, 2);
        let array_dimensions = v.array_dimensions().unwrap();
        assert_eq!(array_dimensions, vec![10u32, 10u32]);
    }

    #[test]
    fn browse_nodes() {
        let address_space = make_sample_address_space();

        // Test that a node can be found
        let object_id = ObjectId::RootFolder.into();
        let result = address_space.find_node_by_browse_path(
            &object_id,
            None::<(NodeId, bool)>,
            &TypeTree::new(),
            BrowseDirection::Forward,
            &["Objects".into(), "Sample".into(), "v1".into()],
        );
        let node = result.unwrap();
        assert_eq!(node.as_node().browse_name(), &QualifiedName::from("v1"));

        // Test that a non existent node cannot be found
        let result = address_space.find_node_by_browse_path(
            &object_id,
            None::<(NodeId, bool)>,
            &TypeTree::new(),
            BrowseDirection::Forward,
            &["Objects".into(), "Sample".into(), "vxxx".into()],
        );
        assert!(result.is_none());
    }

    #[test]
    fn object_builder() {
        let mut address_space = make_sample_address_space();

        let node_type_id = NodeId::new(1, "HelloType");
        let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

        let node_id = NodeId::new(1, "Hello");
        let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
            .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
            .organized_by(ObjectId::ObjectsFolder)
            .has_type_definition(node_type_id.clone())
            .insert(&mut address_space);

        // Verify the variable is there
        let _o = match address_space.find_node(&node_id).unwrap() {
            NodeType::Object(o) => o,
            _ => panic!(),
        };

        // Verify the reference to the objects folder is there
        assert!(address_space.has_reference(
            &ObjectId::ObjectsFolder.into(),
            &node_id,
            ReferenceTypeId::Organizes
        ));
        assert!(address_space.has_reference(
            &node_id,
            &node_type_id,
            ReferenceTypeId::HasTypeDefinition
        ));
    }

    #[test]
    fn object_type_builder() {
        let mut address_space = make_sample_address_space();

        let node_type_id = NodeId::new(1, "HelloType");
        let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

        let _ot = match address_space.find_node(&node_type_id).unwrap() {
            NodeType::ObjectType(ot) => ot,
            _ => panic!(),
        };

        assert!(address_space.has_reference(
            &ObjectTypeId::BaseObjectType.into(),
            &node_type_id,
            ReferenceTypeId::HasSubtype
        ));
    }

    #[test]
    fn variable_builder() {
        let result = std::panic::catch_unwind(|| {
            // This should panic
            let _v = VariableBuilder::new(&NodeId::null(), "", "").build();
        });
        assert!(result.is_err());

        // This should build
        let _v = VariableBuilder::new(&NodeId::new(1, 1), "", "")
            .data_type(DataTypeId::Boolean)
            .build();

        // Check a variable with a bunch of fields set
        let v = VariableBuilder::new(&NodeId::new(1, "Hello"), "BrowseName", "DisplayName")
            .description("Desc")
            .data_type(DataTypeId::UInt32)
            .value_rank(10)
            .array_dimensions(&[1, 2, 3])
            .historizing(true)
            .value(Variant::from(999))
            .minimum_sampling_interval(123.0)
            .build();

        assert_eq!(v.node_id(), &NodeId::new(1, "Hello"));
        assert_eq!(v.browse_name(), &QualifiedName::new(0, "BrowseName"));
        assert_eq!(v.display_name(), &LocalizedText::new("", "DisplayName"));
        assert_eq!(v.data_type(), DataTypeId::UInt32.into());
        assert_eq!(v.description().unwrap(), &LocalizedText::new("", "Desc"));
        assert_eq!(v.value_rank(), 10);
        assert_eq!(v.array_dimensions().unwrap(), vec![1, 2, 3]);
        assert_eq!(v.historizing(), true);
        assert_eq!(
            v.value(
                TimestampsToReturn::Neither,
                NumericRange::None,
                &QualifiedName::null(),
                0.0
            )
            .value
            .unwrap(),
            Variant::from(999)
        );
        assert_eq!(v.minimum_sampling_interval().unwrap(), 123.0);

        // Add a variable to the address space

        let mut address_space = make_sample_address_space();
        let node_id = NodeId::new(1, "Hello");
        let _v = VariableBuilder::new(&node_id, "BrowseName", "DisplayName")
            .description("Desc")
            .value_rank(10)
            .data_type(DataTypeId::UInt32)
            .array_dimensions(&[1, 2, 3])
            .historizing(true)
            .value(Variant::from(999))
            .minimum_sampling_interval(123.0)
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut address_space);

        // Verify the variable is there
        assert!(address_space.find_node(&node_id).is_some());
        // Verify the reference to the objects folder is there
        assert!(address_space.has_reference(
            &ObjectId::ObjectsFolder.into(),
            &node_id,
            ReferenceTypeId::Organizes
        ));
    }

    #[test]
    fn method_builder() {
        let mut address_space = make_sample_address_space();

        address_space.add_namespace("urn:test", 1);
        let ns = 1;

        let object_id: NodeId = ObjectId::ObjectsFolder.into();

        let fn_node_id = NodeId::new(ns, "HelloWorld");

        let inserted = MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
            .component_of(object_id.clone())
            .output_args(&mut address_space, &[("Result", DataTypeId::String).into()])
            .insert(&mut address_space);
        assert!(inserted);

        assert!(matches!(
            address_space.find_node(&fn_node_id),
            Some(NodeType::Method(_))
        ));

        let refs: Vec<_> = address_space
            .find_references(
                &fn_node_id,
                Some((ReferenceTypeId::HasProperty, false)),
                &TypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(refs.len(), 1);

        let child = address_space
            .find_node(&refs.get(0).unwrap().target_node)
            .unwrap();
        if let NodeType::Variable(v) = child {
            // verify OutputArguments
            // verify OutputArguments / Argument value
            assert_eq!(v.data_type(), DataTypeId::Argument.into());
            assert_eq!(v.display_name(), &LocalizedText::from("OutputArguments"));
            let v = v
                .value(
                    TimestampsToReturn::Neither,
                    NumericRange::None,
                    &QualifiedName::null(),
                    0.0,
                )
                .value
                .unwrap();
            if let Variant::Array(array) = v {
                let v = array.values;
                assert_eq!(v.len(), 1);
                let v = v.get(0).unwrap().clone();
                if let Variant::ExtensionObject(v) = v {
                    // deserialize the Argument here
                    let decoding_options = DecodingOptions::test();
                    let argument = v.decode_inner::<Argument>(&decoding_options).unwrap();
                    assert_eq!(argument.name, UAString::from("Result"));
                    assert_eq!(argument.data_type, DataTypeId::String.into());
                    assert_eq!(argument.value_rank, -1);
                    assert_eq!(argument.array_dimensions, None);
                    assert_eq!(argument.description, LocalizedText::null());
                } else {
                    panic!("Variant was expected to be extension object, was {:?}", v);
                }
            } else {
                panic!("Variant was expected to be array, was {:?}", v);
            }
        } else {
            panic!();
        }
    }

    #[test]
    fn simple_delete_node() {
        crate::console_logging::init();

        // This is a super basic, debuggable delete test. There is a single Root node, and a
        // child object. After deleting the child, only the Root should exist with no references at
        // all to the child.

        // A blank address space, with nothing at all in it
        let mut address_space = make_sample_address_space();

        // Add a root node
        let root_node = NodeId::root_folder_id();

        let node = Object::new(&root_node, "Root", "", EventNotifier::empty());
        let _ = address_space.insert::<Object, ReferenceTypeId>(node, None);

        let node_id = NodeId::new(1, "Hello");
        let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
            .organized_by(root_node.clone())
            .insert(&mut address_space);

        // Verify the object and refs are there
        assert!(address_space.find_node(&node_id).is_some());
        assert!(address_space.has_reference(&root_node, &node_id, ReferenceTypeId::Organizes));

        // Try one time deleting references, the other time not deleting them.
        address_space.delete(&node_id, true);
        // Delete the node and the refs
        assert!(address_space.find_node(&node_id).is_none());
        assert!(address_space.find_node(&root_node).is_some());
        assert!(!address_space.has_reference(&root_node, &node_id, ReferenceTypeId::Organizes));
    }

    #[test]
    fn delete_node() {
        crate::console_logging::init();

        // Try creating and deleting a node, verifying that it's totally gone afterwards
        (0..2).for_each(|i| {
            let mut address_space = make_sample_address_space();

            let node_type_id = NodeId::new(1, "HelloType");
            let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
                .subtype_of(ObjectTypeId::BaseObjectType)
                .insert(&mut address_space);

            let node_id = NodeId::new(1, "Hello");
            let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
                .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
                .organized_by(ObjectId::ObjectsFolder)
                .has_type_definition(node_type_id.clone())
                .insert(&mut address_space);

            // Verify the object and refs are there
            assert!(address_space.find_node(&node_id).is_some());
            assert!(address_space.has_reference(
                &ObjectId::ObjectsFolder.into(),
                &node_id,
                ReferenceTypeId::Organizes
            ));
            assert!(!address_space.has_reference(
                &node_id,
                &ObjectId::ObjectsFolder.into(),
                ReferenceTypeId::Organizes
            ));
            assert!(address_space.has_reference(
                &node_id,
                &node_type_id,
                ReferenceTypeId::HasTypeDefinition
            ));

            // Try one time deleting references, the other time not deleting them.
            let delete_target_references = i == 1;
            address_space.delete(&node_id, delete_target_references);
            if !delete_target_references {
                // Deleted the node and outgoing refs, but not incoming refs
                assert!(address_space.find_node(&node_id).is_none());
                assert!(address_space.has_reference(
                    &ObjectId::ObjectsFolder.into(),
                    &node_id,
                    ReferenceTypeId::Organizes
                ));
                assert!(!address_space.has_reference(
                    &node_id,
                    &node_type_id,
                    ReferenceTypeId::HasTypeDefinition
                ));
            } else {
                // Delete the node and the refs
                assert!(address_space.find_node(&node_id).is_none());
                assert!(!address_space.has_reference(
                    &ObjectId::ObjectsFolder.into(),
                    &node_id,
                    ReferenceTypeId::Organizes
                ));
                assert!(!address_space.has_reference(
                    &node_id,
                    &node_type_id,
                    ReferenceTypeId::HasTypeDefinition
                ));
            }
        });
    }
}
