use std::collections::{HashMap, HashSet};

use opcua_types::{
    *,
    service_types::BrowseDirection,
};

/// The `NodeId` is the target node. The reference is held in a list by the source node.
/// The target node does not need to exist.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Reference {
    pub reference_type_id: NodeId,
    pub target_node_id: NodeId,
}

impl Reference {
    pub fn new(reference_type_id: &NodeId, target_node_id: &NodeId) -> Reference {
        Reference {
            reference_type_id: reference_type_id.clone(),
            target_node_id: target_node_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReferenceDirection {
    Forward,
    Inverse,
}

impl Default for References {
    fn default() -> Self {
        Self {
            references_to_map: HashMap::with_capacity(2000),
            references_from_map: HashMap::with_capacity(2000),
            reference_type_subtypes: HashSet::new(),
        }
    }
}

pub(super) struct References {
    /// A map of references where the source node is the key to one or more target nodes. Note this and `references_from_map` are NOT the same
    /// as IsForward/Inverse references. When a reference is added to `references_to_map`, the opposite but equivalent
    /// reference is added to `references_from_map`.
    references_to_map: HashMap<NodeId, Vec<Reference>>,
    /// A map of references where the target node is the key to one or more source nodes.
    references_from_map: HashMap<NodeId, Vec<Reference>>,
    /// A map of subtypes
    reference_type_subtypes: HashSet<(NodeId, NodeId)>,
}

impl References {
    pub fn insert(&mut self, node_id: &NodeId, references: &[(&NodeId, ReferenceTypeId, ReferenceDirection)]) {
        references.iter().for_each(|r| {
            // Test if it is a forward or inverse reference - to flip the node ids around
            let (node_id, target_node) = match r.2 {
                ReferenceDirection::Forward => (node_id, r.0),
                ReferenceDirection::Inverse => (r.0, node_id),
            };
            self.insert_references(&[(node_id, target_node, r.1)]);
        });
    }

    pub fn insert_references(&mut self, references: &[(&NodeId, &NodeId, ReferenceTypeId)]) {
        references.iter().for_each(|reference| {
            let (node_id, target_node_id, reference_type_id) = *reference;
            if node_id == target_node_id {
                panic!("Node id from == node id to {:?}, self reference is not allowed", node_id);
            }
            let reference_type_id = reference_type_id.into();
            Self::add_reference(&mut self.references_to_map, node_id, Reference::new(&reference_type_id, target_node_id));
            Self::add_reference(&mut self.references_from_map, target_node_id, Reference::new(&reference_type_id, node_id));
        });
    }

    /// Adds a reference between one node and a target
    fn add_reference(reference_map: &mut HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference: Reference) {
        if reference_map.contains_key(node_id) {
            let references = reference_map.get_mut(node_id).unwrap();
            references.push(reference);
        } else {
            // Some nodes will have more than one reference, so save some reallocs by reserving
            // space for some more.
            let mut references = Vec::with_capacity(8);
            references.push(reference);
            reference_map.insert(node_id.clone(), references);
        }
    }

    pub fn delete_reference(&mut self, node_id: &NodeId, target_node_id: &NodeId, reference_type_id: ReferenceTypeId) -> bool {
        let mut deleted = false;

        let reference_type_id = reference_type_id.into();
        // Remove the source node reference
        if let Some(references) = self.references_to_map.get_mut(node_id) {
            references.retain(|r| {
                if r.reference_type_id == reference_type_id && r.target_node_id == *target_node_id {
                    deleted = true;
                    false
                } else {
                    true
                }
            });
        }
        // Remove the target node reference
        if let Some(references) = self.references_from_map.get_mut(target_node_id) {
            references.retain(|r| {
                if r.reference_type_id == reference_type_id && r.target_node_id == *node_id {
                    deleted = true;
                    false
                } else {
                    true
                }
            })
        }
        deleted
    }

    pub fn delete_references_to_node(&mut self, node_id: &NodeId) -> bool {
        // Look in the inverse map for the node id that is being deleted
        if let Some(node_references) = self.references_from_map.remove(node_id) {
            // Each reference target node in the inverse reference must be fixed to remove references to
            // the node
            node_references.iter().for_each(|r| {
                if let Some(forward_references) = self.references_to_map.get_mut(&r.target_node_id) {
                    forward_references.retain(|r| {
                        r.target_node_id != *node_id
                    })
                }
            });
            true
        } else {
            false
        }
    }

    /// Test if a reference relationship exists between one node and another node
    pub fn has_reference(&self, node_id: &NodeId, target_node_id: &NodeId, reference_type: ReferenceTypeId) -> bool {
        if let Some(references) = self.references_to_map.get(&node_id) {
            references.contains(&Reference::new(&reference_type.into(), target_node_id))
        } else {
            false
        }
    }

    /// Finds forward references from the specified node
    pub fn find_references_from(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.find_references(&self.references_to_map, node_id, reference_filter)
    }

    /// Finds inverse references, it those that point to the specified node
    pub fn find_references_to(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.find_references(&self.references_from_map, node_id, reference_filter)
    }

    /// Find and filter references that refer to the specified node.
    pub fn find_references(&self, reference_map: &HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        if let Some(ref node_references) = reference_map.get(node_id) {
            let result = self.filter_references_by_type(node_references, reference_filter);
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }

    fn filter_references_by_type(&self, references: &Vec<Reference>, reference_filter: Option<(ReferenceTypeId, bool)>) -> Vec<Reference> {
        if reference_filter.is_none() {
            references.clone()
        } else {
            // Filter by type
            let (reference_type_id, include_subtypes) = reference_filter.unwrap();
            let reference_type_id = reference_type_id.into();
            references.iter()
                .filter(|r| self.reference_type_matches(&reference_type_id, &r.reference_type_id, include_subtypes))
                .cloned()
                .collect::<Vec<Reference>>()
        }
    }

    pub fn find_references_by_direction(&self, node_id: &NodeId, browse_direction: BrowseDirection, reference_filter: Option<(ReferenceTypeId, bool)>) -> (Vec<Reference>, usize) {
        let mut references = Vec::new();
        let inverse_ref_idx: usize;
        match browse_direction {
            BrowseDirection::Forward => {
                if let Some(mut forward_references) = self.find_references_from(node_id, reference_filter) {
                    references.append(&mut forward_references);
                }
                inverse_ref_idx = references.len();
            }
            BrowseDirection::Inverse => {
                inverse_ref_idx = 0;
                if let Some(mut inverse_references) = self.find_references_to(node_id, reference_filter) {
                    references.append(&mut inverse_references);
                }
            }
            BrowseDirection::Both => {
                if let Some(mut forward_references) = self.find_references_from(node_id, reference_filter) {
                    references.append(&mut forward_references);
                }
                inverse_ref_idx = references.len();
                if let Some(mut inverse_references) = self.find_references_to(node_id, reference_filter) {
                    references.append(&mut inverse_references);
                }
            }
        }
        (references, inverse_ref_idx)
    }

    pub fn build_reference_type_subtypes(&mut self) {
        // This is a hard coded hack. It should really be a binary tree where subtypes can be tested
        // by walking up parents.

        // TODO somehow work out subtypes
        let reference_types = vec![
            (ReferenceTypeId::References, ReferenceTypeId::HierarchicalReferences),
            (ReferenceTypeId::References, ReferenceTypeId::HasChild),
            (ReferenceTypeId::References, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::References, ReferenceTypeId::Organizes),
            (ReferenceTypeId::References, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::References, ReferenceTypeId::HasProperty),
            (ReferenceTypeId::References, ReferenceTypeId::HasComponent),
            (ReferenceTypeId::References, ReferenceTypeId::HasOrderedComponent),
            (ReferenceTypeId::References, ReferenceTypeId::HasEventSource),
            (ReferenceTypeId::References, ReferenceTypeId::HasNotifier),
            (ReferenceTypeId::References, ReferenceTypeId::GeneratesEvent),
            (ReferenceTypeId::References, ReferenceTypeId::AlwaysGeneratesEvent),
            (ReferenceTypeId::References, ReferenceTypeId::HasEncoding),
            (ReferenceTypeId::References, ReferenceTypeId::HasModellingRule),
            (ReferenceTypeId::References, ReferenceTypeId::HasDescription),
            (ReferenceTypeId::References, ReferenceTypeId::HasTypeDefinition),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasChild),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::Organizes),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasProperty),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasComponent),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasOrderedComponent),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasEventSource),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasNotifier),
            (ReferenceTypeId::HasChild, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasComponent),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasHistoricalConfiguration),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasProperty),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasOrderedComponent),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasComponent),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasHistoricalConfiguration),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasProperty),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasOrderedComponent),
            (ReferenceTypeId::HasComponent, ReferenceTypeId::HasOrderedComponent),
            (ReferenceTypeId::HasEventSource, ReferenceTypeId::HasNotifier),
            (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasNotifier),
            (ReferenceTypeId::References, ReferenceTypeId::NonHierarchicalReferences),
            (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::GeneratesEvent),
            (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::AlwaysGeneratesEvent),
            (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasEncoding),
            (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasModellingRule),
            (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasDescription),
            (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasTypeDefinition),
            (ReferenceTypeId::GeneratesEvent, ReferenceTypeId::AlwaysGeneratesEvent),
        ];

        self.reference_type_subtypes = reference_types.iter().map(|(r1, r2)| (r1.into(), r2.into())).collect();
    }

    pub fn reference_type_matches(&self, r1: &NodeId, r2: &NodeId, include_subtypes: bool) -> bool {
        if r1 == r2 {
            true
        } else if include_subtypes {
            self.reference_type_subtypes.contains(&(r1.clone(), r2.clone()))
        } else {
            false
        }
    }

    pub fn get_type_id(&self, node_id: &NodeId) -> Option<NodeId> {
        if let Some(references) = self.references_to_map.get(&node_id) {
            let has_type_definition_id = ReferenceTypeId::HasTypeDefinition.into();
            if let Some(reference) = references.iter().find(|r| {
                r.reference_type_id == has_type_definition_id
            }) {
                Some(reference.target_node_id.clone())
            } else {
                None
            }
        } else {
            None
        }
    }
}