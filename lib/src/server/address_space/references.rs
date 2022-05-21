// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::collections::{HashMap, HashSet};

use crate::types::*;

/// The `NodeId` is the target node. The reference is held in a list by the source node.
/// The target node does not need to exist.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Reference {
    pub reference_type: NodeId,
    pub target_node: NodeId,
}

impl Reference {
    pub fn new<T>(reference_type: T, target_node: NodeId) -> Reference
    where
        T: Into<NodeId>,
    {
        Reference {
            reference_type: reference_type.into(),
            target_node,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ReferenceDirection {
    Forward,
    Inverse,
}

pub struct References {
    /// The references map contains all forward references, i.e. the key is the node that has
    /// a reference to one or more other nodes.
    references_map: HashMap<NodeId, Vec<Reference>>,
    /// The referenced by map allows a reverse lookup, to find what nodes this node is referenced
    /// by. It is not the same as an inverse reference. A node may be referenced one or more
    /// times by the other node.
    referenced_by_map: HashMap<NodeId, HashSet<NodeId>>,
}

impl Default for References {
    fn default() -> Self {
        Self {
            references_map: HashMap::with_capacity(2000),
            referenced_by_map: HashMap::with_capacity(2000),
        }
    }
}

impl References {
    /// Inserts a single reference into the map.
    pub fn insert<T>(
        &mut self,
        source_node: &NodeId,
        references: &[(&NodeId, &T, ReferenceDirection)],
    ) where
        T: Into<NodeId> + Clone,
    {
        references.iter().for_each(|r| {
            // An inverse reference will flip the nodes around
            match r.2 {
                ReferenceDirection::Forward => self.insert_reference(source_node, r.0, r.1),
                ReferenceDirection::Inverse => self.insert_reference(r.0, source_node, r.1),
            };
        });
    }

    /// For testing purposes, tests if the node exists anywhere in either direction. This test
    /// just scans everything, looking for any mention of the node. Useful for tests which delete
    /// nodes and expect them to be completely gone.
    #[cfg(test)]
    pub fn reference_to_node_exists(&self, node_id: &NodeId) -> bool {
        if self.referenced_by_map.contains_key(node_id) {
            debug!("Node {} is a key in references_to_map", node_id);
            true
        } else if self.references_map.contains_key(node_id) {
            debug!("Node {} is a key in references_from_map", node_id);
            true
        } else if self
            .references_map
            .iter()
            .find(|(k, v)| {
                if let Some(r) = v.iter().find(|r| r.target_node == *node_id) {
                    debug!(
                        "Node {} is a value in references_from_map[{}, reference = {:?}",
                        node_id, k, r
                    );
                    true
                } else {
                    false
                }
            })
            .is_some()
        {
            true
        } else if self
            .referenced_by_map
            .iter()
            .find(|(k, v)| {
                if v.contains(node_id) {
                    debug!(
                        "Node {} is a value in referenced_by_map, key {}",
                        node_id, k
                    );
                    true
                } else {
                    false
                }
            })
            .is_some()
        {
            true
        } else {
            false
        }
    }

    pub fn insert_reference<T>(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: &T,
    ) where
        T: Into<NodeId> + Clone,
    {
        if source_node == target_node {
            panic!(
                "Node id from == node id to {}, self reference is not allowed",
                source_node
            );
        }

        let reference_type: NodeId = reference_type.clone().into();
        let reference = Reference::new(reference_type, target_node.clone());

        if let Some(ref mut references) = self.references_map.get_mut(source_node) {
            // Duplicates are possible from the machine generated code, so skip dupes
            if !references.contains(&reference) {
                references.push(reference);
            }
        } else {
            // Some nodes will have more than one reference, so save some reallocs by reserving
            // space for some more.
            let mut references = Vec::with_capacity(8);
            references.push(reference);
            self.references_map.insert(source_node.clone(), references);
        }

        // Add a reverse lookup reference
        if let Some(ref mut lookup_set) = self.referenced_by_map.get_mut(target_node) {
            lookup_set.insert(source_node.clone());
        } else {
            let mut lookup_set = HashSet::new();
            lookup_set.insert(source_node.clone());
            self.referenced_by_map
                .insert(target_node.clone(), lookup_set);
        }
    }

    /// Inserts references into the map.
    pub fn insert_references<T>(&mut self, references: &[(&NodeId, &NodeId, &T)])
    where
        T: Into<NodeId> + Clone,
    {
        references.iter().for_each(|r| {
            self.insert_reference(r.0, r.1, r.2);
        });
    }

    fn remove_node_from_referenced_nodes(
        &mut self,
        nodes_to_check: HashSet<NodeId>,
        node_to_remove: &NodeId,
    ) {
        nodes_to_check.into_iter().for_each(|node_to_check| {
            // Removes any references that refer from the node to check back to the node to remove
            let remove_entry =
                if let Some(ref mut references) = self.references_map.get_mut(&node_to_check) {
                    references.retain(|r| r.target_node != *node_to_remove);
                    references.is_empty()
                } else {
                    false
                };
            if remove_entry {
                self.references_map.remove(&node_to_check);
            }
            // Remove lookup that refer from the node to check back to the node to remove
            let remove_lookup_map =
                if let Some(ref mut lookup_map) = self.referenced_by_map.get_mut(&node_to_check) {
                    lookup_map.remove(node_to_remove);
                    lookup_map.is_empty()
                } else {
                    false
                };
            if remove_lookup_map {
                self.referenced_by_map.remove(&node_to_check);
            }
        });
    }

    /// Deletes a matching references between one node and the target node of the specified
    /// reference type. The function returns true if the reference was found and deleted.
    pub fn delete_reference<T>(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: T,
    ) -> bool
    where
        T: Into<NodeId>,
    {
        let reference_type = reference_type.into();

        let mut deleted = false;
        let mut remove_entry = false;
        // Remove the source node reference
        if let Some(references) = self.references_map.get_mut(source_node) {
            // Make a set of all the nodes that this node references
            let other_nodes_before = references
                .iter()
                .map(|r| r.target_node.clone())
                .collect::<HashSet<NodeId>>();
            // Delete a reference
            references.retain(|r| {
                if r.reference_type == reference_type && r.target_node == *target_node {
                    deleted = true;
                    false
                } else {
                    true
                }
            });
            if references.is_empty() {
                remove_entry = true;
            }

            // Make a set of all nodes that this node references (after removal)
            let other_nodes_after = references
                .iter()
                .map(|r| r.target_node.clone())
                .collect::<HashSet<NodeId>>();

            // If nodes are no longer referenced, then the ones that were removed must also have their
            // references changed.
            let difference = other_nodes_before
                .difference(&other_nodes_after)
                .cloned()
                .collect::<HashSet<NodeId>>();
            if !difference.is_empty() {
                self.remove_node_from_referenced_nodes(difference, source_node);
            }
        }
        if remove_entry {
            self.references_map.remove(source_node);
        }

        deleted
    }

    /// Deletes all references to the node.
    pub fn delete_node_references(&mut self, source_node: &NodeId) -> bool {
        let deleted_references = if let Some(references) = self.references_map.remove(source_node) {
            // Deleted every reference from the node, and clean up the reverse lookup map
            let nodes_referenced = references
                .iter()
                .map(|r| r.target_node.clone())
                .collect::<HashSet<NodeId>>();
            self.remove_node_from_referenced_nodes(nodes_referenced, source_node);
            true
        } else {
            false
        };

        let deleted_lookups = if let Some(lookup_map) = self.referenced_by_map.remove(source_node) {
            self.remove_node_from_referenced_nodes(lookup_map, source_node);
            true
        } else {
            false
        };

        deleted_references || deleted_lookups
    }

    /// Test if a reference relationship exists between one node and another node
    pub fn has_reference<T>(
        &self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: T,
    ) -> bool
    where
        T: Into<NodeId>,
    {
        if let Some(references) = self.references_map.get(source_node) {
            let reference = Reference::new(reference_type.into(), target_node.clone());
            references.contains(&reference)
        } else {
            false
        }
    }

    /// Finds forward references from the node
    pub fn find_references<T>(
        &self,
        source_node: &NodeId,
        reference_filter: Option<(T, bool)>,
    ) -> Option<Vec<Reference>>
    where
        T: Into<NodeId> + Clone,
    {
        if let Some(node_references) = self.references_map.get(source_node) {
            let result = self.filter_references_by_type(node_references, &reference_filter);
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }

    /// Returns inverse references for the target node, i.e if there are references where
    /// `Reference.target_node` matches the supplied target node then return references
    /// where `Reference.target_node` is the source node.
    pub fn find_inverse_references<T>(
        &self,
        target_node: &NodeId,
        reference_filter: Option<(T, bool)>,
    ) -> Option<Vec<Reference>>
    where
        T: Into<NodeId> + Clone,
    {
        if let Some(lookup_map) = self.referenced_by_map.get(target_node) {
            // Iterate all nodes that reference this node, collecting their references
            let mut result = Vec::with_capacity(16);
            lookup_map.iter().for_each(|source_node| {
                if let Some(references) = self.references_map.get(source_node) {
                    let references = references
                        .iter()
                        .filter(|r| r.target_node == *target_node)
                        .map(|r| Reference {
                            reference_type: r.reference_type.clone(),
                            target_node: source_node.clone(),
                        })
                        .collect::<Vec<Reference>>();
                    let mut references =
                        self.filter_references_by_type(&references, &reference_filter);
                    if !references.is_empty() {
                        result.append(&mut references);
                    }
                }
            });
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }

    fn filter_references_by_type<T>(
        &self,
        references: &[Reference],
        reference_filter: &Option<(T, bool)>,
    ) -> Vec<Reference>
    where
        T: Into<NodeId> + Clone,
    {
        match reference_filter {
            None => references.to_owned(),
            Some((reference_type_id, include_subtypes)) => {
                let reference_type_id = reference_type_id.clone().into();
                references
                    .iter()
                    .filter(|r| {
                        self.reference_type_matches(
                            &reference_type_id,
                            &r.reference_type,
                            *include_subtypes,
                        )
                    })
                    .cloned()
                    .collect::<Vec<Reference>>()
            }
        }
    }

    /// Find references optionally to and/or from the specified node id. The browse direction
    /// indicates the desired direction, or both. The reference filter indicates if only references
    /// of a certain type (including sub types) should be fetched.
    pub fn find_references_by_direction<T>(
        &self,
        node: &NodeId,
        browse_direction: BrowseDirection,
        reference_filter: Option<(T, bool)>,
    ) -> (Vec<Reference>, usize)
    where
        T: Into<NodeId> + Clone,
    {
        let mut references = Vec::new();
        let inverse_ref_idx: usize;
        match browse_direction {
            BrowseDirection::Forward => {
                if let Some(mut forward_references) = self.find_references(node, reference_filter) {
                    references.append(&mut forward_references);
                }
                inverse_ref_idx = references.len();
            }
            BrowseDirection::Inverse => {
                inverse_ref_idx = 0;
                if let Some(mut inverse_references) =
                    self.find_inverse_references(node, reference_filter)
                {
                    references.append(&mut inverse_references);
                }
            }
            BrowseDirection::Both => {
                let reference_filter: Option<(NodeId, bool)> =
                    reference_filter.map(|(reference_type, include_subtypes)| {
                        (reference_type.into(), include_subtypes)
                    });
                if let Some(mut forward_references) =
                    self.find_references(node, reference_filter.clone())
                {
                    references.append(&mut forward_references);
                }
                inverse_ref_idx = references.len();
                if let Some(mut inverse_references) =
                    self.find_inverse_references(node, reference_filter)
                {
                    references.append(&mut inverse_references);
                }
            }
            BrowseDirection::Invalid => {
                error!("BrowseDirection::Invalid passed to find_references_by_direction");
                inverse_ref_idx = 0;
            }
        }
        (references, inverse_ref_idx)
    }

    /// Test if a reference type matches another reference type which is potentially a subtype.
    /// If `include_subtypes` is set to true, the function will test if the subttype
    /// for a match.
    pub fn reference_type_matches(
        &self,
        ref_type: &NodeId,
        ref_subtype: &NodeId,
        include_subtypes: bool,
    ) -> bool {
        if ref_type == ref_subtype {
            true
        } else if include_subtypes {
            let has_subtype: NodeId = ReferenceTypeId::HasSubtype.into();

            let mut stack = Vec::with_capacity(20);
            stack.push(ref_type.clone());

            // Search every type and subtype until exhausted
            let mut found = false;
            while let Some(current) = stack.pop() {
                // Get all references to subtypes
                if *ref_subtype == current {
                    found = true;
                    break;
                } else if let Some(references) = self.references_map.get(&current) {
                    let mut subtypes = references
                        .iter()
                        .filter(|r| r.reference_type == has_subtype)
                        .map(|r| r.target_node.clone())
                        .collect::<Vec<NodeId>>();
                    if subtypes.contains(ref_subtype) {
                        found = true;
                        break;
                    }
                    stack.append(&mut subtypes);
                }
            }
            found
        } else {
            false
        }
    }

    pub fn get_type_id(&self, node: &NodeId) -> Option<NodeId> {
        if let Some(references) = self.references_map.get(node) {
            let has_type_definition_id = ReferenceTypeId::HasTypeDefinition.into();
            references
                .iter()
                .find(|r| r.reference_type == has_type_definition_id)
                .map(|reference| reference.target_node.clone())
        } else {
            None
        }
    }
}
