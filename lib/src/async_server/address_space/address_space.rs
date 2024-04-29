use hashbrown::{Equivalent, HashMap, HashSet};

use crate::server::prelude::{NodeId, NodeType, ReferenceDirection};

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

impl<'a> ReferenceRef<'a> {
    fn from_ref(value: &'a Reference, direction: ReferenceDirection) -> Self {
        Self {
            reference_type: &value.reference_type,
            target_node: &value.target_node,
            direction,
        }
    }
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
    pub fn insert<'a>(
        &mut self,
        source: &NodeId,
        references: impl Iterator<Item = (&'a NodeId, impl Into<NodeId> + 'a, ReferenceDirection)>,
    ) {
        for (target, typ, direction) in references {
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
            target_node: target_node.clone(),
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
}

/// Represents an in-memory address space.
pub struct AddressSpace {
    node_map: HashMap<NodeId, NodeType>,
    namespaces: HashMap<usize, String>,
}
