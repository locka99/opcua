use crate::{
    async_server::session::continuation_points::{ContinuationPoint, EmptyContinuationPoint},
    server::prelude::{
        random, BrowseDescription, BrowseDescriptionResultMask, BrowseDirection, BrowsePath,
        BrowsePathTarget, BrowseResult, ByteString, ExpandedNodeId, LocalizedText, NodeClass,
        NodeClassMask, NodeId, QualifiedName, ReferenceDescription, StatusCode,
    },
};

use super::type_tree::TypeTree;

/// Container for a node being browsed and the result of the browse operation.
pub struct BrowseNode {
    node_id: NodeId,
    browse_direction: BrowseDirection,
    reference_type_id: NodeId,
    include_subtypes: bool,
    node_class_mask: NodeClassMask,
    result_mask: BrowseDescriptionResultMask,
    references: Vec<ReferenceDescription>,
    status_code: StatusCode,
    // It is feasible to only keep one continuation point, by using the
    // fact that node managers are sequential. If the first node manager is done reading,
    // we move on to the next.
    // All we need to do is keep track of which node manager made the last continuation point.
    input_continuation_point: Option<ContinuationPoint>,
    next_continuation_point: Option<ContinuationPoint>,
    max_references_per_node: usize,
    input_index: usize,
    pub(crate) start_node_manager: usize,
}

pub struct BrowseContinuationPoint {
    pub node_manager_index: usize,
    pub continuation_point: ContinuationPoint,
    pub id: ByteString,

    node_id: NodeId,
    browse_direction: BrowseDirection,
    reference_type_id: NodeId,
    include_subtypes: bool,
    node_class_mask: NodeClassMask,
    result_mask: BrowseDescriptionResultMask,
    status_code: StatusCode,
    pub(crate) max_references_per_node: usize,
}

impl BrowseNode {
    /// Create a new empty browse node
    pub fn new(
        description: BrowseDescription,
        max_references_per_node: usize,
        input_index: usize,
    ) -> Self {
        Self {
            node_id: description.node_id,
            browse_direction: description.browse_direction,
            reference_type_id: description.reference_type_id,
            include_subtypes: description.include_subtypes,
            node_class_mask: NodeClassMask::from_bits_truncate(description.node_class_mask),
            result_mask: BrowseDescriptionResultMask::from_bits_truncate(description.result_mask),
            input_continuation_point: None,
            next_continuation_point: None,
            max_references_per_node,
            references: Vec::new(),
            status_code: StatusCode::BadNodeIdUnknown,
            input_index,
            start_node_manager: 0,
        }
    }

    pub fn from_continuation_point(point: BrowseContinuationPoint, input_index: usize) -> Self {
        Self {
            node_id: point.node_id,
            browse_direction: point.browse_direction,
            reference_type_id: point.reference_type_id,
            include_subtypes: point.include_subtypes,
            node_class_mask: point.node_class_mask,
            result_mask: point.result_mask,
            references: Vec::new(),
            status_code: StatusCode::BadNodeIdUnknown,
            input_continuation_point: Some(point.continuation_point),
            next_continuation_point: None,
            max_references_per_node: point.max_references_per_node,
            input_index,
            start_node_manager: point.node_manager_index,
        }
    }

    /// Set the response status, you should make sure to set this
    /// if you own the node being browsed. It defaults to BadNodeIdUnknown.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status_code = status;
    }

    /// Get the continuation point created during the last request.
    pub fn continuation_point<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.input_continuation_point.as_ref().and_then(|c| c.get())
    }

    /// Consume the continuation point created during the last request.
    pub fn take_continuation_point<T: Send + Sync + 'static>(&mut self) -> Option<Box<T>> {
        self.input_continuation_point.take().and_then(|c| c.take())
    }

    /// Set the continuation point that will be returned to the client.
    pub fn set_next_continuation_point<T: Send + Sync + 'static>(
        &mut self,
        continuation_point: Box<T>,
    ) {
        self.next_continuation_point = Some(ContinuationPoint::new(continuation_point));
    }

    /// Get the current number of added references.
    pub fn result_len(&self) -> usize {
        self.references.len()
    }

    /// Get the number of references that can be added to this result before
    /// stopping and returning a continuation point.
    pub fn remaining(&self) -> usize {
        if self.result_len() >= self.max_references_per_node {
            0
        } else {
            self.max_references_per_node - self.result_len()
        }
    }

    /// Add a reference to the results list, without verifying that it is valid.
    /// If you do this, you are responsible for validating filters,
    /// and requested fields on each reference.
    pub fn add_unchecked(&mut self, reference: ReferenceDescription) {
        self.references.push(reference);
    }

    pub fn matches_filter(
        &self,
        type_tree: &dyn TypeTree,
        reference: &ReferenceDescription,
    ) -> bool {
        if reference.node_id.is_null() {
            warn!("Skipping reference with null NodeId");
            return false;
        }
        if matches!(reference.node_class, NodeClass::Unspecified) {
            warn!(
                "Skipping reference {} with unspecified node class and NodeId",
                reference.node_id
            );
            return false;
        }
        // Validate the reference and reference type
        if !reference.reference_type_id.is_null()
            && !matches!(
                type_tree.get(&reference.reference_type_id),
                Some(NodeClass::ReferenceType)
            )
        {
            warn!(
                "Skipping reference {} with reference type that does not exist or is not a ReferenceType",
                reference.node_id
            );
            return false;
        }

        if !self.node_class_mask.is_empty()
            && !self
                .node_class_mask
                .contains(NodeClassMask::from_bits_truncate(
                    reference.node_class as u32,
                ))
        {
            return false;
        }

        // Check the reference type filter.
        if !self.reference_type_id.is_null() {
            // If the provided reference type is not found, no nodes should be returned.
            if !matches!(
                type_tree.get(&self.reference_type_id),
                Some(NodeClass::ReferenceType)
            ) {
                return false;
            }

            if self.include_subtypes {
                if !type_tree.is_child_of(&reference.reference_type_id, &self.reference_type_id) {
                    return false;
                }
            } else {
                if reference.reference_type_id != self.reference_type_id {
                    return false;
                }
            }
        }

        true
    }

    /// Add a reference, validating that it matches the filters, and returning `true` if it was added.
    /// Note that you are still responsible for not exceeding the `requested_max_references_per_node`
    /// parameter, and producing a continuation point if needed.
    /// This will clear any fields not required by ResultMask.
    pub fn add(&mut self, type_tree: &dyn TypeTree, mut reference: ReferenceDescription) -> bool {
        // First, validate that the reference is valid at all.
        if !self.matches_filter(type_tree, &reference) {
            return false;
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_BROWSE_NAME)
        {
            reference.browse_name = QualifiedName::null();
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_DISPLAY_NAME)
        {
            reference.display_name = LocalizedText::null();
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_NODE_CLASS)
        {
            reference.node_class = NodeClass::Unspecified;
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_REFERENCE_TYPE)
        {
            reference.reference_type_id = NodeId::null();
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION)
        {
            reference.type_definition = ExpandedNodeId::null();
        }

        self.add_unchecked(reference);

        true
    }

    pub fn include_subtypes(&self) -> bool {
        self.include_subtypes
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn browse_direction(&self) -> BrowseDirection {
        self.browse_direction
    }

    pub fn node_class_mask(&self) -> &NodeClassMask {
        &self.node_class_mask
    }

    pub fn result_mask(&self) -> &BrowseDescriptionResultMask {
        &self.result_mask
    }

    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

    pub(crate) fn into_result(
        self,
        node_manager_index: usize,
        node_manager_count: usize,
    ) -> (BrowseResult, Option<BrowseContinuationPoint>, usize) {
        let inner = self
            .next_continuation_point
            .map(|c| (c, node_manager_index))
            .or_else(|| {
                if node_manager_count != 0 && node_manager_index < node_manager_count - 1 {
                    Some((
                        ContinuationPoint::new(Box::new(EmptyContinuationPoint)),
                        node_manager_index + 1,
                    ))
                } else {
                    None
                }
            });

        let continuation_point = inner.map(|(p, node_manager_index)| BrowseContinuationPoint {
            node_manager_index,
            continuation_point: p,
            id: random::byte_string(6),
            node_id: self.node_id,
            browse_direction: self.browse_direction,
            reference_type_id: self.reference_type_id,
            include_subtypes: self.include_subtypes,
            node_class_mask: self.node_class_mask,
            result_mask: self.result_mask,
            status_code: self.status_code,
            max_references_per_node: self.max_references_per_node,
        });

        (
            BrowseResult {
                status_code: self.status_code,
                continuation_point: continuation_point
                    .as_ref()
                    .map(|c| c.id.clone())
                    .unwrap_or_default(),
                references: Some(self.references),
            },
            continuation_point,
            self.input_index,
        )
    }

    /// Returns whether this node is completed in this invocation of the Browse or
    /// BrowseNext service. If this returns true, no new nodes should be added.
    pub fn is_completed(&self) -> bool {
        self.remaining() <= 0 || self.next_continuation_point.is_some()
    }

    pub(crate) fn input_index(&self) -> usize {
        self.input_index
    }
}

// The node manager model works somewhat poorly with translate browse paths.
// In theory a node manager should only need to know about references relating to its own nodes,
// but if a browse path crosses a boundary between node managers it isn't obvious
// how to handle that.
// If it becomes necessary there may be ways to handle this, but it may be we just leave it up
// to the user.

/// Container for a node being discovered in a browse path operation.
pub struct BrowsePathItem {
    path: BrowsePath,
    status_code: StatusCode,
    targets: Vec<BrowsePathTarget>,
}

impl BrowsePathItem {
    pub fn new(path: BrowsePath) -> Self {
        Self {
            path,
            status_code: StatusCode::BadNodeIdUnknown,
            targets: Vec::new(),
        }
    }

    /// Get the path that should be visited.
    pub fn path(&self) -> &BrowsePath {
        &self.path
    }

    /// Set the status code for this item. This defaults to BadNodeIdUnknown.
    /// If you are an owner of the start node, you should make sure to set this.
    pub fn set_status_code(&mut self, status_code: StatusCode) {
        self.status_code = status_code;
    }

    /// Add a path target to the result.
    pub fn add_target(&mut self, node_id: ExpandedNodeId, remaining_path_index: u32) {
        self.targets.push(BrowsePathTarget {
            target_id: node_id,
            remaining_path_index,
        });
    }

    /// Get the registered targets. You are allowed to use these to continue fetching nodes.
    pub fn targets(&self) -> &[BrowsePathTarget] {
        &self.targets
    }
}

pub struct RegisterNodeItem {
    node_id: NodeId,
    registered: bool,
}

impl RegisterNodeItem {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            registered: false,
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn set_registered(&mut self, registered: bool) {
        self.registered = registered;
    }
}
