use crate::types::{
    AddNodeAttributes, AddNodesItem, AddNodesResult, AddReferencesItem, DecodingOptions,
    DeleteNodesItem, DeleteReferencesItem, ExpandedNodeId, NodeClass, NodeId, QualifiedName,
    StatusCode,
};

#[derive(Debug, Clone)]
/// Container for a single node being added in an `AddNode` service call.
pub struct AddNodeItem {
    parent_node_id: ExpandedNodeId,
    reference_type_id: NodeId,
    requested_new_node_id: NodeId,
    browse_name: QualifiedName,
    node_class: NodeClass,
    node_attributes: AddNodeAttributes,
    type_definition_id: ExpandedNodeId,

    result_node_id: NodeId,
    status: StatusCode,
}

impl AddNodeItem {
    pub(crate) fn new(item: AddNodesItem, options: &DecodingOptions) -> Self {
        let mut status = StatusCode::BadNotSupported;
        let attributes =
            match AddNodeAttributes::from_extension_object(item.node_attributes, options) {
                Ok(attr) => attr,
                Err(e) => {
                    status = e;
                    AddNodeAttributes::None
                }
            };
        if item.requested_new_node_id.server_index != 0 {
            status = StatusCode::BadNodeIdRejected;
        }

        Self::validate_attributes(item.node_class, &attributes, &mut status);

        if item.reference_type_id.is_null() {
            status = StatusCode::BadReferenceTypeIdInvalid;
        }
        if item.parent_node_id.is_null() {
            status = StatusCode::BadParentNodeIdInvalid;
        }

        match (item.node_class, item.type_definition.is_null()) {
            (NodeClass::Object | NodeClass::Variable, true) => {
                status = StatusCode::BadTypeDefinitionInvalid
            }
            (NodeClass::Object | NodeClass::Variable, false) => (),
            (_, false) => status = StatusCode::BadTypeDefinitionInvalid,
            _ => (),
        }

        Self {
            parent_node_id: item.parent_node_id,
            reference_type_id: item.reference_type_id,
            requested_new_node_id: item.requested_new_node_id.node_id,
            browse_name: item.browse_name,
            node_class: item.node_class,
            node_attributes: attributes,
            type_definition_id: item.type_definition,
            result_node_id: NodeId::null(),
            status,
        }
    }

    fn validate_attributes(
        node_class: NodeClass,
        attributes: &AddNodeAttributes,
        status: &mut StatusCode,
    ) {
        match (node_class, attributes) {
            (NodeClass::Object, AddNodeAttributes::Object(_))
            | (NodeClass::Variable, AddNodeAttributes::Variable(_))
            | (NodeClass::Method, AddNodeAttributes::Method(_))
            | (NodeClass::ObjectType, AddNodeAttributes::ObjectType(_))
            | (NodeClass::VariableType, AddNodeAttributes::VariableType(_))
            | (NodeClass::ReferenceType, AddNodeAttributes::ReferenceType(_))
            | (NodeClass::DataType, AddNodeAttributes::DataType(_))
            | (NodeClass::View, AddNodeAttributes::View(_)) => {}
            (NodeClass::Unspecified, _) => *status = StatusCode::BadNodeClassInvalid,
            (_, AddNodeAttributes::None | AddNodeAttributes::Generic(_)) => {}
            _ => *status = StatusCode::BadNodeAttributesInvalid,
        }
    }

    /// Set the result of the operation. `node_id` is the node ID of the created node.
    pub fn set_result(&mut self, node_id: NodeId, status: StatusCode) {
        self.result_node_id = node_id;
        self.status = status;
    }

    /// The requested parent node ID.
    pub fn parent_node_id(&self) -> &ExpandedNodeId {
        &self.parent_node_id
    }

    /// The requested reference type ID.
    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

    /// The requested new node ID. May be null, in which case the node manager picks the new
    /// node ID.
    pub fn requested_new_node_id(&self) -> &NodeId {
        &self.requested_new_node_id
    }

    /// Requested browse name of the new node.
    pub fn browse_name(&self) -> &QualifiedName {
        &self.browse_name
    }

    /// Requested node class of the new node.
    pub fn node_class(&self) -> NodeClass {
        self.node_class
    }

    /// Collection of requested attributes for the new node.
    pub fn node_attributes(&self) -> &AddNodeAttributes {
        &self.node_attributes
    }

    /// Requested type definition ID.
    pub fn type_definition_id(&self) -> &ExpandedNodeId {
        &self.type_definition_id
    }

    /// Current result status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn into_result(self) -> AddNodesResult {
        AddNodesResult {
            status_code: self.status,
            added_node_id: self.result_node_id,
        }
    }
}

#[derive(Debug, Clone)]
/// Container for a single reference being added in an `AddReferences` service call.
pub struct AddReferenceItem {
    source_node_id: NodeId,
    reference_type_id: NodeId,
    target_node_id: ExpandedNodeId,
    is_forward: bool,

    source_status: StatusCode,
    target_status: StatusCode,
}

impl AddReferenceItem {
    pub(crate) fn new(item: AddReferencesItem) -> Self {
        let mut status = StatusCode::BadNotSupported;
        if item.source_node_id.is_null() {
            status = StatusCode::BadSourceNodeIdInvalid;
        }
        if item.target_node_id.is_null() {
            status = StatusCode::BadTargetNodeIdInvalid;
        }
        if item.reference_type_id.is_null() {
            status = StatusCode::BadReferenceTypeIdInvalid;
        }
        if !item.target_server_uri.is_null() || item.target_node_id.server_index != 0 {
            status = StatusCode::BadReferenceLocalOnly;
        }
        Self {
            source_node_id: item.source_node_id,
            reference_type_id: item.reference_type_id,
            target_node_id: item.target_node_id,
            is_forward: item.is_forward,
            source_status: status,
            target_status: status,
        }
    }

    /// Requested source node ID.
    pub fn source_node_id(&self) -> &NodeId {
        &self.source_node_id
    }

    /// Requested reference type ID.
    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

    /// Requested target node ID.
    pub fn target_node_id(&self) -> &ExpandedNodeId {
        &self.target_node_id
    }

    /// Current result status, as a summary of source status and target status.
    pub(crate) fn result_status(&self) -> StatusCode {
        if self.source_status.is_good() {
            return self.source_status;
        }
        if self.target_status.is_good() {
            return self.target_status;
        }
        self.source_status
    }

    /// Set the result of this operation for the _source_ end of the reference.
    pub fn set_source_result(&mut self, status: StatusCode) {
        self.source_status = status;
    }

    /// Set the result of this operation for the _target_ end of the reference.
    pub fn set_target_result(&mut self, status: StatusCode) {
        self.target_status = status;
    }

    /// Requested reference direction.
    pub fn is_forward(&self) -> bool {
        self.is_forward
    }

    /// Current target status.
    pub fn target_status(&self) -> StatusCode {
        self.target_status
    }

    /// Current source status.
    pub fn source_status(&self) -> StatusCode {
        self.source_status
    }
}

#[derive(Debug)]
/// Container for a single item in a `DeleteNodes` service call.
pub struct DeleteNodeItem {
    node_id: NodeId,
    delete_target_references: bool,

    status: StatusCode,
}

impl DeleteNodeItem {
    pub(crate) fn new(item: DeleteNodesItem) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;
        if item.node_id.is_null() {
            status = StatusCode::BadNodeIdInvalid;
        }

        Self {
            node_id: item.node_id,
            delete_target_references: item.delete_target_references,
            status,
        }
    }

    /// Current status of the operation.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Set the result of the node deletion operation.
    pub fn set_result(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Whether the request should delete references that point to this node or not.
    pub fn delete_target_references(&self) -> bool {
        self.delete_target_references
    }

    /// Node ID to delete.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

#[derive(Debug)]
/// Container for a single reference being deleted in an `DeleteReferences` service call.
pub struct DeleteReferenceItem {
    source_node_id: NodeId,
    reference_type_id: NodeId,
    is_forward: bool,
    target_node_id: ExpandedNodeId,
    delete_bidirectional: bool,

    source_status: StatusCode,
    target_status: StatusCode,
}

impl DeleteReferenceItem {
    pub(crate) fn new(item: DeleteReferencesItem) -> Self {
        let mut status = StatusCode::BadNotSupported;
        if item.source_node_id.is_null() {
            status = StatusCode::BadSourceNodeIdInvalid;
        }
        if item.target_node_id.is_null() {
            status = StatusCode::BadTargetNodeIdInvalid;
        }
        if item.reference_type_id.is_null() {
            status = StatusCode::BadReferenceTypeIdInvalid;
        }
        if item.target_node_id.server_index != 0 {
            status = StatusCode::BadReferenceLocalOnly;
        }

        Self {
            source_node_id: item.source_node_id,
            reference_type_id: item.reference_type_id,
            is_forward: item.is_forward,
            target_node_id: item.target_node_id,
            delete_bidirectional: item.delete_bidirectional,

            source_status: status,
            target_status: status,
        }
    }

    /// Source node ID of the reference being deleted.
    pub fn source_node_id(&self) -> &NodeId {
        &self.source_node_id
    }

    /// Reference type ID of the reference being deleted.
    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

    /// Target node ID of the reference being deleted.
    pub fn target_node_id(&self) -> &ExpandedNodeId {
        &self.target_node_id
    }

    pub(crate) fn result_status(&self) -> StatusCode {
        if self.source_status.is_good() {
            return self.source_status;
        }
        if self.target_status.is_good() {
            return self.target_status;
        }
        self.source_status
    }

    /// Set the result of this operation for the _source_ end of the reference.
    pub fn set_source_result(&mut self, status: StatusCode) {
        self.source_status = status;
    }

    /// Set the result of this operation for the _target_ end of the reference.
    pub fn set_target_result(&mut self, status: StatusCode) {
        self.target_status = status;
    }

    /// Direction of the reference being deleted.
    pub fn is_forward(&self) -> bool {
        self.is_forward
    }

    /// Current target status.
    pub fn target_status(&self) -> StatusCode {
        self.target_status
    }

    /// Current source status.
    pub fn source_status(&self) -> StatusCode {
        self.source_status
    }

    /// Whether to delete the reference in both directions.
    pub fn delete_bidirectional(&self) -> bool {
        self.delete_bidirectional
    }
}
