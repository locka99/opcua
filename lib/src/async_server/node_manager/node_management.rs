use crate::server::prelude::{
    AddNodesItem, AddNodesResult, AddReferencesItem, DataTypeAttributes, DecodingOptions,
    DeleteNodesItem, DeleteReferencesItem, ExpandedNodeId, ExtensionObject, GenericAttributes,
    MethodAttributes, NodeClass, NodeId, ObjectAttributes, ObjectId, ObjectTypeAttributes,
    QualifiedName, ReferenceTypeAttributes, StatusCode, VariableAttributes, VariableTypeAttributes,
    ViewAttributes,
};

#[derive(Clone, Debug)]
pub enum AddNodeAttributes {
    Object(ObjectAttributes),
    Variable(VariableAttributes),
    Method(MethodAttributes),
    ObjectType(ObjectTypeAttributes),
    VariableType(VariableTypeAttributes),
    ReferenceType(ReferenceTypeAttributes),
    DataType(DataTypeAttributes),
    View(ViewAttributes),
    Generic(GenericAttributes),
    None,
}

impl AddNodeAttributes {
    pub fn from_extension_object(
        obj: ExtensionObject,
        options: &DecodingOptions,
    ) -> Result<Self, StatusCode> {
        if obj.is_null() {
            return Ok(Self::None);
        }
        match obj
            .object_id()
            .map_err(|_| StatusCode::BadNodeAttributesInvalid)?
        {
            ObjectId::ObjectAttributes_Encoding_DefaultBinary => {
                Ok(Self::Object(obj.decode_inner(options)?))
            }
            ObjectId::VariableAttributes_Encoding_DefaultBinary => {
                Ok(Self::Variable(obj.decode_inner(options)?))
            }
            ObjectId::MethodAttributes_Encoding_DefaultBinary => {
                Ok(Self::Method(obj.decode_inner(options)?))
            }
            ObjectId::ObjectTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::ObjectType(obj.decode_inner(options)?))
            }
            ObjectId::VariableTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::VariableType(obj.decode_inner(options)?))
            }
            ObjectId::ReferenceTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::ReferenceType(obj.decode_inner(options)?))
            }
            ObjectId::DataTypeAttributes_Encoding_DefaultBinary => {
                Ok(Self::DataType(obj.decode_inner(options)?))
            }
            ObjectId::ViewAttributes_Encoding_DefaultBinary => {
                Ok(Self::View(obj.decode_inner(options)?))
            }
            ObjectId::GenericAttributes_Encoding_DefaultBinary => {
                Ok(Self::Generic(obj.decode_inner(options)?))
            }
            _ => Err(StatusCode::BadNodeAttributesInvalid),
        }
    }
}

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

    pub fn set_result(&mut self, node_id: NodeId, status: StatusCode) {
        self.result_node_id = node_id;
        self.status = status;
    }

    pub fn parent_node_id(&self) -> &ExpandedNodeId {
        &self.parent_node_id
    }

    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

    pub fn requested_new_node_id(&self) -> &NodeId {
        &self.requested_new_node_id
    }

    pub fn browse_name(&self) -> &QualifiedName {
        &self.browse_name
    }

    pub fn node_class(&self) -> NodeClass {
        self.node_class
    }

    pub fn node_attributes(&self) -> &AddNodeAttributes {
        &self.node_attributes
    }

    pub fn type_definition_id(&self) -> &ExpandedNodeId {
        &self.type_definition_id
    }

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

    pub fn source_node_id(&self) -> &NodeId {
        &self.source_node_id
    }

    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

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

    pub fn set_source_result(&mut self, status: StatusCode) {
        self.source_status = status;
    }

    pub fn set_target_result(&mut self, status: StatusCode) {
        self.target_status = status;
    }

    pub fn is_forward(&self) -> bool {
        self.is_forward
    }

    pub fn target_status(&self) -> StatusCode {
        self.target_status
    }

    pub fn source_status(&self) -> StatusCode {
        self.source_status
    }
}

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

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn set_result(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub fn delete_target_references(&self) -> bool {
        self.delete_target_references
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

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

    pub fn source_node_id(&self) -> &NodeId {
        &self.source_node_id
    }

    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

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

    pub fn set_source_result(&mut self, status: StatusCode) {
        self.source_status = status;
    }

    pub fn set_target_result(&mut self, status: StatusCode) {
        self.target_status = status;
    }

    pub fn is_forward(&self) -> bool {
        self.is_forward
    }

    pub fn target_status(&self) -> StatusCode {
        self.target_status
    }

    pub fn source_status(&self) -> StatusCode {
        self.source_status
    }

    pub fn delete_bidirectional(&self) -> bool {
        self.delete_bidirectional
    }
}
