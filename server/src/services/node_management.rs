use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::service_types::*;

use crate::{
    address_space::{
        AddressSpace,
        types::*,
    },
    services::Service,
};
use opcua_types::node_ids::ObjectId;

pub(crate) struct NodeManagementService;

impl Service for NodeManagementService {}

impl NodeManagementService {
    pub fn new() -> NodeManagementService {
        NodeManagementService {}
    }

    pub fn add_nodes(&self, address_space: &mut AddressSpace, request: &AddNodesRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref nodes_to_add) = request.nodes_to_add {
            if !nodes_to_add.is_empty() {
                let results = nodes_to_add.iter().map(|node_to_add| {
                    let (status_code, added_node_id) = Self::add_node(address_space, node_to_add);
                    AddNodesResult {
                        status_code,
                        added_node_id,
                    }
                }).collect();
                let response = AddNodesResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                };
                Ok(response.into())
            } else {
                Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
            }
        } else {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    pub fn add_references(&self, _address_space: &mut AddressSpace, request: &AddReferencesRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref references_to_add) = request.references_to_add {
            if !references_to_add.is_empty() {
                Ok(self.service_fault(&request.request_header, StatusCode::BadNotImplemented))
            } else {
                Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
            }
        } else {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    pub fn delete_nodes(&self, _address_space: &mut AddressSpace, request: &DeleteNodesRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref nodes_to_delete) = request.nodes_to_delete {
            if !nodes_to_delete.is_empty() {
                let results = nodes_to_delete.iter().map(|node_to_delete| {
                    // TODO fixme
                    StatusCode::Good
                }).collect();
                let response = DeleteNodesResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                };
                Ok(response.into())
            } else {
                Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
            }
        } else {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    pub fn delete_references(&self, _address_space: &mut AddressSpace, request: &DeleteReferencesRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref references_to_delete) = request.references_to_delete {
            if !references_to_delete.is_empty() {
                Ok(self.service_fault(&request.request_header, StatusCode::BadNotImplemented))
            } else {
                Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
            }
        } else {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    fn create_node(node_id: &NodeId, node_class: NodeClass, browse_name: QualifiedName, node_attributes: &ExtensionObject) -> Result<NodeType, StatusCode> {
        let object_id = node_attributes.node_id.as_object_id().map_err(|_| StatusCode::BadNodeAttributesInvalid)?;

        // Note we are expecting the node_class and the object id for the attributes to be for the same
        // thing. If they are different, it is an error.

        let decoding_limits = DecodingLimits::default();
        match object_id {
            ObjectId::ObjectAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::Object {
                    let attributes = node_attributes.decode_inner::<ObjectAttributes>(&decoding_limits)?;
                    Ok(Object::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and object node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::VariableAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::Variable {
                    let attributes = node_attributes.decode_inner::<VariableAttributes>(&decoding_limits)?;
                    Ok(Variable::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and variable node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::MethodAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::Method {
                    let attributes = node_attributes.decode_inner::<MethodAttributes>(&decoding_limits)?;
                    Ok(Method::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and method node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::ObjectTypeAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::ObjectType {
                    let attributes = node_attributes.decode_inner::<ObjectTypeAttributes>(&decoding_limits)?;
                    Ok(ObjectType::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and object type node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::VariableTypeAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::VariableType {
                    let attributes = node_attributes.decode_inner::<VariableTypeAttributes>(&decoding_limits)?;
                    Ok(VariableType::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and variable type node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::ReferenceTypeAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::ReferenceType {
                    let attributes = node_attributes.decode_inner::<ReferenceTypeAttributes>(&decoding_limits)?;
                    Ok(ReferenceType::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and reference type node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::DataTypeAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::DataType {
                    let attributes = node_attributes.decode_inner::<DataTypeAttributes>(&decoding_limits)?;
                    Ok(DataType::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and data type node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            ObjectId::ViewAttributes_Encoding_DefaultBinary => {
                if node_class == NodeClass::View {
                    let attributes = node_attributes.decode_inner::<ViewAttributes>(&decoding_limits)?;
                    Ok(View::from_attributes(node_id, browse_name, attributes).into())
                } else {
                    error!("node class and view node attributes are not compatible");
                    Err(StatusCode::BadNodeAttributesInvalid)
                }
            }
            _ => {
                warn!("create_node was called with an object id which does not match a supported type");
                Err(StatusCode::BadNodeAttributesInvalid)
            }
        }
    }

    fn add_node(address_space: &mut AddressSpace, node_to_add: &AddNodesItem) -> (StatusCode, NodeId) {
        let requested_new_node_id = &node_to_add.requested_new_node_id;
        if requested_new_node_id.server_index != 0 {
            // Server index is supposed to be 0
            error!("node cannot be created because server index is not 0");
            (StatusCode::BadNodeIdRejected, NodeId::null())
        } else if node_to_add.node_class == NodeClass::Unspecified {
            (StatusCode::BadNodeClassInvalid, NodeId::null())
        } else if !requested_new_node_id.is_null() && address_space.node_exists(&requested_new_node_id.node_id) {
            // If a node id is supplied, it should not already exist
            error!("node cannot be created because node id already exists");
            (StatusCode::BadNodeIdExists, NodeId::null())
        } else if let Ok(reference_type_id) = node_to_add.reference_type_id.as_reference_type_id() {
            // Node Id was either supplied or will be generated
            let new_node_id = if requested_new_node_id.is_null() {
                NodeId::next_numeric()
            } else {
                requested_new_node_id.node_id.clone()
            };

            // Check the type definition is valid
            let valid_type_definition = match node_to_add.node_class {
                NodeClass::Object | NodeClass::Variable => {
                    if node_to_add.type_definition.is_null() {
                        false
                    } else {
                        // TODO should we check if the type definition points to an object or variable type?
                        true
                    }
                }
                _ => {
                    // Other node classes must NOT supply a type definition
                    node_to_add.type_definition.is_null()
                }
            };
            // Create a node
            if !valid_type_definition {
                // Type definition was either invalid or supplied when it should not have been supplied
                error!("node cannot be created because type definition is not valid");
                (StatusCode::BadTypeDefinitionInvalid, NodeId::null())
            } else if let Ok(node) = Self::create_node(&new_node_id, node_to_add.node_class, node_to_add.browse_name.clone(), &node_to_add.node_attributes) {
                // Add the node to the address space
                address_space.insert(node, Some(&[
                    (&node_to_add.parent_node_id.node_id, reference_type_id, ReferenceDirection::Forward),
                ]));
                // Object / Variable types must add a reference to the type
                if node_to_add.node_class == NodeClass::Object || node_to_add.node_class == NodeClass::Variable {
                    address_space.set_node_type(&new_node_id, node_to_add.type_definition.node_id.clone());
                }
                (StatusCode::Good, new_node_id)
            } else {
                // Create node failed, so assume a problem with the node attributes
                error!("node cannot be created because attributes / not class are not valid");
                (StatusCode::BadNodeAttributesInvalid, NodeId::null())
            }
        } else {
            error!("node cannot be created because reference type is invalid");
            (StatusCode::BadReferenceTypeIdInvalid, NodeId::null())
        }
    }
}
