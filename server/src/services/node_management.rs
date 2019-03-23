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

    fn create_node(node_id: &NodeId, browse_name: QualifiedName, node_attributes: &ExtensionObject) -> Result<NodeType, StatusCode> {
        let object_id = node_attributes.node_id.as_object_id().map_err(|_| StatusCode::BadNodeAttributesInvalid)?;

        let decoding_limits = DecodingLimits::default();
        match object_id {
            ObjectId::ObjectAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<ObjectAttributes>(&decoding_limits)?;
                Ok(Object::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::VariableAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<VariableAttributes>(&decoding_limits)?;
                Ok(Variable::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::MethodAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<MethodAttributes>(&decoding_limits)?;
                Ok(Method::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::ObjectTypeAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<ObjectTypeAttributes>(&decoding_limits)?;
                Ok(ObjectType::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::VariableTypeAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<VariableTypeAttributes>(&decoding_limits)?;
                Ok(VariableType::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::ReferenceTypeAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<ReferenceTypeAttributes>(&decoding_limits)?;
                Ok(ReferenceType::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::DataTypeAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<DataTypeAttributes>(&decoding_limits)?;
                Ok(DataType::from_attributes(node_id, browse_name, attributes).into())
            }
            ObjectId::ViewAttributes_Encoding_DefaultBinary => {
                let attributes = node_attributes.decode_inner::<ViewAttributes>(&decoding_limits)?;
                Ok(View::from_attributes(node_id, browse_name, attributes).into())
            }
            _ => {
                Err(StatusCode::BadNodeAttributesInvalid)
            }
        }
    }

    fn add_node(address_space: &mut AddressSpace, node_to_add: &AddNodesItem) -> (StatusCode, NodeId) {
        let requested_new_node_id = &node_to_add.requested_new_node_id;
        if requested_new_node_id.server_index != 0 {
            (StatusCode::BadNodeIdRejected, NodeId::null())
        } else {
            let requested_new_node_id = &requested_new_node_id.node_id;
            if !requested_new_node_id.is_null() && address_space.node_exists(&requested_new_node_id) {
                (StatusCode::BadNodeIdExists, NodeId::null())
            } else if let Ok(reference_type_id) = node_to_add.reference_type_id.as_reference_type_id() {
                // Node Id was either supplied or will be generated
                let requested_new_node_id = if requested_new_node_id.is_null() {
                    NodeId::next_numeric()
                } else {
                    requested_new_node_id.clone()
                };
                // Create a node
                if let Ok(node) = Self::create_node(&requested_new_node_id, node_to_add.browse_name.clone(), &node_to_add.node_attributes) {
                    // Add the node to the address space
                    address_space.insert(node, Some(&[
                        (&node_to_add.parent_node_id.node_id, reference_type_id, ReferenceDirection::Forward),
                    ]));
                    (StatusCode::Good, requested_new_node_id)
                } else {
                    (StatusCode::BadNodeAttributesInvalid, NodeId::null())
                }
            } else {
                (StatusCode::BadReferenceTypeIdInvalid, NodeId::null())
            }
        }
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
                Ok(self.service_fault(&request.request_header, StatusCode::BadNotImplemented))
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
}
