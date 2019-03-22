use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::service_types::*;

use crate::{
    address_space::AddressSpace,
    services::Service,
    session::Session,
    state::ServerState,
    constants,
};

pub(crate) struct NodeManagementService;

impl Service for NodeManagementService {}

impl NodeManagementService {
    pub fn new() -> NodeManagementService {
        NodeManagementService {}
    }

    pub fn add_nodes(&self, _address_space: &mut AddressSpace, request: &AddNodesRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref nodes_to_add) = request.nodes_to_add {
            if !nodes_to_add.is_empty() {
                let results = nodes_to_add.iter().map(|node_to_add| {
                    AddNodesResult {
                        status_code: StatusCode::BadUserAccessDenied,
                        added_node_id: NodeId::null(),
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
