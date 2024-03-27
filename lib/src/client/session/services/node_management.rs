use crate::{
    client::{
        session::{process_service_result, process_unexpected_response, session_error},
        Session,
    },
    core::supported_message::SupportedMessage,
    types::{
        AddNodesItem, AddNodesRequest, AddNodesResult, AddReferencesItem, AddReferencesRequest,
        DeleteNodesItem, DeleteNodesRequest, DeleteReferencesItem, DeleteReferencesRequest,
        StatusCode,
    },
};

impl Session {
    /// Add nodes by sending a [`AddNodesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_add` - A list of [`AddNodesItem`] to be added to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<AddNodesResult>)` - A list of [`AddNodesResult`] corresponding to each add node operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn add_nodes(
        &self,
        nodes_to_add: &[AddNodesItem],
    ) -> Result<Vec<AddNodesResult>, StatusCode> {
        if nodes_to_add.is_empty() {
            session_error!(self, "add_nodes, called with no nodes to add");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = AddNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_add: Some(nodes_to_add.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::AddNodesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Add references by sending a [`AddReferencesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `references_to_add` - A list of [`AddReferencesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each add reference operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn add_references(
        &self,
        references_to_add: &[AddReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if references_to_add.is_empty() {
            session_error!(self, "add_references, called with no references to add");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = AddReferencesRequest {
                request_header: self.make_request_header(),
                references_to_add: Some(references_to_add.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::AddReferencesResponse(response) = response {
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap())
            } else {
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Delete nodes by sending a [`DeleteNodesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_delete` - A list of [`DeleteNodesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each delete node operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_nodes(
        &self,
        nodes_to_delete: &[DeleteNodesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if nodes_to_delete.is_empty() {
            session_error!(self, "delete_nodes, called with no nodes to delete");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_delete: Some(nodes_to_delete.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::DeleteNodesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Delete references by sending a [`DeleteReferencesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_delete` - A list of [`DeleteReferencesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each delete node operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_references(
        &self,
        references_to_delete: &[DeleteReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if references_to_delete.is_empty() {
            session_error!(
                self,
                "delete_references, called with no references to delete"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteReferencesRequest {
                request_header: self.make_request_header(),
                references_to_delete: Some(references_to_delete.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::DeleteReferencesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(process_unexpected_response(response))
            }
        }
    }
}
