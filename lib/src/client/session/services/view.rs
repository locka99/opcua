use crate::{
    client::{
        session::{
            process_service_result, process_unexpected_response, session_debug, session_error,
        },
        Session,
    },
    core::supported_message::SupportedMessage,
    types::{
        BrowseDescription, BrowseNextRequest, BrowsePath, BrowsePathResult, BrowseRequest,
        BrowseResult, ByteString, DateTime, NodeId, RegisterNodesRequest, StatusCode,
        TranslateBrowsePathsToNodeIdsRequest, UnregisterNodesRequest, ViewDescription,
    },
};

impl Session {
    /// Discover the references to the specified nodes by sending a [`BrowseRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.8.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_browse` - A list of [`BrowseDescription`] describing nodes to browse.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///                                    may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
        max_references_per_node: u32,
        view: Option<ViewDescription>,
    ) -> Result<Vec<BrowseResult>, StatusCode> {
        if nodes_to_browse.is_empty() {
            session_error!(self, "browse, was not supplied with any nodes to browse");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = BrowseRequest {
                request_header: self.make_request_header(),
                view: view.unwrap_or_else(|| ViewDescription {
                    view_id: NodeId::null(),
                    timestamp: DateTime::null(),
                    view_version: 0,
                }),
                requested_max_references_per_node: max_references_per_node,
                nodes_to_browse: Some(nodes_to_browse.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::BrowseResponse(response) = response {
                session_debug!(self, "browse, success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(self, "browse failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Continue to discover references to nodes by sending continuation points in a [`BrowseNextRequest`]
    /// to the server. This function may have to be called repeatedly to process the initial query.
    ///
    /// See OPC UA Part 4 - Services 5.8.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `release_continuation_points` - Flag indicating if the continuation points should be released by the server
    /// * `continuation_points` - A list of [`BrowseDescription`] continuation points
    ///
    /// # Returns
    ///
    /// * `Ok(Option<Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///                                    may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Vec<BrowseResult>, StatusCode> {
        if continuation_points.is_empty() {
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = BrowseNextRequest {
                request_header: self.make_request_header(),
                continuation_points: Some(continuation_points.to_vec()),
                release_continuation_points,
            };
            let response = self.send(request).await?;
            if let SupportedMessage::BrowseNextResponse(response) = response {
                session_debug!(self, "browse_next, success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(self, "browse_next failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Translate browse paths to NodeIds by sending a [`TranslateBrowsePathsToNodeIdsRequest`] request to the Server
    /// Each [`BrowsePath`] is constructed of a starting node and a `RelativePath`. The specified starting node
    /// identifies the node from which the RelativePath is based. The RelativePath contains a sequence of
    /// ReferenceTypes and BrowseNames.
    ///
    /// See OPC UA Part 4 - Services 5.8.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `browse_paths` - A list of [`BrowsePath`] node + relative path for the server to look up
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<BrowsePathResult>>)` - List of [`BrowsePathResult`] for the list of browse
    ///                       paths. The size and order of the list matches the size and order of the `browse_paths`
    ///                       parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn translate_browse_paths_to_node_ids(
        &self,
        browse_paths: &[BrowsePath],
    ) -> Result<Vec<BrowsePathResult>, StatusCode> {
        if browse_paths.is_empty() {
            session_error!(
                self,
                "translate_browse_paths_to_node_ids, was not supplied with any browse paths"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = TranslateBrowsePathsToNodeIdsRequest {
                request_header: self.make_request_header(),
                browse_paths: Some(browse_paths.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::TranslateBrowsePathsToNodeIdsResponse(response) = response {
                session_debug!(self, "translate_browse_paths_to_node_ids, success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(
                    self,
                    "translate_browse_paths_to_node_ids failed {:?}",
                    response
                );
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Register nodes on the server by sending a [`RegisterNodesRequest`]. The purpose of this
    /// call is server-dependent but allows a client to ask a server to create nodes which are
    /// otherwise expensive to set up or maintain, e.g. nodes attached to hardware.
    ///
    /// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_register` - A list of [`NodeId`] nodes for the server to register
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<NodeId>)` - A list of [`NodeId`] corresponding to size and order of the input. The
    ///                       server may return an alias for the input `NodeId`
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn register_nodes(
        &self,
        nodes_to_register: &[NodeId],
    ) -> Result<Vec<NodeId>, StatusCode> {
        if nodes_to_register.is_empty() {
            session_error!(
                self,
                "register_nodes, was not supplied with any nodes to register"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = RegisterNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_register: Some(nodes_to_register.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::RegisterNodesResponse(response) = response {
                session_debug!(self, "register_nodes, success");
                process_service_result(&response.response_header)?;
                Ok(response.registered_node_ids.unwrap())
            } else {
                session_error!(self, "register_nodes failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Unregister nodes on the server by sending a [`UnregisterNodesRequest`]. This indicates to
    /// the server that the client relinquishes any need for these nodes. The server will ignore
    /// unregistered nodes.
    ///
    /// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_unregister` - A list of [`NodeId`] nodes for the server to unregister
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request succeeded, server ignores invalid nodes
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn unregister_nodes(&self, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode> {
        if nodes_to_unregister.is_empty() {
            session_error!(
                self,
                "unregister_nodes, was not supplied with any nodes to unregister"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = UnregisterNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_unregister: Some(nodes_to_unregister.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::UnregisterNodesResponse(response) = response {
                session_debug!(self, "unregister_nodes, success");
                process_service_result(&response.response_header)?;
                Ok(())
            } else {
                session_error!(self, "unregister_nodes failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }
}
