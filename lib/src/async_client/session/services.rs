// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::convert::TryFrom;

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::{
    async_client::callbacks::OnSubscriptionNotification,
    core::supported_message::SupportedMessage,
    types::{
        node_ids::{MethodId, ObjectId},
        status_code::StatusCode,
        *,
    },
};

/// Enumeration used with Session::history_read()
pub enum HistoryReadAction {
    ReadEventDetails(ReadEventDetails),
    ReadRawModifiedDetails(ReadRawModifiedDetails),
    ReadProcessedDetails(ReadProcessedDetails),
    ReadAtTimeDetails(ReadAtTimeDetails),
}

/// Enumeration used with Session::history_update()
pub enum HistoryUpdateAction {
    UpdateDataDetails(UpdateDataDetails),
    UpdateStructureDataDetails(UpdateStructureDataDetails),
    UpdateEventDetails(UpdateEventDetails),
    DeleteRawModifiedDetails(DeleteRawModifiedDetails),
    DeleteAtTimeDetails(DeleteAtTimeDetails),
    DeleteEventDetails(DeleteEventDetails),
}

#[async_trait]
pub trait Service {
    fn make_request_header(&self) -> RequestHeader;

    /// Synchronously sends a request. The return value is the response to the request
    async fn send_request<T>(&self, request: T) -> Result<SupportedMessage, StatusCode>
    where
        T: Into<SupportedMessage> + Send;

    /// Asynchronously sends a request. The return value is the request handle of the request
    fn async_send_request<T>(
        &self,
        request: T,
        sender: Option<Sender<SupportedMessage>>,
    ) -> Result<u32, StatusCode>
    where
        T: Into<SupportedMessage>;
}

/// Discovery Service set
#[async_trait]
pub trait DiscoveryService: Service {
    /// Sends a [`FindServersRequest`] to the server denoted by the discovery url.
    ///
    /// See OPC UA Part 4 - Services 5.4.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `endpoint_url` - The network address that the Client used to access the Discovery Endpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ApplicationDescription>)` - A list of [`ApplicationDescription`] that meet criteria specified in the request.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`FindServersRequest`]: ./struct.FindServersRequest.html
    /// [`ApplicationDescription`]: ./struct.ApplicationDescription.html
    ///
    async fn find_servers<T>(
        &self,
        endpoint_url: T,
    ) -> Result<Vec<ApplicationDescription>, StatusCode>
    where
        T: Into<UAString> + Send;

    /// Obtain the list of endpoints supported by the server by sending it a [`GetEndpointsRequest`].
    ///
    /// See OPC UA Part 4 - Services 5.4.4 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of endpoints supported by the server
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`GetEndpointsRequest`]: ./struct.GetEndpointsRequest.html
    ///
    async fn get_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode>;

    /// This function is used by servers that wish to register themselves with a discovery server.
    /// i.e. one server is the client to another server. The server sends a [`RegisterServerRequest`]
    /// to the discovery server to register itself. Servers are expected to re-register themselves periodically
    /// with the discovery server, with a maximum of 10 minute intervals.
    ///
    /// See OPC UA Part 4 - Services 5.4.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `server` - The server to register
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`RegisterServerRequest`]: ./struct.RegisterServerRequest.html
    ///
    async fn register_server(&self, server: RegisteredServer) -> Result<(), StatusCode>;
}

/// SecureChannel Service set
#[async_trait]
pub trait SecureChannelService: Service {
    /// Sends an [`OpenSecureChannelRequest`] to the server
    ///
    ///
    /// See OPC UA Part 4 - Services 5.5.2 for complete description of the service and error responses.
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`OpenSecureChannelRequest`]: ./struct.OpenSecureChannelRequest.html
    ///
    async fn open_secure_channel(&self) -> Result<(), StatusCode>;

    /// Sends a [`CloseSecureChannelRequest`] to the server which will cause the server to drop
    /// the connection.
    ///
    /// See OPC UA Part 4 - Services 5.5.3 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`CloseSecureChannelRequest`]: ./struct.CloseSecureChannelRequest.html
    ///
    fn close_secure_channel(&self) -> Result<(), StatusCode>;
}

/// Session Service set
#[async_trait]
pub trait SessionService: Service {
    /// Sends a [`CreateSessionRequest`] to the server, returning the session id of the created
    /// session. Internally, the session will store the authentication token which is used for requests
    /// subsequent to this call.
    ///
    /// See OPC UA Part 4 - Services 5.6.2 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(NodeId)` - Success, session id
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`CreateSessionRequest`]: ./struct.CreateSessionRequest.html
    ///
    async fn create_session(&self) -> Result<NodeId, StatusCode>;

    /// Sends an [`ActivateSessionRequest`] to the server to activate this session
    ///
    /// See OPC UA Part 4 - Services 5.6.3 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`ActivateSessionRequest`]: ./struct.ActivateSessionRequest.html
    ///
    async fn activate_session(&self) -> Result<(), StatusCode>;

    /// Cancels an outstanding service request by sending a [`CancelRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.6.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `request_handle` - Handle to the outstanding request to be cancelled.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - Success, number of cancelled requests
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`CancelRequest`]: ./struct.CancelRequest.html
    ///
    async fn cancel(&self, request_handle: IntegerId) -> Result<u32, StatusCode>;
}

/// NodeManagement Service set
#[async_trait]
pub trait NodeManagementService: Service {
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
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`AddNodesRequest`]: ./struct.AddNodesRequest.html
    /// [`AddNodesItem`]: ./struct.AddNodesItem.html
    /// [`AddNodesResult`]: ./struct.AddNodesResult.html
    ///
    async fn add_nodes(
        &self,
        nodes_to_add: &[AddNodesItem],
    ) -> Result<Vec<AddNodesResult>, StatusCode>;

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
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`AddReferencesRequest`]: ./struct.AddReferencesRequest.html
    /// [`AddReferencesItem`]: ./struct.AddReferencesItem.html
    ///
    async fn add_references(
        &self,
        references_to_add: &[AddReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode>;

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
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`DeleteNodesRequest`]: ./struct.DeleteNodesRequest.html
    /// [`DeleteNodesItem`]: ./struct.DeleteNodesItem.html
    ///
    async fn delete_nodes(
        &self,
        nodes_to_delete: &[DeleteNodesItem],
    ) -> Result<Vec<StatusCode>, StatusCode>;

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
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`DeleteReferencesRequest`]: ./struct.DeleteReferencesRequest.html
    /// [`DeleteReferencesItem`]: ./struct.DeleteReferencesItem.html
    ///
    async fn delete_references(
        &self,
        references_to_delete: &[DeleteReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode>;
}

/// View Service set
#[async_trait]
pub trait ViewService: Service {
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
    /// * `Ok(Option<Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///                                    may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`BrowseRequest`]: ./struct.BrowseRequest.html
    /// [`BrowseDescription`]: ./struct.BrowseDescription.html
    /// [`BrowseResult`]: ./struct.BrowseResult.html
    ///
    async fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode>;

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
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`BrowseRequest`]: ./struct.BrowseRequest.html
    /// [`BrowseNextRequest`]: ./struct.BrowseNextRequest.html
    /// [`BrowseResult`]: ./struct.BrowseResult.html
    ///
    async fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode>;

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
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`TranslateBrowsePathsToNodeIdsRequest`]: ./struct.TranslateBrowsePathsToNodeIdsRequest.html
    /// [`BrowsePath`]: ./struct.BrowsePath.html
    /// [`BrowsePathResult`]: ./struct.BrowsePathResult.html
    async fn translate_browse_paths_to_node_ids(
        &self,
        browse_paths: &[BrowsePath],
    ) -> Result<Vec<BrowsePathResult>, StatusCode>;

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
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`RegisterNodesRequest`]: ./struct.RegisterNodesRequest.html
    /// [`NodeId`]: ./struct.NodeId.html
    async fn register_nodes(&self, nodes_to_register: &[NodeId])
        -> Result<Vec<NodeId>, StatusCode>;

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
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`UnregisterNodesRequest`]: ./struct.UnregisterNodesRequest.html
    /// [`NodeId`]: ./struct.NodeId.html
    ///
    async fn unregister_nodes(&self, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode>;
}

/// Attribute Service set
#[async_trait]
pub trait AttributeService: Service {
    /// Reads the value of nodes by sending a [`ReadRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.10.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_read` - A list of [`ReadValueId`] to be read by the server.
    /// * `timestamps_to_return` - The [`TimestampsToReturn`] for each node, Both, Server, Source or None
    /// * `max_age` - The maximum age of value to read in milliseconds. Read the service description
    ///               for details. Basically it will attempt to read a value within the age range or
    ///               attempt to read a new value. If 0 the server will attempt to read a new value from the datasource.
    ///               If set to `i32::MAX` or greater, the server shall attempt to get a cached value.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<DataValue>)` - A list of [`DataValue`] corresponding to each read operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`ReadRequest`]: ./struct.ReadRequest.html
    /// [`ReadValueId`]: ./struct.ReadValueId.html
    /// [`DataValue`]: ./struct.DataValue.html
    ///
    async fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode>;

    /// Reads historical values or events of one or more nodes. The caller is expected to provide
    /// a HistoryReadAction enum which must be one of the following:
    ///
    /// * HistoryReadAction::ReadEventDetails
    /// * HistoryReadAction::ReadRawModifiedDetails
    /// * HistoryReadAction::ReadProcessedDetails
    /// * HistoryReadAction::ReadAtTimeDetails
    ///
    /// See OPC UA Part 4 - Services 5.10.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `history_read_details` - A history read operation encoded in an `ExtensionObject`.
    /// * `timestamps_to_return` - Enumeration of which timestamps to return.
    /// * `release_continuation_points` - Flag indicating whether to release the continuation point for the operation.
    /// * `nodes_to_read` - The list of `HistoryReadValueId` of the nodes to apply the history read operation to.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<HistoryReadResult>)` - A list of `HistoryReadResult` results corresponding to history read operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    async fn history_read(
        &self,
        history_read_details: HistoryReadAction,
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
        nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode>;

    /// Writes values to nodes by sending a [`WriteRequest`] to the server. Note that some servers may reject DataValues
    /// containing source or server timestamps.
    ///
    /// See OPC UA Part 4 - Services 5.10.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_write` - A list of [`WriteValue`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` results corresponding to each write operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`WriteRequest`]: ./struct.WriteRequest.html
    /// [`WriteValue`]: ./struct.WriteValue.html
    ///
    async fn write(&self, nodes_to_write: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode>;

    /// Updates historical values. The caller is expected to provide one or more history update operations
    /// in a slice of HistoryUpdateAction enums which are one of the following:
    ///
    /// * UpdateDataDetails
    /// * UpdateStructureDataDetails
    /// * UpdateEventDetails
    /// * DeleteRawModifiedDetails
    /// * DeleteAtTimeDetails
    /// * DeleteEventDetails
    ///
    /// See OPC UA Part 4 - Services 5.10.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `history_update_details` - A list of history update operations each encoded as an `ExtensionObject`.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ClientHistoryUpdateResult>)` - A list of `ClientHistoryUpdateResult` results corresponding to history update operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    async fn history_update(
        &self,
        history_update_details: &[HistoryUpdateAction],
    ) -> Result<Vec<HistoryUpdateResult>, StatusCode>;
}

/// Method Service set
#[async_trait]
pub trait MethodService: Service {
    /// Calls a single method on an object on the server by sending a [`CallRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `method` - The method to call. Note this function takes anything that can be turned into
    ///   a [`CallMethodRequest`] which includes a (`NodeId`, `NodeId`, `Option<Vec<Variant>>`)
    ///   which refers to the object id, method id, and input arguments respectively.
    ///
    /// # Returns
    ///
    /// * `Ok(CallMethodResult)` - A `[CallMethodResult]` for the Method call.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`CallRequest`]: ./struct.CallRequest.html
    /// [`CallMethodRequest`]: ./struct.CallMethodRequest.html
    /// [`CallMethodResult`]: ./struct.CallMethodResult.html
    ///
    async fn call<T>(&self, method: T) -> Result<CallMethodResult, StatusCode>
    where
        T: Into<CallMethodRequest> + Send;

    /// Calls GetMonitoredItems via call_method(), putting a sane interface on the input / output.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - Server allocated identifier for the subscription to return monitored items for.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<u32>, Vec<u32>))` - Result for call, consisting a list of (monitored_item_id, client_handle)
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    async fn call_get_monitored_items(
        &self,
        subscription_id: u32,
    ) -> Result<(Vec<u32>, Vec<u32>), StatusCode> {
        let args = Some(vec![Variant::from(subscription_id)]);
        let object_id: NodeId = ObjectId::Server.into();
        let method_id: NodeId = MethodId::Server_GetMonitoredItems.into();
        let request: CallMethodRequest = (object_id, method_id, args).into();
        let response = self.call(request).await?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = <Vec<u32>>::try_from(&result.remove(0))
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                let client_handles = <Vec<u32>>::try_from(&result.remove(0))
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                Ok((server_handles, client_handles))
            } else {
                error!("Expected a result with 2 args and didn't get it.");
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("Expected a result and didn't get it.");
            Err(StatusCode::BadUnexpectedError)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////
// MonitoredItem Service set
////////////////////////////////////////////////////////////////////////////////////////////////
#[async_trait]
pub trait MonitoredItemService: Service {
    /// Creates monitored items on a subscription by sending a [`CreateMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_create` - A list of [`MonitoredItemCreateRequest`] to be created and assigned to the specified Subscription.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemCreateResult>)` - A list of [`MonitoredItemCreateResult`] corresponding to the items to create.
    ///    The size and order of the list matches the size and order of the `items_to_create` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`CreateMonitoredItemsRequest`]: ./struct.CreateMonitoredItemsRequest.html
    /// [`MonitoredItemCreateRequest`]: ./struct.MonitoredItemCreateRequest.html
    /// [`MonitoredItemCreateResult`]: ./struct.MonitoredItemCreateResult.html
    ///
    async fn create_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_create: &[MonitoredItemCreateRequest],
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode>;

    /// Modifies monitored items on a subscription by sending a [`ModifyMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_modify` - The list of [`MonitoredItemModifyRequest`] to modify.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemModifyResult>)` - A list of [`MonitoredItemModifyResult`] corresponding to the MonitoredItems to modify.
    ///    The size and order of the list matches the size and order of the `items_to_modify` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`ModifyMonitoredItemsRequest`]: ./struct.ModifyMonitoredItemsRequest.html
    /// [`MonitoredItemModifyRequest`]: ./struct.MonitoredItemModifyRequest.html
    /// [`MonitoredItemModifyResult`]: ./struct.MonitoredItemModifyResult.html
    ///
    async fn modify_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_modify: &[MonitoredItemModifyRequest],
    ) -> Result<Vec<MonitoredItemModifyResult>, StatusCode>;

    /// Sets the monitoring mode on one or more monitored items by sending a [`SetMonitoringModeRequest`]
    /// to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored items to be modified.
    /// * `monitoring_mode` - the monitored mode to apply to the monitored items
    /// * `monitored_item_ids` - the monitored items to be modified
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Individual result for each monitored item.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`SetMonitoringModeRequest`]: ./struct.SetMonitoringModeRequest.html
    ///
    async fn set_monitoring_mode(
        &self,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        monitored_item_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode>;

    /// Sets a monitored item so it becomes the trigger that causes other monitored items to send
    /// change events in the same update. Sends a [`SetTriggeringRequest`] to the server.
    /// Note that `items_to_remove` is applied before `items_to_add`.
    ///
    /// See OPC UA Part 4 - Services 5.12.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored item to be used as the trigger.
    /// * `monitored_item_id` - the monitored item that is the trigger.
    /// * `links_to_add` - zero or more items to be added to the monitored item's triggering list.
    /// * `items_to_remove` - zero or more items to be removed from the monitored item's triggering list.
    ///
    /// # Returns
    ///
    /// * `Ok((Option<Vec<StatusCode>>, Option<Vec<StatusCode>>))` - Individual result for each item added / removed for the SetTriggering call.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`SetTriggeringRequest`]: ./struct.SetTriggeringRequest.html
    ///
    async fn set_triggering(
        &self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) -> Result<(Option<Vec<StatusCode>>, Option<Vec<StatusCode>>), StatusCode>;

    /// Deletes monitored items from a subscription by sending a [`DeleteMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.6 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of StatusCodes for the MonitoredItems to delete. The size and
    ///   order of the list matches the size and order of the `items_to_delete` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`DeleteMonitoredItemsRequest`]: ./struct.DeleteMonitoredItemsRequest.html
    ///
    async fn delete_monitored_items(
        &self,
        subscription_id: u32,
        items_to_delete: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode>;
}

////////////////////////////////////////////////////////////////////////////////////////////////
// Subscription Service set
////////////////////////////////////////////////////////////////////////////////////////////////
#[async_trait]
pub trait SubscriptionService: Service {
    /// Create a subscription by sending a [`CreateSubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `publishing_interval` - The requested publishing interval defines the cyclic rate that
    ///   the Subscription is being requested to return Notifications to the Client. This interval
    ///   is expressed in milliseconds. This interval is represented by the publishing timer in the
    ///   Subscription state table. The negotiated value for this parameter returned in the
    ///   response is used as the default sampling interval for MonitoredItems assigned to this
    ///   Subscription. If the requested value is 0 or negative, the server shall revise with the
    ///   fastest supported publishing interval in milliseconds.
    /// * `lifetime_count` - Requested lifetime count. The lifetime count shall be a minimum of
    ///   three times the keep keep-alive count. When the publishing timer has expired this
    ///   number of times without a Publish request being available to send a NotificationMessage,
    ///   then the Subscription shall be deleted by the Server.
    /// * `max_keep_alive_count` - Requested maximum keep-alive count. When the publishing timer has
    ///   expired this number of times without requiring any NotificationMessage to be sent, the
    ///   Subscription sends a keep-alive Message to the Client. The negotiated value for this
    ///   parameter is returned in the response. If the requested value is 0, the server shall
    ///   revise with the smallest supported keep-alive count.
    /// * `max_notifications_per_publish` - The maximum number of notifications that the Client
    ///   wishes to receive in a single Publish response. A value of zero indicates that there is
    ///   no limit. The number of notifications per Publish is the sum of monitoredItems in
    ///   the DataChangeNotification and events in the EventNotificationList.
    /// * `priority` - Indicates the relative priority of the Subscription. When more than one
    ///   Subscription needs to send Notifications, the Server should de-queue a Publish request
    ///   to the Subscription with the highest priority number. For Subscriptions with equal
    ///   priority the Server should de-queue Publish requests in a round-robin fashion.
    ///   A Client that does not require special priority settings should set this value to zero.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscription, `false`, publishing is disabled for the Subscription.
    ///   The value of this parameter does not affect the value of the monitoring mode Attribute of
    ///   MonitoredItems.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - identifier for new subscription
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`CreateSubscriptionRequest`]: ./struct.CreateSubscriptionRequest.html
    ///
    async fn create_subscription<CB>(
        &self,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        callback: CB,
    ) -> Result<u32, StatusCode>
    where
        CB: OnSubscriptionNotification + Send + Sync + 'static;

    /// Modifies a subscription by sending a [`ModifySubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    ///
    /// See `create_subscription` for description of other parameters
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`ModifySubscriptionRequest`]: ./struct.ModifySubscriptionRequest.html
    ///
    async fn modify_subscription(
        &self,
        subscription_id: u32,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
    ) -> Result<(), StatusCode>;

    /// Changes the publishing mode of subscriptions by sending a [`SetPublishingModeRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscriptions, `false`, publishing is disabled for the Subscriptions.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Service return code for the  action for each id, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`SetPublishingModeRequest`]: ./struct.SetPublishingModeRequest.html
    ///
    async fn set_publishing_mode(
        &self,
        subscription_ids: &[u32],
        publishing_enabled: bool,
    ) -> Result<Vec<StatusCode>, StatusCode>;

    /// Transfers Subscriptions and their MonitoredItems from one Session to another. For example,
    /// a Client may need to reopen a Session and then transfer its Subscriptions to that Session.
    /// It may also be used by one Client to take over a Subscription from another Client by
    /// transferring the Subscription to its Session.
    ///
    /// See OPC UA Part 4 - Services 5.13.7 for complete description of the service and error responses.
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `send_initial_values` - A boolean parameter with the following values - `true` the first
    ///   publish response shall contain the current values of all monitored items in the subscription,
    ///   `false`, the first publish response shall contain only the value changes since the last
    ///   publish response was sent.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<TransferResult>)` - The [`TransferResult`] for each transfer subscription.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`TransferSubscriptionsRequest`]: ./struct.TransferSubscriptionsRequest.html
    /// [`TransferResult`]: ./struct.TransferResult.html
    ///
    async fn transfer_subscriptions(
        &self,
        subscription_ids: &[u32],
        send_initial_values: bool,
    ) -> Result<Vec<TransferResult>, StatusCode>;

    /// Deletes a subscription by sending a [`DeleteSubscriptionsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    ///
    /// # Returns
    ///
    /// * `Ok(StatusCode)` - Service return code for the delete action, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`DeleteSubscriptionsRequest`]: ./struct.DeleteSubscriptionsRequest.html
    ///
    async fn delete_subscription(&self, subscription_id: u32) -> Result<StatusCode, StatusCode>;

    /// Deletes subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with the list
    /// of subscriptions to delete.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - List of subscription identifiers to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of result for delete action on each id, `Good` or `BadSubscriptionIdInvalid`
    ///   The size and order of the list matches the size and order of the input.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`DeleteSubscriptionsRequest`]: ./struct.DeleteSubscriptionsRequest.html
    ///
    async fn delete_subscriptions(
        &self,
        subscription_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode>;
}
