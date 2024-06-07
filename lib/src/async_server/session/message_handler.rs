use std::{collections::HashMap, sync::Arc, time::Instant};

use chrono::Utc;
use parking_lot::RwLock;
use tokio::task::JoinHandle;

use crate::{
    async_server::{
        authenticator::UserToken,
        info::ServerInfo,
        node_manager::{
            resolve_external_references, BrowseNode, BrowsePathItem, ExternalReferencesContPoint,
            NodeManager, ReadNode, RegisterNodeItem, RequestContext,
        },
        subscriptions::{CreateMonitoredItem, PendingPublish, SubscriptionCache},
    },
    server::prelude::{
        BrowseNextRequest, BrowseNextResponse, BrowsePathResult, BrowsePathTarget, BrowseRequest,
        BrowseResponse, BrowseResult, ByteString, CreateMonitoredItemsRequest,
        CreateMonitoredItemsResponse, DeleteMonitoredItemsRequest, DeleteMonitoredItemsResponse,
        DeleteSubscriptionsRequest, DeleteSubscriptionsResponse, ModifyMonitoredItemsRequest,
        ModifyMonitoredItemsResponse, PublishRequest, ReadRequest, ReadResponse,
        RegisterNodesRequest, RegisterNodesResponse, ResponseHeader, ServiceFault,
        SetMonitoringModeRequest, SetMonitoringModeResponse, SetTriggeringRequest,
        SetTriggeringResponse, StatusCode, SupportedMessage, TimestampsToReturn,
        TranslateBrowsePathsToNodeIdsRequest, TranslateBrowsePathsToNodeIdsResponse,
        UnregisterNodesRequest, UnregisterNodesResponse,
    },
};

use super::{controller::Response, instance::Session};

pub type NodeManagers = Vec<Arc<dyn NodeManager + Send + Sync + 'static>>;

pub(crate) struct MessageHandler {
    node_managers: NodeManagers,
    info: Arc<ServerInfo>,
    subscriptions: Arc<SubscriptionCache>,
}

pub(crate) enum HandleMessageResult {
    AsyncMessage(JoinHandle<Response>),
    PublishResponse(PendingPublishRequest),
    SyncMessage(Response),
}

pub(crate) struct PendingPublishRequest {
    request_id: u32,
    request_handle: u32,
    recv: tokio::sync::oneshot::Receiver<SupportedMessage>,
}

impl PendingPublishRequest {
    pub async fn recv(self) -> Result<Response, String> {
        match self.recv.await {
            Ok(msg) => Ok(Response {
                message: msg,
                request_id: self.request_id,
            }),
            Err(_) => {
                // This shouldn't be possible at all.
                warn!("Failed to receive response to publish request, sender dropped.");
                Ok(Response {
                    message: ServiceFault::new(self.request_handle, StatusCode::BadInternalError)
                        .into(),
                    request_id: self.request_id,
                })
            }
        }
    }
}

struct Request<T> {
    pub request: Box<T>,
    pub request_id: u32,
    pub request_handle: u32,
    pub info: Arc<ServerInfo>,
    pub session: Arc<RwLock<Session>>,
    pub token: UserToken,
    pub subscriptions: Arc<SubscriptionCache>,
    pub session_id: u32,
}

macro_rules! service_fault {
    ($req:ident, $status:expr) => {
        Response {
            message: ServiceFault::new($req.request_handle, $status).into(),
            request_id: $req.request_id,
        }
    };
}

impl<T> Request<T> {
    pub fn new(
        request: Box<T>,
        info: Arc<ServerInfo>,
        request_id: u32,
        request_handle: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
        subscriptions: Arc<SubscriptionCache>,
        session_id: u32,
    ) -> Self {
        Self {
            request,
            request_id,
            request_handle,
            info,
            session,
            token,
            subscriptions,
            session_id,
        }
    }

    pub fn service_fault(&self, status_code: StatusCode) -> Response {
        Response {
            message: ServiceFault::new(self.request_handle, status_code).into(),
            request_id: self.request_id,
        }
    }

    pub fn context(&self) -> RequestContext {
        RequestContext {
            session: self.session.clone(),
            authenticator: self.info.authenticator.clone(),
            token: self.token.clone(),
            current_node_manager_index: 0,
            type_tree: self.info.type_tree.clone(),
            subscriptions: self.subscriptions.clone(),
            session_id: self.session_id,
        }
    }
}

macro_rules! async_service_call {
    ($m:ident, $slf:ident, $req:ident, $r:ident) => {
        HandleMessageResult::AsyncMessage(tokio::task::spawn(Self::$m(
            $slf.node_managers.clone(),
            Request::new(
                $req,
                $slf.info.clone(),
                $r.request_id,
                $r.request_handle,
                $r.session,
                $r.token,
                $slf.subscriptions.clone(),
                $r.session_id,
            ),
        )))
    };
}

struct RequestData {
    request_id: u32,
    request_handle: u32,
    session: Arc<RwLock<Session>>,
    token: UserToken,
    session_id: u32,
}

impl MessageHandler {
    pub fn new(
        info: Arc<ServerInfo>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        Self {
            node_managers,
            info,
            subscriptions,
        }
    }

    pub fn handle_message(
        &mut self,
        message: SupportedMessage,
        session_id: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
        request_id: u32,
    ) -> HandleMessageResult {
        let data = RequestData {
            request_id,
            request_handle: message.request_handle(),
            session,
            token,
            session_id,
        };
        // Session management requests are not handled here.
        match message {
            SupportedMessage::ReadRequest(request) => {
                async_service_call!(read, self, request, data)
            }

            SupportedMessage::BrowseRequest(request) => {
                async_service_call!(browse, self, request, data)
            }

            SupportedMessage::BrowseNextRequest(request) => {
                async_service_call!(browse_next, self, request, data)
            }

            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                async_service_call!(translate_browse_paths, self, request, data)
            }

            SupportedMessage::RegisterNodesRequest(request) => {
                async_service_call!(register_nodes, self, request, data)
            }

            SupportedMessage::UnregisterNodesRequest(request) => {
                async_service_call!(unregister_nodes, self, request, data)
            }

            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                async_service_call!(create_monitored_items, self, request, data)
            }

            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                async_service_call!(modify_monitored_items, self, request, data)
            }

            SupportedMessage::SetMonitoringModeRequest(request) => {
                async_service_call!(set_monitoring_mode, self, request, data)
            }

            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                async_service_call!(delete_monitored_items, self, request, data)
            }

            SupportedMessage::SetTriggeringRequest(request) => self.set_triggering(request, data),

            SupportedMessage::PublishRequest(request) => self.publish(request, data),

            SupportedMessage::RepublishRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions.republish(data.session_id, &request),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::CreateSubscriptionRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions.create_subscription(
                        data.session_id,
                        &data.session,
                        &request,
                        &self.info,
                    ),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::ModifySubscriptionRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions
                        .modify_subscription(data.session_id, &request, &self.info),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::SetPublishingModeRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions
                        .set_publishing_mode(data.session_id, &request),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::TransferSubscriptionsRequest(request) => {
                HandleMessageResult::SyncMessage(Response {
                    message: self
                        .subscriptions
                        .transfer(&request, data.session_id, &data.session)
                        .into(),
                    request_id: data.request_id,
                })
            }

            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                async_service_call!(delete_subscriptions, self, request, data)
            }

            message => {
                debug!(
                    "Message handler does not handle this kind of message {:?}",
                    message
                );
                HandleMessageResult::SyncMessage(Response {
                    message: ServiceFault::new(
                        message.request_header(),
                        StatusCode::BadServiceUnsupported,
                    )
                    .into(),
                    request_id,
                })
            }
        }
    }

    async fn read(node_managers: NodeManagers, request: Request<ReadRequest>) -> Response {
        let num_nodes = request
            .request
            .nodes_to_read
            .as_ref()
            .map(|r| r.len())
            .unwrap_or_default();
        if num_nodes == 0 {
            return request.service_fault(StatusCode::BadNothingToDo);
        }
        if request.request.max_age < 0.0 {
            return request.service_fault(StatusCode::BadMaxAgeInvalid);
        }
        if request.request.timestamps_to_return == TimestampsToReturn::Invalid {
            return request.service_fault(StatusCode::BadTimestampsToReturnInvalid);
        }
        if num_nodes > request.info.operational_limits.max_nodes_per_read {
            return request.service_fault(StatusCode::BadTooManyOperations);
        }
        let mut context = request.context();

        let mut results: Vec<_> = request
            .request
            .nodes_to_read
            .unwrap_or_default()
            .into_iter()
            .map(|n| ReadNode::new(n))
            .collect();

        for (idx, node_manager) in node_managers.into_iter().enumerate() {
            context.current_node_manager_index = idx;
            if let Err(e) = node_manager
                .read(
                    &context,
                    request.request.max_age,
                    request.request.timestamps_to_return,
                    &mut results,
                )
                .await
            {
                for node in &mut results {
                    if node_manager.owns_node(&node.node().node_id) {
                        node.set_error(e);
                    }
                }
            }
        }

        let results = results.into_iter().map(|r| r.take_result()).collect();

        Response {
            message: ReadResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn browse(node_managers: NodeManagers, request: Request<BrowseRequest>) -> Response {
        let num_nodes = request
            .request
            .nodes_to_browse
            .as_ref()
            .map(|r| r.len())
            .unwrap_or_default();
        if num_nodes == 0 {
            return request.service_fault(StatusCode::BadNothingToDo);
        }
        if !request.request.view.view_id.is_null() || !request.request.view.timestamp.is_null() {
            info!("Browse request ignored because view was specified (views not supported)");
            return request.service_fault(StatusCode::BadViewIdUnknown);
        }
        if num_nodes > request.info.operational_limits.max_nodes_per_browse {
            return request.service_fault(StatusCode::BadTooManyOperations);
        }

        let mut context = request.context();

        let max_references_per_node = if request.request.requested_max_references_per_node == 0 {
            request
                .info
                .operational_limits
                .max_references_per_browse_node
        } else {
            request
                .info
                .operational_limits
                .max_references_per_browse_node
                .min(request.request.requested_max_references_per_node as usize)
        };

        let mut nodes: Vec<_> = request
            .request
            .nodes_to_browse
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(idx, r)| BrowseNode::new(r, max_references_per_node, idx))
            .collect();

        let mut results: Vec<_> = (0..nodes.len()).map(|_| None).collect();
        let node_manager_count = node_managers.len();

        for (node_manager_index, node_manager) in node_managers.iter().enumerate() {
            context.current_node_manager_index = node_manager_index;

            if let Err(e) = node_manager.browse(&context, &mut nodes).await {
                for node in &mut nodes {
                    if node_manager.owns_node(&node.node_id()) {
                        node.set_status(e);
                    }
                }
            }
            // Iterate over the current nodes, removing unfinished ones, and storing
            // continuation points when relevant.
            // This does not preserve ordering, for efficiency, so node managers should
            // not rely on ordering at all.
            // We store the input index to make sure the results are correctly ordered.
            let mut i = 0;
            let mut session = request.session.write();
            while let Some(n) = nodes.get(i) {
                if n.is_completed() {
                    let (result, input_index) = nodes.swap_remove(i).into_result(
                        node_manager_index,
                        node_manager_count,
                        &mut session,
                    );
                    results[input_index] = Some(result);
                } else {
                    i += 1;
                }
            }

            if nodes.is_empty() {
                break;
            }
        }

        // Process external references

        // Any remaining nodes may have an external ref continuation point, process these before proceeding.
        {
            let type_tree = trace_read_lock!(context.type_tree);
            for node in nodes.iter_mut() {
                if let Some(mut p) = node.take_continuation_point::<ExternalReferencesContPoint>() {
                    while node.remaining() > 0 {
                        let Some(rf) = p.items.pop_front() else {
                            break;
                        };
                        node.add(&type_tree, rf);
                    }

                    if !p.items.is_empty() {
                        node.set_next_continuation_point(p);
                    }
                }
            }
        }

        // Gather a unique list of all references
        let mut external_refs = HashMap::new();
        for (rf, mask) in nodes
            .iter()
            .flat_map(|n| n.get_external_refs().map(|r| (r, n.result_mask())))
        {
            // OR together the masks, so that if (for some reason) a user requests different
            // masks for two nodes but they return a reference to the same node, we use the widest
            // available mask...
            external_refs
                .entry(rf)
                .and_modify(|m| *m |= mask)
                .or_insert(mask);
        }

        // Actually resolve the references
        let external_refs: Vec<_> = external_refs.into_iter().collect();
        let node_meta = resolve_external_references(&context, &node_managers, &external_refs).await;
        let node_map: HashMap<_, _> = node_meta
            .iter()
            .filter_map(|n| n.as_ref())
            .map(|n| (&n.node_id.node_id, n))
            .collect();

        // Finally, process all remaining nodes, including external references
        {
            let mut session = request.session.write();
            let type_tree = trace_read_lock!(context.type_tree);
            for mut node in nodes {
                node.resolve_external_references(&type_tree, &node_map);

                let (result, input_index) =
                    node.into_result(node_manager_count - 1, node_manager_count, &mut session);
                results[input_index] = Some(result);
            }
        }

        // Cannot be None here, since we are guaranteed to always empty out nodes.
        let results = results.into_iter().map(Option::unwrap).collect();

        Response {
            message: BrowseResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn browse_next(
        node_managers: NodeManagers,
        request: Request<BrowseNextRequest>,
    ) -> Response {
        let num_nodes = request
            .request
            .continuation_points
            .as_ref()
            .map(|r| r.len())
            .unwrap_or_default();
        if num_nodes == 0 {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }
        if num_nodes > request.info.operational_limits.max_nodes_per_browse {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }
        let mut context = request.context();

        let mut results: Vec<_> = (0..num_nodes).map(|_| None).collect();

        let mut nodes = {
            let mut session = trace_write_lock!(request.session);
            let mut nodes = Vec::with_capacity(num_nodes);
            for (idx, point) in request
                .request
                .continuation_points
                .unwrap_or_default()
                .into_iter()
                .enumerate()
            {
                let point = session.remove_browse_continuation_point(&point);
                if let Some(point) = point {
                    nodes.push(BrowseNode::from_continuation_point(point, idx));
                } else {
                    results[idx] = Some(BrowseResult {
                        status_code: StatusCode::BadContinuationPointInvalid,
                        continuation_point: ByteString::null(),
                        references: None,
                    });
                }
            }
            nodes
        };

        let results = if request.request.release_continuation_points {
            results
                .into_iter()
                .map(|r| {
                    r.unwrap_or_else(|| BrowseResult {
                        status_code: StatusCode::Good,
                        continuation_point: ByteString::null(),
                        references: None,
                    })
                })
                .collect()
        } else {
            let node_manager_count = node_managers.len();

            let mut batch_nodes = Vec::with_capacity(nodes.len());

            for (node_manager_index, node_manager) in node_managers.iter().enumerate() {
                context.current_node_manager_index = node_manager_index;
                let mut i = 0;
                // Get all the nodes with a continuation point at the current node manager.
                // We collect these as we iterate through the node managers.
                while let Some(n) = nodes.get(i) {
                    if n.start_node_manager == node_manager_index {
                        batch_nodes.push(nodes.swap_remove(i));
                    } else {
                        i += 1;
                    }
                }

                if let Err(e) = node_manager.browse(&context, &mut batch_nodes).await {
                    for node in &mut nodes {
                        if node_manager.owns_node(node.node_id()) {
                            node.set_status(e);
                        }
                    }
                }
                // Iterate over the current nodes, removing unfinished ones, and storing
                // continuation points when relevant.
                // This does not preserve ordering, for efficiency, so node managers should
                // not rely on ordering at all.
                // We store the input index to make sure the results are correctly ordered.
                let mut i = 0;
                let mut session = request.session.write();
                while let Some(n) = batch_nodes.get(i) {
                    if n.is_completed() {
                        let (result, input_index) = batch_nodes.swap_remove(i).into_result(
                            node_manager_index,
                            node_manager_count,
                            &mut session,
                        );
                        results[input_index] = Some(result);
                    } else {
                        i += 1;
                    }
                }

                if nodes.is_empty() && batch_nodes.is_empty() {
                    break;
                }
            }

            // Process external references

            // Any remaining nodes may have an external ref continuation point, process these before proceeding.
            {
                let type_tree = trace_read_lock!(context.type_tree);
                for node in nodes.iter_mut() {
                    if let Some(mut p) =
                        node.take_continuation_point::<ExternalReferencesContPoint>()
                    {
                        while node.remaining() > 0 {
                            let Some(rf) = p.items.pop_front() else {
                                break;
                            };
                            node.add(&type_tree, rf);
                        }

                        if !p.items.is_empty() {
                            node.set_next_continuation_point(p);
                        }
                    }
                }
            }

            // Gather a unique list of all references
            let mut external_refs = HashMap::new();
            for (rf, mask) in nodes
                .iter()
                .chain(batch_nodes.iter())
                .flat_map(|n| n.get_external_refs().map(|r| (r, n.result_mask())))
            {
                // OR together the masks, so that if (for some reason) a user requests different
                // masks for two nodes but they return a reference to the same node, we use the widest
                // available mask...
                external_refs
                    .entry(rf)
                    .and_modify(|m| *m |= mask)
                    .or_insert(mask);
            }

            // Actually resolve the references
            let external_refs: Vec<_> = external_refs.into_iter().collect();
            let node_meta =
                resolve_external_references(&context, &node_managers, &external_refs).await;
            let node_map: HashMap<_, _> = node_meta
                .iter()
                .filter_map(|n| n.as_ref())
                .map(|n| (&n.node_id.node_id, n))
                .collect();

            // Finally, process all remaining nodes, including external references.
            // This may still produce a continuation point, for external references.
            {
                let mut session = request.session.write();
                let type_tree = trace_read_lock!(context.type_tree);
                for mut node in nodes.into_iter().chain(batch_nodes.into_iter()) {
                    node.resolve_external_references(&type_tree, &node_map);

                    let (result, input_index) =
                        node.into_result(node_manager_count - 1, node_manager_count, &mut session);
                    results[input_index] = Some(result);
                }
            }

            // Cannot be None here, since we are guaranteed to always empty out nodes.
            results.into_iter().map(Option::unwrap).collect()
        };

        Response {
            message: BrowseNextResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn translate_browse_paths(
        node_managers: NodeManagers,
        request: Request<TranslateBrowsePathsToNodeIdsRequest>,
    ) -> Response {
        // - We're given a list of (NodeId, BrowsePath) pairs
        // - For a node manager, ask them to explore the browse path, returning _all_ visited nodes in each layer.
        // - This extends the list of (NodeId, BrowsePath) pairs, though each new node should have a shorter browse path.
        // - We keep which node managers returned which nodes. Once every node manager has been asked about every
        //   returned node, the service is finished and we can collect all the node IDs in the bottom layer.

        let mut context = request.context();

        let Some(paths) = request.request.browse_paths else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };

        if paths.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }

        if paths.len()
            > request
                .info
                .operational_limits
                .max_nodes_per_translate_browse_paths_to_node_ids
        {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }

        let mut items: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| BrowsePathItem::new_root(p, i))
            .collect();

        let mut idx = 0;
        let mut iteration = 1;
        let mut any_new_items_in_iteration = false;
        let mut final_results = Vec::new();
        loop {
            let mgr = &node_managers[idx];
            let mut chunk: Vec<_> = items
                .iter_mut()
                .filter(|it| {
                    // Item has not yet been marked bad, meaning it failed to resolve somewhere it should.
                    it.status().is_good()
                        // Either it's from a previous node manager,
                        && (it.node_manager_index() < idx
                            // Or it's not from a later node manager in the previous iteration.
                            || it.node_manager_index() > idx
                                && it.iteration_number() == iteration - 1)
                        // Or it may be an external reference with an unmatched browse name.
                        && (!it.path().is_empty() || it.unmatched_browse_name().is_some() && mgr.owns_node(it.node_id()))
                })
                .collect();
            context.current_node_manager_index = idx;

            if !chunk.is_empty() {
                // Call translate on any of the target IDs.
                if let Err(e) = mgr
                    .translate_browse_paths_to_node_ids(&context, &mut chunk)
                    .await
                {
                    for n in &mut chunk {
                        if mgr.owns_node(n.node_id()) {
                            n.set_status(e);
                        }
                    }
                } else {
                    let mut next = Vec::new();
                    for n in &mut chunk {
                        let index = n.input_index();
                        for el in n.results_mut().drain(..) {
                            next.push((el, index));
                        }
                        if n.path().is_empty() && n.unmatched_browse_name().is_none() {
                            final_results.push(n.clone())
                        }
                    }

                    for (n, input_index) in next {
                        let item = BrowsePathItem::new(
                            n,
                            input_index,
                            &items[input_index],
                            idx,
                            iteration,
                        );
                        if item.path().is_empty() && item.unmatched_browse_name().is_none() {
                            final_results.push(item);
                        } else {
                            any_new_items_in_iteration = true;
                            items.push(item);
                        }
                    }
                }
            }

            idx += 1;
            if idx == node_managers.len() {
                idx = 0;
                iteration += 1;
                if !any_new_items_in_iteration {
                    break;
                }
                any_new_items_in_iteration = false;
            }

            idx = (idx + 1) % node_managers.len();
        }
        // Collect all final paths.
        let mut results: Vec<_> = items
            .iter()
            .take(paths.len())
            .map(|p| BrowsePathResult {
                status_code: p.status(),
                targets: Some(Vec::new()),
            })
            .collect();

        for res in final_results {
            results[res.input_index()]
                .targets
                .as_mut()
                .unwrap()
                .push(BrowsePathTarget {
                    target_id: res.node.into(),
                    // External server references are not yet supported.
                    remaining_path_index: u32::MAX,
                });
        }

        for res in results.iter_mut() {
            if res.targets.is_none() || res.targets.as_ref().is_some_and(|t| t.is_empty()) {
                res.targets = None;
                if res.status_code.is_good() {
                    res.status_code = StatusCode::BadNoMatch;
                }
            }
        }

        Response {
            message: TranslateBrowsePathsToNodeIdsResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn register_nodes(
        node_managers: NodeManagers,
        request: Request<RegisterNodesRequest>,
    ) -> Response {
        let context = request.context();

        let Some(nodes_to_register) = request.request.nodes_to_register else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };

        if nodes_to_register.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }

        if nodes_to_register.len() > request.info.operational_limits.max_nodes_per_register_nodes {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }

        let mut items: Vec<_> = nodes_to_register
            .into_iter()
            .map(|n| RegisterNodeItem::new(n))
            .collect();

        for mgr in node_managers {
            let mut owned: Vec<_> = items
                .iter_mut()
                .filter(|n| mgr.owns_node(n.node_id()))
                .collect();

            if owned.is_empty() {
                continue;
            }

            // All errors are fatal in this case, node managers should avoid them.
            if let Err(e) = mgr.register_nodes(&context, &mut owned).await {
                error!("Register nodes failed for node manager {}: {e}", mgr.name());
                return service_fault!(request, e);
            }
        }

        let registered_node_ids: Vec<_> =
            items.into_iter().filter_map(|n| n.into_result()).collect();

        Response {
            message: RegisterNodesResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                registered_node_ids: Some(registered_node_ids),
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn unregister_nodes(
        node_managers: NodeManagers,
        request: Request<UnregisterNodesRequest>,
    ) -> Response {
        let context = request.context();

        let Some(nodes_to_unregister) = request.request.nodes_to_unregister else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };

        if nodes_to_unregister.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }

        if nodes_to_unregister.len() > request.info.operational_limits.max_nodes_per_register_nodes
        {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }

        for mgr in node_managers {
            let owned: Vec<_> = nodes_to_unregister
                .iter()
                .filter(|n| mgr.owns_node(n))
                .collect();

            if owned.is_empty() {
                continue;
            }

            // All errors are fatal in this case, node managers should avoid them.
            if let Err(e) = mgr.unregister_nodes(&context, &owned).await {
                error!(
                    "Unregister nodes failed for node manager {}: {e}",
                    mgr.name()
                );
                return service_fault!(request, e);
            }
        }

        Response {
            message: UnregisterNodesResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn create_monitored_items(
        node_managers: NodeManagers,
        request: Request<CreateMonitoredItemsRequest>,
    ) -> Response {
        let context = request.context();
        let Some(items_to_create) = request.request.items_to_create else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };
        if items_to_create.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }
        if items_to_create.len() > request.info.operational_limits.max_monitored_items_per_call {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }
        let Some(len) = request
            .subscriptions
            .get_monitored_item_count(request.session_id, request.request.subscription_id)
        else {
            return service_fault!(request, StatusCode::BadSubscriptionIdInvalid);
        };

        let max_per_sub = request
            .info
            .config
            .limits
            .subscriptions
            .max_monitored_items_per_sub;
        if max_per_sub > 0 && max_per_sub < len + items_to_create.len() {
            return service_fault!(request, StatusCode::BadTooManyMonitoredItems);
        }

        let mut items: Vec<_> = items_to_create
            .into_iter()
            .map(|r| {
                CreateMonitoredItem::new(
                    r,
                    request.info.monitored_item_id_handle.next(),
                    request.request.subscription_id,
                    &request.info,
                    request.request.timestamps_to_return,
                )
            })
            .collect();

        for mgr in &node_managers {
            let owned: Vec<_> = items
                .iter_mut()
                .filter(|n| {
                    n.status_code().is_good() && mgr.owns_node(&n.item_to_monitor().node_id)
                })
                .collect();

            if owned.is_empty() {
                continue;
            }

            if let Err(e) = mgr.create_monitored_items(&context, &owned).await {
                for n in owned {
                    n.set_status(e);
                }
            }
        }

        let handles: Vec<_> = items.iter().map(|i| i.handle()).collect();

        let res = match request.subscriptions.create_monitored_items(
            request.session_id,
            request.request.subscription_id,
            items,
        ) {
            Ok(r) => r,
            // Shouldn't happen, would be due to a race condition. If it does happen we're fine with failing.
            Err(e) => {
                // Should clean up any that failed to create though.
                for mgr in &node_managers {
                    mgr.delete_monitored_items(&context, &handles).await;
                }
                return service_fault!(request, e);
            }
        };

        Response {
            message: CreateMonitoredItemsResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(res),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn modify_monitored_items(
        node_managers: NodeManagers,
        request: Request<ModifyMonitoredItemsRequest>,
    ) -> Response {
        let context = request.context();
        let Some(items_to_modify) = request.request.items_to_modify else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };
        if items_to_modify.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }
        if items_to_modify.len() > request.info.operational_limits.max_monitored_items_per_call {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }

        // Call modify first, then only pass successful modify's to the node managers.
        let results = match request.subscriptions.modify_monitored_items(
            request.session_id,
            request.request.subscription_id,
            &request.info,
            request.request.timestamps_to_return,
            items_to_modify,
        ) {
            Ok(r) => r,
            Err(e) => return service_fault!(request, e),
        };

        for mgr in node_managers {
            let owned: Vec<_> = results
                .iter()
                .filter(|n| n.0.status_code.is_good() && mgr.owns_node(&n.1))
                .map(|n| &n.0)
                .collect();

            if owned.is_empty() {
                continue;
            }

            mgr.modify_monitored_items(&context, request.request.subscription_id, &owned)
                .await;
        }

        Response {
            message: ModifyMonitoredItemsResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results.into_iter().map(|r| r.0).collect()),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn set_monitoring_mode(
        node_managers: NodeManagers,
        request: Request<SetMonitoringModeRequest>,
    ) -> Response {
        let context = request.context();
        let Some(items) = request.request.monitored_item_ids else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };
        if items.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }
        if items.len() > request.info.operational_limits.max_monitored_items_per_call {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }

        let results = match request.subscriptions.set_monitoring_mode(
            request.session_id,
            request.request.subscription_id,
            request.request.monitoring_mode,
            items,
        ) {
            Ok(r) => r,
            Err(e) => return service_fault!(request, e),
        };

        for mgr in node_managers {
            let owned: Vec<_> = results
                .iter()
                .filter(|n| n.1.is_good() && mgr.owns_node(&n.2))
                .map(|n| n.0)
                .collect();

            if owned.is_empty() {
                continue;
            }

            mgr.set_monitoring_mode(
                &context,
                request.request.monitoring_mode,
                request.request.subscription_id,
                &owned,
            )
            .await;
        }

        Response {
            message: SetMonitoringModeResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results.into_iter().map(|r| r.1).collect()),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn delete_monitored_items(
        node_managers: NodeManagers,
        request: Request<DeleteMonitoredItemsRequest>,
    ) -> Response {
        let context = request.context();
        let Some(items) = request.request.monitored_item_ids else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };
        if items.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }
        if items.len() > request.info.operational_limits.max_monitored_items_per_call {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }

        let results = match request.subscriptions.delete_monitored_items(
            request.session_id,
            request.request.subscription_id,
            &items,
        ) {
            Ok(r) => r,
            Err(e) => return service_fault!(request, e),
        };

        for mgr in node_managers {
            let owned: Vec<_> = results
                .iter()
                .filter(|n| n.1.is_good() && mgr.owns_node(&n.2))
                .map(|n| n.0)
                .collect();

            if owned.is_empty() {
                continue;
            }

            mgr.delete_monitored_items(&context, &owned).await;
        }

        Response {
            message: DeleteMonitoredItemsResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results.into_iter().map(|r| r.1).collect()),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn delete_subscriptions(
        node_managers: NodeManagers,
        request: Request<DeleteSubscriptionsRequest>,
    ) -> Response {
        let context = request.context();
        let Some(items) = request.request.subscription_ids else {
            return service_fault!(request, StatusCode::BadNothingToDo);
        };
        if items.is_empty() {
            return service_fault!(request, StatusCode::BadNothingToDo);
        }

        let results = match Self::delete_subscriptions_inner(
            node_managers,
            items,
            &request.subscriptions,
            &context,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return service_fault!(request, e),
        };

        Response {
            message: DeleteSubscriptionsResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(results),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        }
    }

    async fn delete_subscriptions_inner(
        node_managers: NodeManagers,
        to_delete: Vec<u32>,
        subscriptions: &SubscriptionCache,
        context: &RequestContext,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        let results = subscriptions.delete_subscriptions(context.session_id, &to_delete)?;

        for mgr in node_managers {
            let owned: Vec<_> = results
                .iter()
                .filter(|f| f.0.is_good())
                .flat_map(|f| f.1.iter().filter(|i| mgr.owns_node(&i.1)))
                .map(|i| i.0)
                .collect();

            if owned.is_empty() {
                continue;
            }

            mgr.delete_monitored_items(&context, &owned).await;
        }

        Ok(results.into_iter().map(|r| r.0).collect())
    }

    pub async fn delete_session_subscriptions(
        &mut self,
        session_id: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
    ) {
        let ids = self.subscriptions.get_session_subscription_ids(session_id);
        if ids.is_empty() {
            return;
        }

        let context = RequestContext {
            session,
            session_id,
            authenticator: self.info.authenticator.clone(),
            token,
            current_node_manager_index: 0,
            type_tree: self.info.type_tree.clone(),
            subscriptions: self.subscriptions.clone(),
        };

        // Ignore the result
        if let Err(e) = Self::delete_subscriptions_inner(
            self.node_managers.clone(),
            ids,
            &self.subscriptions,
            &context,
        )
        .await
        {
            warn!("Cleaning up session subscriptions failed: {e}");
        }
    }

    fn set_triggering(
        &self,
        request: Box<SetTriggeringRequest>,
        data: RequestData,
    ) -> HandleMessageResult {
        let result = self
            .subscriptions
            .set_triggering(
                data.session_id,
                request.subscription_id,
                request.triggering_item_id,
                request.links_to_add.unwrap_or_default(),
                request.links_to_remove.unwrap_or_default(),
            )
            .map(|(add_res, remove_res)| SetTriggeringResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                add_results: Some(add_res),
                add_diagnostic_infos: None,
                remove_results: Some(remove_res),
                remove_diagnostic_infos: None,
            });

        HandleMessageResult::SyncMessage(Response::from_result(
            result,
            data.request_handle,
            data.request_id,
        ))
    }

    fn publish(&self, request: Box<PublishRequest>, data: RequestData) -> HandleMessageResult {
        let now = Utc::now();
        let now_instant = Instant::now();
        let (send, recv) = tokio::sync::oneshot::channel();
        let timeout = request.request_header.timeout_hint;
        let timeout = if timeout == 0 {
            self.info.config.publish_timeout_default_ms
        } else {
            timeout.into()
        };

        let req = PendingPublish {
            response: send,
            request,
            ack_results: None,
            deadline: now_instant + std::time::Duration::from_millis(timeout),
        };
        match self
            .subscriptions
            .enqueue_publish_request(data.session_id, &now, now_instant, req)
        {
            Ok(_) => HandleMessageResult::PublishResponse(PendingPublishRequest {
                request_id: data.request_id,
                request_handle: data.request_handle,
                recv,
            }),
            Err(e) => HandleMessageResult::SyncMessage(Response {
                message: ServiceFault::new(data.request_handle, e).into(),
                request_id: data.request_id,
            }),
        }
    }
}
