use crate::{
    async_server::{
        node_manager::{
            HistoryNode, HistoryReadDetails, HistoryUpdateDetails, HistoryUpdateNode, NodeManagers,
            ReadNode, WriteNode,
        },
        session::{controller::Response, message_handler::Request},
    },
    server::prelude::{
        ByteString, DeleteAtTimeDetails, ExtensionObject, HistoryReadRequest, HistoryReadResponse,
        HistoryReadResult, HistoryUpdateRequest, HistoryUpdateResponse, NodeId, ObjectId,
        ReadRequest, ReadResponse, ResponseHeader, StatusCode, TimestampsToReturn, WriteRequest,
        WriteResponse,
    },
};
pub async fn read(node_managers: NodeManagers, request: Request<ReadRequest>) -> Response {
    let mut context = request.context();
    let nodes_to_read = take_service_items!(
        request,
        request.request.nodes_to_read,
        request.info.operational_limits.max_nodes_per_read
    );
    if request.request.max_age < 0.0 {
        return service_fault!(request, StatusCode::BadMaxAgeInvalid);
    }
    if request.request.timestamps_to_return == TimestampsToReturn::Invalid {
        return service_fault!(request, StatusCode::BadTimestampsToReturnInvalid);
    }

    let mut results: Vec<_> = nodes_to_read
        .into_iter()
        .map(|n| ReadNode::new(n))
        .collect();

    for (idx, node_manager) in node_managers.into_iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut batch: Vec<_> = results
            .iter_mut()
            .filter(|n| node_manager.owns_node(&n.node().node_id))
            .collect();
        if let Err(e) = node_manager
            .read(
                &context,
                request.request.max_age,
                request.request.timestamps_to_return,
                &mut batch,
            )
            .await
        {
            for node in &mut results {
                node.set_error(e);
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

pub async fn write(node_managers: NodeManagers, request: Request<WriteRequest>) -> Response {
    let mut context = request.context();
    let nodes_to_write = take_service_items!(
        request,
        request.request.nodes_to_write,
        request.info.operational_limits.max_nodes_per_write
    );

    let mut results: Vec<_> = nodes_to_write
        .into_iter()
        .map(|n| WriteNode::new(n))
        .collect();

    for (idx, node_manager) in node_managers.into_iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut batch: Vec<_> = results
            .iter_mut()
            .filter(|n| node_manager.owns_node(&n.value().node_id))
            .collect();
        if let Err(e) = node_manager.write(&context, &mut batch).await {
            for node in &mut results {
                node.set_status(e);
            }
        }
    }

    let results = results.into_iter().map(|r| r.status()).collect();

    Response {
        message: WriteResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(results),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn history_read(
    node_managers: NodeManagers,
    request: Request<HistoryReadRequest>,
) -> Response {
    let context = request.context();
    let Some(items) = request.request.nodes_to_read else {
        return service_fault!(request, StatusCode::BadNothingToDo);
    };
    if items.is_empty() {
        return service_fault!(request, StatusCode::BadNothingToDo);
    }
    let details = match HistoryReadDetails::from_extension_object(
        request.request.history_read_details,
        &request.info.decoding_options(),
    ) {
        Ok(r) => r,
        Err(e) => return service_fault!(request, e),
    };

    if matches!(details, HistoryReadDetails::Events(_)) {
        if items.len()
            > request
                .info
                .operational_limits
                .max_nodes_per_history_read_events
        {
            return service_fault!(request, StatusCode::BadTooManyOperations);
        }
    } else if items.len()
        > request
            .info
            .operational_limits
            .max_nodes_per_history_read_data
    {
        return service_fault!(request, StatusCode::BadTooManyOperations);
    }
    let mut nodes: Vec<_> = {
        let mut session = trace_write_lock!(request.session);
        items
            .into_iter()
            .map(|node| {
                if node.continuation_point.is_null() {
                    let mut node = HistoryNode::new(node, None);
                    if request.request.release_continuation_points {
                        node.set_status(StatusCode::Good);
                    }
                    node
                } else {
                    let cp = session.remove_history_continuation_point(&node.continuation_point);
                    let cp_missing = cp.is_none();
                    let mut node = HistoryNode::new(node, cp);
                    if cp_missing {
                        node.set_status(StatusCode::BadContinuationPointInvalid);
                    } else if request.request.release_continuation_points {
                        node.set_status(StatusCode::Good);
                    }
                    node
                }
            })
            .collect()
    };

    // If we are releasing continuation points we should not return any data.
    if request.request.release_continuation_points {
        return Response {
            message: HistoryReadResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                results: Some(
                    nodes
                        .into_iter()
                        .map(|n| HistoryReadResult {
                            status_code: n.status(),
                            continuation_point: ByteString::null(),
                            history_data: ExtensionObject::null(),
                        })
                        .collect(),
                ),
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        };
    }

    for manager in &node_managers {
        let mut batch: Vec<_> = nodes
            .iter_mut()
            .filter(|n| {
                if n.node_id() == &ObjectId::Server.into()
                    && matches!(details, HistoryReadDetails::Events(_))
                {
                    manager.owns_server_events()
                } else {
                    manager.owns_node(n.node_id()) && n.status() == StatusCode::BadNodeIdUnknown
                }
            })
            .collect();

        if batch.is_empty() {
            continue;
        }

        let result = match &details {
            HistoryReadDetails::RawModified(d) => {
                manager
                    .history_read_raw_modified(
                        &context,
                        d,
                        &mut batch,
                        request.request.timestamps_to_return,
                    )
                    .await
            }
            HistoryReadDetails::AtTime(d) => {
                manager
                    .history_read_at_time(
                        &context,
                        d,
                        &mut batch,
                        request.request.timestamps_to_return,
                    )
                    .await
            }
            HistoryReadDetails::Processed(d) => {
                manager
                    .history_read_processed(
                        &context,
                        d,
                        &mut batch,
                        request.request.timestamps_to_return,
                    )
                    .await
            }
            HistoryReadDetails::Events(d) => {
                manager
                    .history_read_events(
                        &context,
                        d,
                        &mut batch,
                        request.request.timestamps_to_return,
                    )
                    .await
            }
            HistoryReadDetails::Annotations(d) => {
                manager
                    .history_read_annotations(
                        &context,
                        d,
                        &mut batch,
                        request.request.timestamps_to_return,
                    )
                    .await
            }
        };

        if let Err(e) = result {
            for node in batch {
                node.set_status(e);
            }
        }
    }
    let results: Vec<_> = {
        let mut session = trace_write_lock!(request.session);
        nodes
            .into_iter()
            .map(|n| n.into_result(&mut session))
            .collect()
    };

    Response {
        message: HistoryReadResponse {
            response_header: ResponseHeader::new_good(&request.request.request_header),
            results: Some(results),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn history_update(
    node_managers: NodeManagers,
    request: Request<HistoryUpdateRequest>,
) -> Response {
    let context = request.context();
    let items = take_service_items!(
        request,
        request.request.history_update_details,
        request.info.operational_limits.max_nodes_per_history_update
    );
    let decoding_options = request.info.decoding_options();

    let mut nodes: Vec<_> = items
        .into_iter()
        .map(|obj| {
            let details = match HistoryUpdateDetails::from_extension_object(obj, &decoding_options)
            {
                Ok(h) => h,
                Err(e) => {
                    // need some empty history update node here, it won't be passed to node managers.
                    let mut node = HistoryUpdateNode::new(HistoryUpdateDetails::DeleteAtTime(
                        DeleteAtTimeDetails {
                            node_id: NodeId::null(),
                            req_times: None,
                        },
                    ));
                    node.set_status(e);
                    return node;
                }
            };
            HistoryUpdateNode::new(details)
        })
        .collect();

    for manager in &node_managers {
        let mut batch: Vec<_> = nodes
            .iter_mut()
            .filter(|n| {
                if n.details().node_id() == &ObjectId::Server.into()
                    && matches!(
                        n.details(),
                        HistoryUpdateDetails::UpdateEvent(_) | HistoryUpdateDetails::DeleteEvent(_)
                    )
                {
                    manager.owns_server_events()
                } else {
                    manager.owns_node(n.details().node_id())
                        && n.status() == StatusCode::BadNodeIdUnknown
                }
            })
            .collect();

        if batch.is_empty() {
            continue;
        }

        if let Err(e) = manager.history_update(&context, &mut batch).await {
            for node in batch {
                node.set_status(e);
            }
        }
    }
    let results: Vec<_> = nodes.into_iter().map(|n| n.into_result()).collect();

    Response {
        message: HistoryUpdateResponse {
            response_header: ResponseHeader::new_good(&request.request.request_header),
            results: Some(results),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}
