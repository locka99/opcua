use crate::{
    server::{
        node_manager::{NodeManagers, ParsedNodeTypeDescription, QueryRequest},
        session::{controller::Response, message_handler::Request},
        ParsedContentFilter,
    },
    types::{
        ByteString, QueryFirstRequest, QueryFirstResponse, QueryNextRequest, QueryNextResponse,
        ResponseHeader, StatusCode,
    },
};

pub async fn query_first(
    node_managers: NodeManagers,
    request: Request<QueryFirstRequest>,
) -> Response {
    let mut context = request.context();
    let node_types = take_service_items!(
        request,
        request.request.node_types,
        request.info.operational_limits.max_node_descs_per_query
    );
    let data_sets_limit = request.info.operational_limits.max_data_sets_query_return;
    let references_limit = request.info.operational_limits.max_references_query_return;
    let max_data_sets_to_return = if request.request.max_data_sets_to_return == 0 {
        data_sets_limit
    } else {
        data_sets_limit.min(request.request.max_data_sets_to_return as usize)
    };
    let max_references_to_return = if request.request.max_references_to_return == 0 {
        references_limit
    } else {
        references_limit.min(request.request.max_references_to_return as usize)
    };
    if !request.request.view.view_id.is_null() || !request.request.view.timestamp.is_null() {
        info!("Browse request ignored because view was specified (views not supported)");
        return service_fault!(request, StatusCode::BadViewIdUnknown);
    }

    let mut status_code = StatusCode::Good;

    let mut parsing_results = Vec::with_capacity(node_types.len());
    let mut final_node_types = Vec::with_capacity(node_types.len());
    for node_type in node_types {
        let (res, parsed) = ParsedNodeTypeDescription::parse(node_type);
        if let Ok(parsed) = parsed {
            final_node_types.push(parsed);
        } else {
            status_code = StatusCode::BadInvalidArgument;
        }
        parsing_results.push(res);
    }

    let (filter_result, filter) = {
        let type_tree = trace_read_lock!(request.info.type_tree);
        ParsedContentFilter::parse(request.request.filter, &type_tree, false, false)
    };

    let content_filter = match filter {
        Ok(r) => r,
        Err(e) => {
            status_code = e;
            ParsedContentFilter::empty()
        }
    };

    if status_code.is_bad() {
        return Response {
            message: QueryFirstResponse {
                response_header: ResponseHeader::new_service_result(
                    request.request_handle,
                    status_code,
                ),
                query_data_sets: None,
                continuation_point: ByteString::null(),
                parsing_results: Some(parsing_results),
                filter_result,
                diagnostic_infos: None,
            }
            .into(),
            request_id: request.request_id,
        };
    }

    let mut query_request = QueryRequest::new(
        final_node_types,
        content_filter,
        max_data_sets_to_return,
        max_references_to_return,
    );

    for (index, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = index;
        // All node managers must succeed. Partial success is really
        // hard to quantify for query...
        // TODO: This is pretty much impossible to implement
        // until we actually implement this in the core node manager.
        if let Err(e) = node_manager.query(&context, &mut query_request).await {
            return Response {
                message: QueryFirstResponse {
                    response_header: ResponseHeader::new_service_result(request.request_handle, e),
                    query_data_sets: None,
                    continuation_point: ByteString::null(),
                    parsing_results: Some(parsing_results),
                    filter_result,
                    diagnostic_infos: None,
                }
                .into(),
                request_id: request.request_id,
            };
        }

        if query_request.is_completed() {
            break;
        }
    }
    let (result, continuation_point, status) = {
        let mut session = trace_write_lock!(request.session);
        query_request.into_result(
            context.current_node_manager_index,
            node_managers.len(),
            &mut session,
        )
    };

    Response {
        message: QueryFirstResponse {
            response_header: ResponseHeader::new_service_result(request.request_handle, status),
            query_data_sets: Some(result),
            continuation_point,
            parsing_results: None,
            diagnostic_infos: None,
            filter_result,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn query_next(
    node_managers: NodeManagers,
    request: Request<QueryNextRequest>,
) -> Response {
    let mut context = request.context();
    let mut query_request = {
        let mut session = trace_write_lock!(request.session);
        let Some(p) = session.remove_query_continuation_point(&request.request.continuation_point)
        else {
            return service_fault!(request, StatusCode::BadContinuationPointInvalid);
        };
        QueryRequest::from_continuation_point(p)
    };

    if request.request.release_continuation_point {
        return Response {
            message: QueryNextResponse {
                response_header: ResponseHeader::new_good(request.request_handle),
                query_data_sets: None,
                revised_continuation_point: ByteString::null(),
            }
            .into(),
            request_id: request.request_id,
        };
    }

    for (index, node_manager) in node_managers.iter().enumerate() {
        if index < query_request.node_manager_index() {
            continue;
        }
        context.current_node_manager_index = index;

        if let Err(e) = node_manager.query(&context, &mut query_request).await {
            return service_fault!(request, e);
        }

        if query_request.is_completed() {
            break;
        }
    }

    let (result, continuation_point, status) = {
        let mut session = trace_write_lock!(request.session);
        query_request.into_result(
            context.current_node_manager_index,
            node_managers.len(),
            &mut session,
        )
    };

    Response {
        message: QueryNextResponse {
            response_header: ResponseHeader::new_service_result(request.request_handle, status),
            query_data_sets: Some(result),
            revised_continuation_point: continuation_point,
        }
        .into(),
        request_id: request.request_id,
    }
}
