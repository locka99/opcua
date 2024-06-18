use crate::{
    async_server::{
        node_manager::{MethodCall, NodeManagers},
        session::{controller::Response, message_handler::Request},
    },
    server::prelude::{CallRequest, CallResponse, ResponseHeader, StatusCode},
};

pub async fn call(node_managers: NodeManagers, request: Request<CallRequest>) -> Response {
    let context = request.context();
    let Some(method_calls) = request.request.methods_to_call else {
        return service_fault!(request, StatusCode::BadNothingToDo);
    };
    if method_calls.is_empty() {
        return service_fault!(request, StatusCode::BadNothingToDo);
    }
    if method_calls.len() > request.info.operational_limits.max_nodes_per_method_call {
        return service_fault!(request, StatusCode::BadTooManyOperations);
    }

    let mut calls: Vec<_> = method_calls.into_iter().map(MethodCall::new).collect();

    for node_manager in &node_managers {
        let mut owned: Vec<_> = calls
            .iter_mut()
            .filter(|c| {
                node_manager.owns_node(c.method_id()) && c.status() == StatusCode::BadMethodInvalid
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = node_manager.call(&context, &mut owned).await {
            for call in &mut calls {
                call.set_status(e);
            }
        }
    }

    Response {
        message: CallResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(calls.into_iter().map(|c| c.into_result()).collect()),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}
