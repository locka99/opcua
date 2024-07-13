use crate::{
    server::{
        node_manager::{MethodCall, NodeManagers},
        session::{controller::Response, message_handler::Request},
    },
    types::{CallRequest, CallResponse, ResponseHeader, StatusCode},
};

pub async fn call(node_managers: NodeManagers, request: Request<CallRequest>) -> Response {
    let context = request.context();
    let method_calls = take_service_items!(
        request,
        request.request.methods_to_call,
        request.info.operational_limits.max_nodes_per_method_call
    );

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
            for call in owned {
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
