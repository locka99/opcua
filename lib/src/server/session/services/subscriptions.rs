use crate::{
    server::{
        node_manager::{NodeManagers, RequestContext},
        session::{controller::Response, message_handler::Request},
        SubscriptionCache,
    },
    types::{DeleteSubscriptionsRequest, DeleteSubscriptionsResponse, ResponseHeader, StatusCode},
};

pub async fn delete_subscriptions(
    node_managers: NodeManagers,
    request: Request<DeleteSubscriptionsRequest>,
) -> Response {
    let mut context = request.context();
    let items = take_service_items!(
        request,
        request.request.subscription_ids,
        request.info.operational_limits.max_subscriptions_per_call
    );

    let results = match delete_subscriptions_inner(
        node_managers,
        items,
        &request.subscriptions,
        &mut context,
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

pub async fn delete_subscriptions_inner(
    node_managers: NodeManagers,
    to_delete: Vec<u32>,
    subscriptions: &SubscriptionCache,
    context: &mut RequestContext,
) -> Result<Vec<StatusCode>, StatusCode> {
    let results = subscriptions.delete_subscriptions(context.session_id, &to_delete)?;

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|f| f.0.is_good())
            .flat_map(|f| f.1.iter().filter(|i| mgr.owns_node(i.node_id())))
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.delete_monitored_items(&context, &owned).await;
    }

    Ok(results.into_iter().map(|r| r.0).collect())
}
