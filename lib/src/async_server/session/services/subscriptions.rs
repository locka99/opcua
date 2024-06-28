use crate::{
    async_server::{
        node_manager::{NodeManagers, RequestContext},
        session::{controller::Response, message_handler::Request},
        SubscriptionCache,
    },
    server::prelude::{
        DeleteSubscriptionsRequest, DeleteSubscriptionsResponse, ResponseHeader, StatusCode,
    },
};

pub async fn delete_subscriptions(
    node_managers: NodeManagers,
    request: Request<DeleteSubscriptionsRequest>,
) -> Response {
    let context = request.context();
    let items = take_service_items!(
        request,
        request.request.subscription_ids,
        request.info.operational_limits.max_subscriptions_per_call
    );

    let results =
        match delete_subscriptions_inner(node_managers, items, &request.subscriptions, &context)
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
    context: &RequestContext,
) -> Result<Vec<StatusCode>, StatusCode> {
    let results = subscriptions.delete_subscriptions(context.session_id, &to_delete)?;

    for mgr in &node_managers {
        let owned: Vec<_> = results
            .iter()
            .filter(|f| f.0.is_good())
            .flat_map(|f| f.1.iter().filter(|i| mgr.owns_node(&i.1)))
            .map(|i| (i.0, &i.1, i.2))
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.delete_monitored_items(&context, &owned).await;
    }

    Ok(results.into_iter().map(|r| r.0).collect())
}
