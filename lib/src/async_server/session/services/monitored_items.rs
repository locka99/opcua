use crate::{
    async_server::{
        node_manager::NodeManagers,
        session::{controller::Response, message_handler::Request},
        subscriptions::CreateMonitoredItem,
    },
    server::prelude::{
        CreateMonitoredItemsRequest, CreateMonitoredItemsResponse, DeleteMonitoredItemsRequest,
        DeleteMonitoredItemsResponse, ModifyMonitoredItemsRequest, ModifyMonitoredItemsResponse,
        ResponseHeader, SetMonitoringModeRequest, SetMonitoringModeResponse, StatusCode,
    },
};

pub async fn create_monitored_items(
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

    let mut items: Vec<_> = {
        let type_tree = trace_read_lock!(request.info.type_tree);
        items_to_create
            .into_iter()
            .map(|r| {
                CreateMonitoredItem::new(
                    r,
                    request.info.monitored_item_id_handle.next(),
                    request.request.subscription_id,
                    &request.info,
                    request.request.timestamps_to_return,
                    &type_tree,
                )
            })
            .collect()
    };

    for mgr in &node_managers {
        let mut owned: Vec<_> = items
            .iter_mut()
            .filter(|n| {
                n.status_code() == StatusCode::BadNodeIdUnknown
                    && mgr.owns_node(&n.item_to_monitor().node_id)
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = mgr.create_monitored_items(&context, &mut owned).await {
            for n in owned {
                n.set_status(e);
            }
        }
    }

    let handles: Vec<_> = items
        .iter()
        .map(|i| {
            (
                i.handle(),
                &i.item_to_monitor().node_id,
                i.item_to_monitor().attribute_id,
            )
        })
        .collect();

    let res = match request.subscriptions.create_monitored_items(
        request.session_id,
        request.request.subscription_id,
        &items,
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

pub async fn modify_monitored_items(
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
    let results = {
        let type_tree = trace_read_lock!(request.info.type_tree);

        match request.subscriptions.modify_monitored_items(
            request.session_id,
            request.request.subscription_id,
            &request.info,
            request.request.timestamps_to_return,
            items_to_modify,
            &type_tree,
        ) {
            Ok(r) => r,
            Err(e) => return service_fault!(request, e),
        }
    };

    for mgr in &node_managers {
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.0.status_code.is_good() && mgr.owns_node(&n.1))
            .map(|n| (&n.0, &n.1, n.2))
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.modify_monitored_items(&context, &owned).await;
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

pub async fn set_monitoring_mode(
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

    for mgr in &node_managers {
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.1.is_good() && mgr.owns_node(&n.2))
            .map(|n| (n.0, &n.2, n.3))
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.set_monitoring_mode(&context, request.request.monitoring_mode, &owned)
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

pub async fn delete_monitored_items(
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

    for mgr in &node_managers {
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.1.is_good() && mgr.owns_node(&n.2))
            .map(|n| (n.0, &n.2, n.3))
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
