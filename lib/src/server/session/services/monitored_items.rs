use crate::{
    server::{
        node_manager::{MonitoredItemRef, NodeManagers},
        session::{controller::Response, message_handler::Request},
        subscriptions::CreateMonitoredItem,
    },
    types::{
        CreateMonitoredItemsRequest, CreateMonitoredItemsResponse, DeleteMonitoredItemsRequest,
        DeleteMonitoredItemsResponse, ModifyMonitoredItemsRequest, ModifyMonitoredItemsResponse,
        ResponseHeader, SetMonitoringModeRequest, SetMonitoringModeResponse, StatusCode,
    },
};

pub async fn create_monitored_items(
    node_managers: NodeManagers,
    request: Request<CreateMonitoredItemsRequest>,
) -> Response {
    let mut context = request.context();
    let items_to_create = take_service_items!(
        request,
        request.request.items_to_create,
        request.info.operational_limits.max_monitored_items_per_call
    );
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

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
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
            MonitoredItemRef::new(
                i.handle(),
                i.item_to_monitor().node_id.clone(),
                i.item_to_monitor().attribute_id,
            )
        })
        .collect();
    let handles_ref: Vec<_> = handles.iter().collect();

    let res = match request.subscriptions.create_monitored_items(
        request.session_id,
        request.request.subscription_id,
        &items,
    ) {
        Ok(r) => r,
        // Shouldn't happen, would be due to a race condition. If it does happen we're fine with failing.
        Err(e) => {
            // Should clean up any that failed to create though.
            for (idx, mgr) in node_managers.iter().enumerate() {
                context.current_node_manager_index = idx;
                mgr.delete_monitored_items(&context, &handles_ref).await;
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
    let mut context = request.context();
    let items_to_modify = take_service_items!(
        request,
        request.request.items_to_modify,
        request.info.operational_limits.max_monitored_items_per_call
    );

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

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.status_code().is_good() && mgr.owns_node(n.node_id()))
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.modify_monitored_items(&context, &owned).await;
    }

    Response {
        message: ModifyMonitoredItemsResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(results.into_iter().map(|r| r.into_result()).collect()),
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
    let mut context = request.context();
    let items = take_service_items!(
        request,
        request.request.monitored_item_ids,
        request.info.operational_limits.max_monitored_items_per_call
    );

    let results = match request.subscriptions.set_monitoring_mode(
        request.session_id,
        request.request.subscription_id,
        request.request.monitoring_mode,
        items,
    ) {
        Ok(r) => r,
        Err(e) => return service_fault!(request, e),
    };

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.0.is_good() && mgr.owns_node(n.1.node_id()))
            .map(|n| &n.1)
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
            results: Some(results.into_iter().map(|r| r.0).collect()),
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
    let mut context = request.context();
    let items = take_service_items!(
        request,
        request.request.monitored_item_ids,
        request.info.operational_limits.max_monitored_items_per_call
    );

    let results = match request.subscriptions.delete_monitored_items(
        request.session_id,
        request.request.subscription_id,
        &items,
    ) {
        Ok(r) => r,
        Err(e) => return service_fault!(request, e),
    };

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.0.is_good() && mgr.owns_node(n.1.node_id()))
            .map(|n| &n.1)
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.delete_monitored_items(&context, &owned).await;
    }

    Response {
        message: DeleteMonitoredItemsResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(results.into_iter().map(|r| r.0).collect()),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}
