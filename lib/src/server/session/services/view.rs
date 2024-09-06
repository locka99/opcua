use std::collections::HashMap;

use crate::{
    server::{
        node_manager::{
            resolve_external_references, BrowseNode, BrowsePathItem, ExternalReferencesContPoint,
            NodeManagers, RegisterNodeItem,
        },
        session::{controller::Response, message_handler::Request},
    },
    types::{
        BrowseNextRequest, BrowseNextResponse, BrowsePathResult, BrowsePathTarget, BrowseRequest,
        BrowseResponse, BrowseResult, ByteString, RegisterNodesRequest, RegisterNodesResponse,
        ResponseHeader, StatusCode, TranslateBrowsePathsToNodeIdsRequest,
        TranslateBrowsePathsToNodeIdsResponse, UnregisterNodesRequest, UnregisterNodesResponse,
    },
};

pub async fn browse(node_managers: NodeManagers, request: Request<BrowseRequest>) -> Response {
    let mut context: crate::server::node_manager::RequestContext = request.context();
    let nodes_to_browse = take_service_items!(
        request,
        request.request.nodes_to_browse,
        request.info.operational_limits.max_nodes_per_browse
    );
    if !request.request.view.view_id.is_null() || !request.request.view.timestamp.is_null() {
        info!("Browse request ignored because view was specified (views not supported)");
        return service_fault!(request, StatusCode::BadViewIdUnknown);
    }

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

    let mut nodes: Vec<_> = nodes_to_browse
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

pub async fn browse_next(
    node_managers: NodeManagers,
    request: Request<BrowseNextRequest>,
) -> Response {
    let mut context = request.context();
    let nodes_to_browse = take_service_items!(
        request,
        request.request.continuation_points,
        request.info.operational_limits.max_nodes_per_browse
    );
    let mut results: Vec<_> = (0..nodes_to_browse.len()).map(|_| None).collect();

    let mut nodes = {
        let mut session = trace_write_lock!(request.session);
        let mut nodes = Vec::with_capacity(nodes_to_browse.len());
        for (idx, point) in nodes_to_browse.into_iter().enumerate() {
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
        let node_meta = resolve_external_references(&context, &node_managers, &external_refs).await;
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

pub async fn translate_browse_paths(
    node_managers: NodeManagers,
    request: Request<TranslateBrowsePathsToNodeIdsRequest>,
) -> Response {
    // - We're given a list of (NodeId, BrowsePath) pairs
    // - For a node manager, ask them to explore the browse path, returning _all_ visited nodes in each layer.
    // - This extends the list of (NodeId, BrowsePath) pairs, though each new node should have a shorter browse path.
    // - We keep which node managers returned which nodes. Once every node manager has been asked about every
    //   returned node, the service is finished and we can collect all the node IDs in the bottom layer.

    let mut context = request.context();
    let paths = take_service_items!(
        request,
        request.request.browse_paths,
        request
            .info
            .operational_limits
            .max_nodes_per_translate_browse_paths_to_node_ids
    );

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
                    let item =
                        BrowsePathItem::new(n, input_index, &items[input_index], idx, iteration);
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

pub async fn register_nodes(
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

    for mgr in &node_managers {
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

    let registered_node_ids: Vec<_> = items.into_iter().filter_map(|n| n.into_result()).collect();

    Response {
        message: RegisterNodesResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            registered_node_ids: Some(registered_node_ids),
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn unregister_nodes(
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

    if nodes_to_unregister.len() > request.info.operational_limits.max_nodes_per_register_nodes {
        return service_fault!(request, StatusCode::BadTooManyOperations);
    }

    for mgr in &node_managers {
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
