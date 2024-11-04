use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use crate::{
    client::{
        session::{
            process_service_result, process_unexpected_response,
            services::subscriptions::{CreateMonitoredItem, ModifyMonitoredItem, Subscription},
            session_debug, session_error, session_trace, session_warn,
        },
        Session,
    },
    core::supported_message::SupportedMessage,
    types::{
        CreateMonitoredItemsRequest, CreateSubscriptionRequest, DeleteMonitoredItemsRequest,
        DeleteSubscriptionsRequest, ModifyMonitoredItemsRequest, ModifySubscriptionRequest,
        MonitoredItemCreateRequest, MonitoredItemCreateResult, MonitoredItemModifyRequest,
        MonitoredItemModifyResult, MonitoringMode, MonitoringParameters, PublishRequest,
        SetMonitoringModeRequest, SetPublishingModeRequest, SetTriggeringRequest, StatusCode,
        TimestampsToReturn, TransferResult, TransferSubscriptionsRequest,
    },
};

use super::OnSubscriptionNotification;

impl Session {
    async fn create_subscription_inner(
        &self,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        publishing_enabled: bool,
        priority: u8,
        callback: Box<dyn OnSubscriptionNotification>,
    ) -> Result<u32, StatusCode> {
        let request = CreateSubscriptionRequest {
            request_header: self.make_request_header(),
            requested_publishing_interval: publishing_interval.as_millis() as f64,
            requested_lifetime_count: lifetime_count,
            requested_max_keep_alive_count: max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
        };
        let response = self.send(request).await?;
        if let SupportedMessage::CreateSubscriptionResponse(response) = response {
            process_service_result(&response.response_header)?;
            let subscription = Subscription::new(
                response.subscription_id,
                Duration::from_millis(response.revised_publishing_interval.max(0.0).floor() as u64),
                response.revised_lifetime_count,
                response.revised_max_keep_alive_count,
                max_notifications_per_publish,
                priority,
                publishing_enabled,
                callback,
            );

            // Add the new subscription to the subscription state
            {
                let mut subscription_state = trace_lock!(self.subscription_state);
                subscription_state.add_subscription(subscription);
            }

            // Send an async publish request for this new subscription
            let _ = self.trigger_publish_tx.send(Instant::now());

            session_debug!(
                self,
                "create_subscription, created a subscription with id {}",
                response.subscription_id
            );
            Ok(response.subscription_id)
        } else {
            session_error!(self, "create_subscription failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }

    /// Create a subscription by sending a [`CreateSubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `publishing_interval` - The requested publishing interval defines the cyclic rate that
    ///   the Subscription is being requested to return Notifications to the Client. This interval
    ///   is expressed in milliseconds. This interval is represented by the publishing timer in the
    ///   Subscription state table. The negotiated value for this parameter returned in the
    ///   response is used as the default sampling interval for MonitoredItems assigned to this
    ///   Subscription. If the requested value is 0 or negative, the server shall revise with the
    ///   fastest supported publishing interval in milliseconds.
    /// * `lifetime_count` - Requested lifetime count. The lifetime count shall be a minimum of
    ///   three times the keep keep-alive count. When the publishing timer has expired this
    ///   number of times without a Publish request being available to send a NotificationMessage,
    ///   then the Subscription shall be deleted by the Server.
    /// * `max_keep_alive_count` - Requested maximum keep-alive count. When the publishing timer has
    ///   expired this number of times without requiring any NotificationMessage to be sent, the
    ///   Subscription sends a keep-alive Message to the Client. The negotiated value for this
    ///   parameter is returned in the response. If the requested value is 0, the server shall
    ///   revise with the smallest supported keep-alive count.
    /// * `max_notifications_per_publish` - The maximum number of notifications that the Client
    ///   wishes to receive in a single Publish response. A value of zero indicates that there is
    ///   no limit. The number of notifications per Publish is the sum of monitoredItems in
    ///   the DataChangeNotification and events in the EventNotificationList.
    /// * `priority` - Indicates the relative priority of the Subscription. When more than one
    ///   Subscription needs to send Notifications, the Server should de-queue a Publish request
    ///   to the Subscription with the highest priority number. For Subscriptions with equal
    ///   priority the Server should de-queue Publish requests in a round-robin fashion.
    ///   A Client that does not require special priority settings should set this value to zero.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscription, `false`, publishing is disabled for the Subscription.
    ///   The value of this parameter does not affect the value of the monitoring mode Attribute of
    ///   MonitoredItems.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - identifier for new subscription
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn create_subscription(
        &self,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        callback: impl OnSubscriptionNotification + Send + Sync + 'static,
    ) -> Result<u32, StatusCode> {
        self.create_subscription_inner(
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            Box::new(callback),
        )
        .await
    }

    fn subscription_exists(&self, subscription_id: u32) -> bool {
        let subscription_state = trace_lock!(self.subscription_state);
        subscription_state.subscription_exists(subscription_id)
    }

    /// Modifies a subscription by sending a [`ModifySubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    /// * `publishing_interval` - The requested publishing interval defines the cyclic rate that
    ///   the Subscription is being requested to return Notifications to the Client. This interval
    ///   is expressed in milliseconds. This interval is represented by the publishing timer in the
    ///   Subscription state table. The negotiated value for this parameter returned in the
    ///   response is used as the default sampling interval for MonitoredItems assigned to this
    ///   Subscription. If the requested value is 0 or negative, the server shall revise with the
    ///   fastest supported publishing interval in milliseconds.
    /// * `lifetime_count` - Requested lifetime count. The lifetime count shall be a minimum of
    ///   three times the keep keep-alive count. When the publishing timer has expired this
    ///   number of times without a Publish request being available to send a NotificationMessage,
    ///   then the Subscription shall be deleted by the Server.
    /// * `max_keep_alive_count` - Requested maximum keep-alive count. When the publishing timer has
    ///   expired this number of times without requiring any NotificationMessage to be sent, the
    ///   Subscription sends a keep-alive Message to the Client. The negotiated value for this
    ///   parameter is returned in the response. If the requested value is 0, the server shall
    ///   revise with the smallest supported keep-alive count.
    /// * `max_notifications_per_publish` - The maximum number of notifications that the Client
    ///   wishes to receive in a single Publish response. A value of zero indicates that there is
    ///   no limit. The number of notifications per Publish is the sum of monitoredItems in
    ///   the DataChangeNotification and events in the EventNotificationList.
    /// * `priority` - Indicates the relative priority of the Subscription. When more than one
    ///   Subscription needs to send Notifications, the Server should de-queue a Publish request
    ///   to the Subscription with the highest priority number. For Subscriptions with equal
    ///   priority the Server should de-queue Publish requests in a round-robin fashion.
    ///   A Client that does not require special priority settings should set this value to zero.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn modify_subscription(
        &self,
        subscription_id: u32,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
    ) -> Result<(), StatusCode> {
        if subscription_id == 0 {
            session_error!(self, "modify_subscription, subscription id must be non-zero, or the subscription is considered invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(self, "modify_subscription, subscription id does not exist");
            Err(StatusCode::BadInvalidArgument)
        } else {
            let request = ModifySubscriptionRequest {
                request_header: self.make_request_header(),
                subscription_id,
                requested_publishing_interval: publishing_interval,
                requested_lifetime_count: lifetime_count,
                requested_max_keep_alive_count: max_keep_alive_count,
                max_notifications_per_publish,
                priority,
            };
            let response = self.send(request).await?;
            if let SupportedMessage::ModifySubscriptionResponse(response) = response {
                process_service_result(&response.response_header)?;
                let mut subscription_state = trace_lock!(self.subscription_state);
                subscription_state.modify_subscription(
                    subscription_id,
                    Duration::from_millis(
                        response.revised_publishing_interval.max(0.0).floor() as u64
                    ),
                    response.revised_lifetime_count,
                    response.revised_max_keep_alive_count,
                    max_notifications_per_publish,
                    priority,
                );
                session_debug!(self, "modify_subscription success for {}", subscription_id);
                Ok(())
            } else {
                session_error!(self, "modify_subscription failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Changes the publishing mode of subscriptions by sending a [`SetPublishingModeRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscriptions, `false`, publishing is disabled for the Subscriptions.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Service return code for the action for each id, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn set_publishing_mode(
        &self,
        subscription_ids: &[u32],
        publishing_enabled: bool,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        session_debug!(
            self,
            "set_publishing_mode, for subscriptions {:?}, publishing enabled {}",
            subscription_ids,
            publishing_enabled
        );
        if subscription_ids.is_empty() {
            // No subscriptions
            session_error!(
                self,
                "set_publishing_mode, no subscription ids were provided"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = SetPublishingModeRequest {
                request_header: self.make_request_header(),
                publishing_enabled,
                subscription_ids: Some(subscription_ids.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::SetPublishingModeResponse(response) = response {
                process_service_result(&response.response_header)?;
                {
                    // Clear out all subscriptions, assuming the delete worked
                    let mut subscription_state = trace_lock!(self.subscription_state);
                    subscription_state.set_publishing_mode(subscription_ids, publishing_enabled);
                }
                session_debug!(self, "set_publishing_mode success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "set_publishing_mode failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Transfers Subscriptions and their MonitoredItems from one Session to another. For example,
    /// a Client may need to reopen a Session and then transfer its Subscriptions to that Session.
    /// It may also be used by one Client to take over a Subscription from another Client by
    /// transferring the Subscription to its Session.
    ///
    /// See OPC UA Part 4 - Services 5.13.7 for complete description of the service and error responses.
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `send_initial_values` - A boolean parameter with the following values - `true` the first
    ///   publish response shall contain the current values of all monitored items in the subscription,
    ///   `false`, the first publish response shall contain only the value changes since the last
    ///   publish response was sent.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<TransferResult>)` - The [`TransferResult`] for each transfer subscription.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn transfer_subscriptions(
        &self,
        subscription_ids: &[u32],
        send_initial_values: bool,
    ) -> Result<Vec<TransferResult>, StatusCode> {
        if subscription_ids.is_empty() {
            // No subscriptions
            session_error!(
                self,
                "set_publishing_mode, no subscription ids were provided"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = TransferSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(subscription_ids.to_vec()),
                send_initial_values,
            };
            let response = self.send(request).await?;
            if let SupportedMessage::TransferSubscriptionsResponse(response) = response {
                process_service_result(&response.response_header)?;
                session_debug!(self, "transfer_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "transfer_subscriptions failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Deletes a subscription by sending a [`DeleteSubscriptionsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    ///
    /// # Returns
    ///
    /// * `Ok(StatusCode)` - Service return code for the delete action, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_subscription(
        &self,
        subscription_id: u32,
    ) -> Result<StatusCode, StatusCode> {
        if subscription_id == 0 {
            session_error!(self, "delete_subscription, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "delete_subscription, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else {
            let result = self.delete_subscriptions(&[subscription_id][..]).await?;
            Ok(result[0])
        }
    }

    /// Deletes subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with the list
    /// of subscriptions to delete.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - List of subscription identifiers to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of result for delete action on each id, `Good` or `BadSubscriptionIdInvalid`
    ///   The size and order of the list matches the size and order of the input.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_subscriptions(
        &self,
        subscription_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if subscription_ids.is_empty() {
            // No subscriptions
            session_trace!(self, "delete_subscriptions with no subscriptions");
            Err(StatusCode::BadNothingToDo)
        } else {
            // Send a delete request holding all the subscription ides that we wish to delete
            let request = DeleteSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(subscription_ids.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::DeleteSubscriptionsResponse(response) = response {
                process_service_result(&response.response_header)?;
                {
                    // Clear out deleted subscriptions, assuming the delete worked
                    let mut subscription_state = trace_lock!(self.subscription_state);
                    subscription_ids.iter().for_each(|id| {
                        let _ = subscription_state.delete_subscription(*id);
                    });
                }
                session_debug!(self, "delete_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "delete_subscriptions failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Creates monitored items on a subscription by sending a [`CreateMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_create` - A list of [`MonitoredItemCreateRequest`] to be created and assigned to the specified Subscription.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemCreateResult>)` - A list of [`MonitoredItemCreateResult`] corresponding to the items to create.
    ///    The size and order of the list matches the size and order of the `items_to_create` request parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn create_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_create: Vec<MonitoredItemCreateRequest>,
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        session_debug!(
            self,
            "create_monitored_items, for subscription {}, {} items",
            subscription_id,
            items_to_create.len()
        );
        if subscription_id == 0 {
            session_error!(self, "create_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "create_monitored_items, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_create.is_empty() {
            session_error!(
                self,
                "create_monitored_items, called with no items to create"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let mut final_items_to_create = Vec::new();
            let mut created_items = Vec::new();

            for mut req in items_to_create {
                if req.requested_parameters.client_handle == 0 {
                    req.requested_parameters.client_handle = self.monitored_item_handle.next();
                }

                final_items_to_create.push(req.clone());
                created_items.push(req);
            }

            let request = CreateMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return,
                items_to_create: Some(final_items_to_create.clone()),
            };
            let response = self.send(request).await?;

            if let SupportedMessage::CreateMonitoredItemsResponse(response) = response {
                process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    session_debug!(
                        self,
                        "create_monitored_items, {} items created",
                        created_items.len()
                    );
                    // Set the items in our internal state
                    let items_to_create = created_items
                        .into_iter()
                        .zip(results)
                        .map(|(i, r)| CreateMonitoredItem {
                            id: r.monitored_item_id,
                            client_handle: i.requested_parameters.client_handle,
                            discard_oldest: i.requested_parameters.discard_oldest,
                            item_to_monitor: i.item_to_monitor.clone(),
                            monitoring_mode: i.monitoring_mode,
                            queue_size: r.revised_queue_size,
                            sampling_interval: r.revised_sampling_interval,
                            filter: i.requested_parameters.filter,
                        })
                        .collect::<Vec<CreateMonitoredItem>>();
                    {
                        let mut subscription_state = trace_lock!(self.subscription_state);
                        subscription_state.insert_monitored_items(subscription_id, items_to_create);
                    }
                } else {
                    session_debug!(
                        self,
                        "create_monitored_items, success but no monitored items were created"
                    );
                }
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "create_monitored_items failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Modifies monitored items on a subscription by sending a [`ModifyMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_modify` - The list of [`MonitoredItemModifyRequest`] to modify.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemModifyResult>)` - A list of [`MonitoredItemModifyResult`] corresponding to the MonitoredItems to modify.
    ///    The size and order of the list matches the size and order of the `items_to_modify` request parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn modify_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_modify: &[MonitoredItemModifyRequest],
    ) -> Result<Vec<MonitoredItemModifyResult>, StatusCode> {
        session_debug!(
            self,
            "modify_monitored_items, for subscription {}, {} items",
            subscription_id,
            items_to_modify.len()
        );
        if subscription_id == 0 {
            session_error!(self, "modify_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "modify_monitored_items, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_modify.is_empty() {
            session_error!(
                self,
                "modify_monitored_items, called with no items to modify"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let monitored_item_ids = items_to_modify
                .iter()
                .map(|i| i.monitored_item_id)
                .collect::<Vec<u32>>();
            let request = ModifyMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return,
                items_to_modify: Some(items_to_modify.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::ModifyMonitoredItemsResponse(response) = response {
                process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    // Set the items in our internal state
                    let items_to_modify = monitored_item_ids
                        .iter()
                        .zip(results.iter())
                        .map(|(id, r)| ModifyMonitoredItem {
                            id: *id,
                            queue_size: r.revised_queue_size,
                            sampling_interval: r.revised_sampling_interval,
                        })
                        .collect::<Vec<ModifyMonitoredItem>>();
                    {
                        let mut subscription_state = trace_lock!(self.subscription_state);
                        subscription_state
                            .modify_monitored_items(subscription_id, &items_to_modify);
                    }
                }
                session_debug!(self, "modify_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "modify_monitored_items failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Sets the monitoring mode on one or more monitored items by sending a [`SetMonitoringModeRequest`]
    /// to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored items to be modified.
    /// * `monitoring_mode` - the monitored mode to apply to the monitored items
    /// * `monitored_item_ids` - the monitored items to be modified
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Individual result for each monitored item.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn set_monitoring_mode(
        &self,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        monitored_item_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if monitored_item_ids.is_empty() {
            session_error!(self, "set_monitoring_mode, called with nothing to do");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = {
                let monitored_item_ids = Some(monitored_item_ids.to_vec());
                SetMonitoringModeRequest {
                    request_header: self.make_request_header(),
                    subscription_id,
                    monitoring_mode,
                    monitored_item_ids,
                }
            };
            let response = self.send(request).await?;

            {
                let mut subscription_state = trace_lock!(self.subscription_state);
                subscription_state.set_monitoring_mode(
                    subscription_id,
                    monitored_item_ids,
                    monitoring_mode,
                );
            }
            if let SupportedMessage::SetMonitoringModeResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "set_monitoring_mode failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Sets a monitored item so it becomes the trigger that causes other monitored items to send
    /// change events in the same update. Sends a [`SetTriggeringRequest`] to the server.
    /// Note that `items_to_remove` is applied before `items_to_add`.
    ///
    /// See OPC UA Part 4 - Services 5.12.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored item to be used as the trigger.
    /// * `monitored_item_id` - the monitored item that is the trigger.
    /// * `links_to_add` - zero or more items to be added to the monitored item's triggering list.
    /// * `items_to_remove` - zero or more items to be removed from the monitored item's triggering list.
    ///
    /// # Returns
    ///
    /// * `Ok((Option<Vec<StatusCode>>, Option<Vec<StatusCode>>))` - Individual result for each item added / removed for the SetTriggering call.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn set_triggering(
        &self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) -> Result<(Option<Vec<StatusCode>>, Option<Vec<StatusCode>>), StatusCode> {
        if links_to_add.is_empty() && links_to_remove.is_empty() {
            session_error!(self, "set_triggering, called with nothing to add or remove");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = {
                let links_to_add = if links_to_add.is_empty() {
                    None
                } else {
                    Some(links_to_add.to_vec())
                };
                let links_to_remove = if links_to_remove.is_empty() {
                    None
                } else {
                    Some(links_to_remove.to_vec())
                };
                SetTriggeringRequest {
                    request_header: self.make_request_header(),
                    subscription_id,
                    triggering_item_id,
                    links_to_add,
                    links_to_remove,
                }
            };
            let response = self.send(request).await?;
            if let SupportedMessage::SetTriggeringResponse(response) = response {
                // Update client side state
                let mut subscription_state = trace_lock!(self.subscription_state);
                subscription_state.set_triggering(
                    subscription_id,
                    triggering_item_id,
                    links_to_add,
                    links_to_remove,
                );
                Ok((response.add_results, response.remove_results))
            } else {
                session_error!(self, "set_triggering failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Deletes monitored items from a subscription by sending a [`DeleteMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.6 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of StatusCodes for the MonitoredItems to delete. The size and
    ///   order of the list matches the size and order of the `items_to_delete` request parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_monitored_items(
        &self,
        subscription_id: u32,
        items_to_delete: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        session_debug!(
            self,
            "delete_monitored_items, subscription {} for {} items",
            subscription_id,
            items_to_delete.len()
        );
        if subscription_id == 0 {
            session_error!(self, "delete_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "delete_monitored_items, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_delete.is_empty() {
            session_error!(
                self,
                "delete_monitored_items, called with no items to delete"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                monitored_item_ids: Some(items_to_delete.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::DeleteMonitoredItemsResponse(response) = response {
                process_service_result(&response.response_header)?;
                if response.results.is_some() {
                    let mut subscription_state = trace_lock!(self.subscription_state);
                    subscription_state.delete_monitored_items(subscription_id, items_to_delete);
                }
                session_debug!(self, "delete_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "delete_monitored_items failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    pub(crate) fn next_publish_time(&self, set_last_publish: bool) -> Option<Instant> {
        let mut subscription_state = trace_lock!(self.subscription_state);
        if set_last_publish {
            subscription_state.set_last_publish();
        }
        subscription_state.next_publish_time()
    }

    /// Send a publish request, returning `true` if the session should send a new request
    /// immediately.
    pub(crate) async fn publish(&self) -> Result<bool, StatusCode> {
        let acks = {
            let mut subscription_state = trace_lock!(self.subscription_state);
            let acks = subscription_state.take_acknowledgements();
            if !acks.is_empty() {
                Some(acks)
            } else {
                None
            }
        };

        if log_enabled!(log::Level::Debug) {
            let sequence_nrs: Vec<u32> = acks
                .iter()
                .flatten()
                .map(|ack| ack.sequence_number)
                .collect();
            debug!(
                "publish is acknowledging subscription acknowledgements with sequence nrs {:?}",
                sequence_nrs
            );
        }

        let request = PublishRequest {
            request_header: self.channel.make_request_header(self.publish_timeout),
            subscription_acknowledgements: acks.clone(),
        };

        let response = self.channel.send(request, self.publish_timeout).await;

        let err_status = match response {
            Ok(SupportedMessage::PublishResponse(r)) => {
                session_debug!(self, "PublishResponse");

                let decoding_options = {
                    let secure_channel = trace_read_lock!(self.channel.secure_channel);
                    secure_channel.decoding_options()
                };

                {
                    let mut subscription_state = trace_lock!(self.subscription_state);
                    subscription_state.handle_notification(
                        r.subscription_id,
                        r.notification_message,
                        &decoding_options,
                    );
                }

                return Ok(r.more_notifications);
            }
            Err(e) => e,
            Ok(r) => {
                session_error!(self, "publish failed {:?}", r);
                process_unexpected_response(r)
            }
        };

        if let Some(acks) = acks {
            let mut subscription_state = trace_lock!(self.subscription_state);
            subscription_state.re_queue_acknowledgements(acks);
        }

        Err(err_status)
    }

    /// This code attempts to take the existing subscriptions created by a previous session and
    /// either transfer them to this session, or construct them from scratch.
    pub(crate) async fn transfer_subscriptions_from_old_session(&self) {
        // TODO: This whole thing should probably be optional, so that users can
        // customize the process.
        let subscription_ids = {
            let subscription_state = trace_lock!(self.subscription_state);
            subscription_state.subscription_ids()
        };

        let Some(subscription_ids) = subscription_ids else {
            return;
        };

        // Start by getting the subscription ids
        // Try to use TransferSubscriptions to move subscriptions_ids over. If this
        // works then there is nothing else to do.
        let mut subscription_ids_to_recreate =
            subscription_ids.iter().copied().collect::<HashSet<u32>>();
        if let Ok(transfer_results) = self.transfer_subscriptions(&subscription_ids, true).await {
            session_debug!(self, "transfer_results = {:?}", transfer_results);
            transfer_results.iter().enumerate().for_each(|(i, r)| {
                if r.status_code.is_good() {
                    // Subscription was transferred so it does not need to be recreated
                    subscription_ids_to_recreate.remove(&subscription_ids[i]);
                }
            });
        }

        // But if it didn't work, then some or all subscriptions have to be remade.
        if !subscription_ids_to_recreate.is_empty() {
            session_warn!(self, "Some or all of the existing subscriptions could not be transferred and must be created manually");
        }

        for subscription_id in subscription_ids_to_recreate {
            session_debug!(self, "Recreating subscription {}", subscription_id);

            let deleted_subscription = {
                let mut subscription_state = trace_lock!(self.subscription_state);
                subscription_state.delete_subscription(subscription_id)
            };

            let Some(subscription) = deleted_subscription else {
                session_warn!(
                    self,
                    "Subscription removed from session while transfer in progress"
                );
                continue;
            };

            let Ok(subscription_id) = self
                .create_subscription_inner(
                    subscription.publishing_interval,
                    subscription.lifetime_count,
                    subscription.max_keep_alive_count,
                    subscription.max_notifications_per_publish,
                    subscription.publishing_enabled,
                    subscription.priority,
                    subscription.callback,
                )
                .await
            else {
                session_warn!(
                    self,
                    "Could not create a subscription from the existing subscription {}",
                    subscription_id
                );
                continue;
            };

            let items_to_create = subscription
                .monitored_items
                .iter()
                .map(|(_, item)| MonitoredItemCreateRequest {
                    item_to_monitor: item.item_to_monitor().clone(),
                    monitoring_mode: item.monitoring_mode,
                    requested_parameters: MonitoringParameters {
                        client_handle: item.client_handle(),
                        sampling_interval: item.sampling_interval(),
                        filter: item.filter.clone(),
                        queue_size: item.queue_size() as u32,
                        discard_oldest: item.discard_oldest(),
                    },
                })
                .collect::<Vec<MonitoredItemCreateRequest>>();

            let mut iter = items_to_create.into_iter();

            loop {
                let chunk = (&mut iter)
                    .take(self.recreate_monitored_items_chunk)
                    .collect::<Vec<_>>();

                if chunk.is_empty() {
                    break;
                }

                let _ = self
                    .create_monitored_items(subscription_id, TimestampsToReturn::Both, chunk)
                    .await;
            }

            for item in subscription.monitored_items.values() {
                let triggered_items = item.triggered_items();
                if !triggered_items.is_empty() {
                    let links_to_add = triggered_items.iter().copied().collect::<Vec<u32>>();
                    let _ = self
                        .set_triggering(subscription_id, item.id(), links_to_add.as_slice(), &[])
                        .await;
                }
            }
        }
    }
}
