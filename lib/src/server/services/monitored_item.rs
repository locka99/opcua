// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use crate::core::supported_message::SupportedMessage;
use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::{
    address_space::AddressSpace, services::Service, session::Session, state::ServerState,
};

/// The monitored item service. Allows client to create, modify and delete monitored items on a subscription.
pub(crate) struct MonitoredItemService;

impl Service for MonitoredItemService {
    fn name(&self) -> String {
        String::from("MonitoredItemService")
    }
}

impl MonitoredItemService {
    pub fn new() -> MonitoredItemService {
        MonitoredItemService {}
    }

    /// Implementation of CreateMonitoredItems service. See OPC Unified Architecture, Part 4 5.12.2
    pub fn create_monitored_items(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &CreateMonitoredItemsRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.items_to_create) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let server_state = trace_read_lock!(server_state);
            let mut session = trace_write_lock!(session);
            let address_space = trace_read_lock!(address_space);

            let items_to_create = request.items_to_create.as_ref().unwrap();
            // Find subscription and add items to it
            if let Some(subscription) = session.subscriptions_mut().get_mut(request.subscription_id)
            {
                let now = chrono::Utc::now();
                let results = Some(subscription.create_monitored_items(
                    &server_state,
                    &address_space,
                    &now,
                    request.timestamps_to_return,
                    items_to_create,
                ));
                let response = CreateMonitoredItemsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos: None,
                };
                response.into()
            } else {
                // No matching subscription
                self.service_fault(
                    &request.request_header,
                    StatusCode::BadSubscriptionIdInvalid,
                )
            }
        }
    }

    /// Implementation of ModifyMonitoredItems service. See OPC Unified Architecture, Part 4 5.12.3
    pub fn modify_monitored_items(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &ModifyMonitoredItemsRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.items_to_modify) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let server_state = trace_read_lock!(server_state);
            let mut session = trace_write_lock!(session);
            let address_space = trace_read_lock!(address_space);
            let items_to_modify = request.items_to_modify.as_ref().unwrap();
            // Find subscription and modify items in it
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions_mut().get_mut(subscription_id) {
                let results = Some(subscription.modify_monitored_items(
                    &server_state,
                    &address_space,
                    request.timestamps_to_return,
                    items_to_modify,
                ));
                ModifyMonitoredItemsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos: None,
                }
                .into()
            } else {
                // No matching subscription
                self.service_fault(
                    &request.request_header,
                    StatusCode::BadSubscriptionIdInvalid,
                )
            }
        }
    }

    /// Implementation of SetMonitoringMode service. See OPC Unified Architecture, Part 4 5.12.4
    pub fn set_monitoring_mode(
        &self,
        session: Arc<RwLock<Session>>,
        request: &SetMonitoringModeRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.monitored_item_ids) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock!(session);
            let monitored_item_ids = request.monitored_item_ids.as_ref().unwrap();
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions_mut().get_mut(subscription_id) {
                let monitoring_mode = request.monitoring_mode;
                let results = monitored_item_ids
                    .iter()
                    .map(|i| subscription.set_monitoring_mode(*i, monitoring_mode))
                    .collect();
                SetMonitoringModeResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                }
                .into()
            } else {
                self.service_fault(
                    &request.request_header,
                    StatusCode::BadSubscriptionIdInvalid,
                )
            }
        }
    }

    /// Implementation of SetTriggering service. See OPC Unified Architecture, Part 4 5.12.5
    pub fn set_triggering(
        &self,
        session: Arc<RwLock<Session>>,
        request: &SetTriggeringRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.links_to_add)
            && is_empty_option_vec!(request.links_to_remove)
        {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock!(session);
            let links_to_add = match request.links_to_add {
                Some(ref links_to_add) => &links_to_add[..],
                None => &[],
            };
            let links_to_remove = match request.links_to_remove {
                Some(ref links_to_remove) => &links_to_remove[..],
                None => &[],
            };

            // Set the triggering on the subscription.
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions_mut().get_mut(subscription_id) {
                match subscription.set_triggering(
                    request.triggering_item_id,
                    links_to_add,
                    links_to_remove,
                ) {
                    Ok((add_results, remove_results)) => {
                        let response = SetTriggeringResponse {
                            response_header: ResponseHeader::new_good(&request.request_header),
                            add_results: if request.links_to_add.is_some() {
                                Some(add_results)
                            } else {
                                None
                            },
                            add_diagnostic_infos: None,
                            remove_results: if request.links_to_remove.is_some() {
                                Some(remove_results)
                            } else {
                                None
                            },
                            remove_diagnostic_infos: None,
                        };
                        response.into()
                    }
                    Err(err) => self.service_fault(&request.request_header, err),
                }
            } else {
                self.service_fault(
                    &request.request_header,
                    StatusCode::BadSubscriptionIdInvalid,
                )
            }
        }
    }

    /// Implementation of DeleteMonitoredItems service. See OPC Unified Architecture, Part 4 5.12.6
    pub fn delete_monitored_items(
        &self,
        session: Arc<RwLock<Session>>,
        request: &DeleteMonitoredItemsRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.monitored_item_ids) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock!(session);
            let monitored_item_ids = request.monitored_item_ids.as_ref().unwrap();
            // Find subscription and delete items from it
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions_mut().get_mut(subscription_id) {
                let results = Some(subscription.delete_monitored_items(monitored_item_ids));
                let diagnostic_infos = None;
                let response = DeleteMonitoredItemsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos,
                };
                response.into()
            } else {
                // No matching subscription
                self.service_fault(
                    &request.request_header,
                    StatusCode::BadSubscriptionIdInvalid,
                )
            }
        }
    }
}
