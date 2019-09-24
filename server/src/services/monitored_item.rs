use std::result::Result;

use opcua_types::{
    *,
    status_code::StatusCode,
};

use crate::{
    address_space::AddressSpace,
    state::ServerState,
    session::Session, services::Service,
};

/// The monitored item service. Allows client to create, modify and delete monitored items on a subscription.
pub(crate) struct MonitoredItemService;

impl Service for MonitoredItemService {
    fn name(&self) -> String { String::from("MonitoredItemService") }
}

impl MonitoredItemService {
    pub fn new() -> MonitoredItemService {
        MonitoredItemService {}
    }

    /// Implementation of CreateMonitoredItems service. See OPC Unified Architecture, Part 4 5.12.2
    pub fn create_monitored_items(&self, server_state: &ServerState, session: &mut Session, address_space: &AddressSpace, request: &CreateMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.items_to_create) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let items_to_create = request.items_to_create.as_ref().unwrap();
            // Find subscription and add items to it
            if let Some(subscription) = session.subscriptions.get_mut(request.subscription_id) {
                let now = chrono::Utc::now();
                let results = Some(subscription.create_monitored_items(address_space, &now, request.timestamps_to_return, items_to_create, server_state.max_monitored_items_per_sub));
                let response = CreateMonitoredItemsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos: None,
                };
                Ok(response.into())
            } else {
                // No matching subscription
                Ok(self.service_fault(&request.request_header, StatusCode::BadSubscriptionIdInvalid))
            }
        }
    }

    /// Implementation of ModifyMonitoredItems service. See OPC Unified Architecture, Part 4 5.12.3
    pub fn modify_monitored_items(&self, session: &mut Session, address_space: &AddressSpace, request: &ModifyMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.items_to_modify) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let items_to_modify = request.items_to_modify.as_ref().unwrap();
            // Find subscription and modify items in it
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions.get_mut(subscription_id) {
                let results = Some(subscription.modify_monitored_items(address_space, request.timestamps_to_return, items_to_modify));
                let response = ModifyMonitoredItemsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos: None,
                };
                Ok(response.into())
            } else {
                // No matching subscription
                Ok(self.service_fault(&request.request_header, StatusCode::BadSubscriptionIdInvalid))
            }
        }
    }

    /// Implementation of SetMonitoringMode service. See OPC Unified Architecture, Part 4 5.12.4
    pub fn set_monitoring_mode(&self, session: &mut Session, request: &SetMonitoringModeRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.monitored_item_ids) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let monitored_item_ids = request.monitored_item_ids.as_ref().unwrap();
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions.get_mut(subscription_id) {
                let monitoring_mode = request.monitoring_mode;
                let results = monitored_item_ids.iter().map(|i| {
                    subscription.set_monitoring_mode(*i, monitoring_mode)
                }).collect();
                let response = SetMonitoringModeResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                };
                Ok(response.into())
            } else {
                Ok(self.service_fault(&request.request_header, StatusCode::BadSubscriptionIdInvalid))
            }
        }
    }

    /// Implementation of SetTriggering service. See OPC Unified Architecture, Part 4 5.12.5
    pub fn set_triggering(&self, session: &mut Session, request: &SetTriggeringRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.links_to_add) && is_empty_option_vec!(request.links_to_remove) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let links_to_add = match request.links_to_add {
                Some(ref links_to_add) => &links_to_add[..],
                None => &[]
            };
            let links_to_remove = match request.links_to_remove {
                Some(ref links_to_remove) => &links_to_remove[..],
                None => &[]
            };

            // Set the triggering on the subscription.
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions.get_mut(subscription_id) {
                match subscription.set_triggering(request.triggering_item_id, links_to_add, links_to_remove) {
                    Ok((add_results, remove_results)) => {
                        let response = SetTriggeringResponse {
                            response_header: ResponseHeader::new_good(&request.request_header),
                            add_results: if request.links_to_add.is_some() { Some(add_results) } else { None },
                            add_diagnostic_infos: None,
                            remove_results: if request.links_to_remove.is_some() { Some(remove_results) } else { None },
                            remove_diagnostic_infos: None,
                        };
                        Ok(response.into())
                    }
                    Err(err) => {
                        Ok(self.service_fault(&request.request_header, err))
                    }
                }
            } else {
                Ok(self.service_fault(&request.request_header, StatusCode::BadSubscriptionIdInvalid))
            }
        }
    }

    /// Implementation of DeleteMonitoredItems service. See OPC Unified Architecture, Part 4 5.12.6
    pub fn delete_monitored_items(&self, session: &mut Session, request: &DeleteMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.monitored_item_ids) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let monitored_item_ids = request.monitored_item_ids.as_ref().unwrap();
            // Find subscription and delete items from it
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions.get_mut(subscription_id) {
                let results = Some(subscription.delete_monitored_items(monitored_item_ids));
                let diagnostic_infos = None;
                let response = DeleteMonitoredItemsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos,
                };
                Ok(response.into())
            } else {
                // No matching subscription
                Ok(self.service_fault(&request.request_header, StatusCode::BadSubscriptionIdInvalid))
            }
        }
    }
}
