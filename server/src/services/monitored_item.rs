use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::service_types::*;

use crate::session::Session;
use crate::services::Service;

/// The monitored item service. Allows client to create, modify and delete monitored items on a subscription.
pub(crate) struct MonitoredItemService;

impl Service for MonitoredItemService {}

impl MonitoredItemService {
    pub fn new() -> MonitoredItemService {
        MonitoredItemService {}
    }

    pub fn create_monitored_items(&self, session: &mut Session, request: CreateMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref items_to_create) = request.items_to_create {
            // Find subscription and add items to it
            if let Some(subscription) = session.subscriptions.get_mut(request.subscription_id) {
                let results = Some(subscription.create_monitored_items(request.timestamps_to_return, items_to_create));
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
        } else {
            // No items to create so nothing to do
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    pub fn modify_monitored_items(&self, session: &mut Session, request: ModifyMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref items_to_modify) = request.items_to_modify {
            // Find subscription and modify items in it
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions.get_mut(subscription_id) {
                let results = Some(subscription.modify_monitored_items(request.timestamps_to_return, items_to_modify));
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
        } else {
            // No items to modify so nothing to do
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    pub fn delete_monitored_items(&self, session: &mut Session, request: DeleteMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref items_to_delete) = request.monitored_item_ids {
            // Find subscription and delete items from it
            let subscription_id = request.subscription_id;
            if let Some(subscription) = session.subscriptions.get_mut(subscription_id) {
                let results = Some(subscription.delete_monitored_items(items_to_delete));
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
        } else {
            // No items to modify so nothing to do
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }
}