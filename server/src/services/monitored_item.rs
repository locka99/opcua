use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use server::ServerState;
use session::Session;

pub struct MonitoredItemService {}

impl MonitoredItemService {
    pub fn new() -> MonitoredItemService {
        MonitoredItemService {}
    }

    pub fn create_monitored_items(&self, _: &mut ServerState, session: &mut Session, request: CreateMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        let mut service_status = GOOD;

        // pub timestamps_to_return: TimestampsToReturn,
        let results = if let Some(ref items_to_create) = request.items_to_create {
            // Find subscription and add items to it
            let subscription_id = request.subscription_id;
            if let Some(mut subscription) = session.subscriptions.get_mut(&subscription_id) {
                Some(subscription.create_monitored_items(items_to_create))
            } else {
                // No matching subscription
                service_status = BAD_SUBSCRIPTION_ID_INVALID;
                None
            }
        } else {
            // No items to create so nothing to do
            service_status = BAD_NOTHING_TO_DO;
            None
        };
        let response = CreateMonitoredItemsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::CreateMonitoredItemsResponse(response))
    }

    pub fn modify_monitored_items(&self, _: &mut ServerState, session: &mut Session, request: ModifyMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        let mut service_status = GOOD;
        let results = if let Some(ref items_to_modify) = request.items_to_modify {
            // Find subscription and modify items in it
            let subscription_id = request.subscription_id;
            if let Some(mut subscription) = session.subscriptions.get_mut(&subscription_id) {
                Some(subscription.modify_monitored_items(items_to_modify))
            } else {
                // No matching subscription
                service_status = BAD_SUBSCRIPTION_ID_INVALID;
                None
            }
        } else {
            // No items to modify so nothing to do
            service_status = BAD_NOTHING_TO_DO;
            None
        };
        let response = ModifyMonitoredItemsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::ModifyMonitoredItemsResponse(response))
    }

    pub fn delete_monitored_items(&self, _: &mut ServerState, session: &mut Session, request: DeleteMonitoredItemsRequest) -> Result<SupportedMessage, StatusCode> {
        let mut service_status = GOOD;
        let results = if let Some(ref items_to_delete) = request.monitored_item_ids {
            // Find subscription and delete items from it
            let subscription_id = request.subscription_id;
            if let Some(mut subscription) = session.subscriptions.get_mut(&subscription_id) {
                Some(subscription.delete_monitored_items(items_to_delete))
            } else {
                // No matching subscription
                service_status = BAD_SUBSCRIPTION_ID_INVALID;
                None
            }
        } else {
            // No items to modify so nothing to do
            service_status = BAD_NOTHING_TO_DO;
            None
        };
        let response = DeleteMonitoredItemsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::DeleteMonitoredItemsResponse(response))
    }
}