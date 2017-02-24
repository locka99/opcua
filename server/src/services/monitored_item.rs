use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use server::ServerState;
use session::SessionState;

pub struct MonitoredItemService {}

impl MonitoredItemService {
    pub fn new() -> MonitoredItemService {
        MonitoredItemService {}
    }

    pub fn create_monitored_items(&self, _: &mut ServerState, session_state: &mut SessionState, request: CreateMonitoredItemsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let mut service_status = &GOOD;

        // pub timestamps_to_return: TimestampsToReturn,
        let results = if let Some(ref items_to_create) = request.items_to_create {
            // Find subscription and add items to it
            let mut subscriptions = session_state.subscriptions.lock().unwrap();
            let subscription_id = request.subscription_id;
            if let Some(mut subscription) = subscriptions.get_mut(&subscription_id) {
                Some(subscription.create_monitored_items(items_to_create))
            } else {
                // No matching subscription
                service_status = &BAD_SUBSCRIPTION_ID_INVALID;
                None
            }
        } else {
            // No items to create so nothing to do
            service_status = &BAD_NOTHING_TO_DO;
            None
        };
        let response = CreateMonitoredItemsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::CreateMonitoredItemsResponse(response))
    }

    pub fn modify_monitored_items(&self, _: &mut ServerState, _: &mut SessionState, _: ModifyMonitoredItemsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        unimplemented!();
    }

    pub fn delete_monitored_items(&self, _: &mut ServerState, _: &mut SessionState, _: DeleteMonitoredItemsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        unimplemented!();
    }
}