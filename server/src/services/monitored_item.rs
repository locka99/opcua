use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct MonitoredItemService {}

impl MonitoredItemService {
    pub fn new() -> MonitoredItemService {
        MonitoredItemService {}
    }

    pub fn create_monitored_items(&self, _: &mut ServerState, _: &mut SessionState, request: &CreateMonitoredItemsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let service_status = &GOOD;

        // pub subscription_id: UInt32,
        // pub timestamps_to_return: TimestampsToReturn,
        // pub items_to_create: Option<Vec<MonitoredItemCreateRequest>>,

        let results = if request.items_to_create.is_some() {
            let items_to_create = request.items_to_create.as_ref().unwrap();
            let results = Vec::with_capacity(items_to_create.len());
            for _ in items_to_create {
                // Process items to create here
            }
            Some(results)
        } else {
            None
        };

        let response = CreateMonitoredItemsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::CreateMonitoredItemsResponse(response))
    }
}