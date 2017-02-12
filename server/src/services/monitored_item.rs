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

    pub fn create_monitored_items(&self, server_state: &mut ServerState, _: &mut SessionState, request: &CreateMonitoredItemsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        // pub subscription_id: UInt32,
        // pub timestamps_to_return: TimestampsToReturn,
        // pub items_to_create: Option<Vec<MonitoredItemCreateRequest>>,

        let results = if request.items_to_create.is_some() {
            let items_to_create = request.items_to_create.as_ref().unwrap();
            let results = Vec::with_capacity(items_to_create.len());
            for item in items_to_create {

            }
            Some(results)
        }
        else {
            None
        };


        let response = CreateMonitoredItemsResponse {
            response_header: ResponseHeader::new_good(&DateTime::now(), &request.request_header),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::CreateMonitoredItemsResponse(response))
    }
}