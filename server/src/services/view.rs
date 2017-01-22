use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use server::ServerState;
use tcp_session::SessionState;

pub struct ViewService {}

impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, _: &mut ServerState, _: &mut SessionState, request: &BrowseRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("browse {:#?}", request);
        let browse_results = if request.nodes_to_browse.is_some() {
            let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();
            // Nodes to browse
            for node in nodes_to_browse {
                // TODO browse address space for nodes
            }
            Some(vec![])
        } else {
            None
        };
        let response = BrowseResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            results: browse_results,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::BrowseResponse(response))
    }
}