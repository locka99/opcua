// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use crate::core::{config::Config, supported_message::SupportedMessage};
use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::state::ServerState;

use super::Service;

/// The discovery service. Allows a server to return the endpoints that it supports.
pub(crate) struct DiscoveryService;

impl Service for DiscoveryService {
    fn name(&self) -> String {
        String::from("DiscoveryService")
    }
}

impl DiscoveryService {
    pub fn new() -> DiscoveryService {
        DiscoveryService {}
    }

    pub fn get_endpoints(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        request: &GetEndpointsRequest,
    ) -> SupportedMessage {
        let server_state = trace_read_lock!(server_state);

        // TODO some of the arguments in the request are ignored
        //  localeIds - list of locales to use for human readable strings (in the endpoint descriptions)

        // TODO audit - generate event for failed service invocation

        let endpoints = server_state.endpoints(&request.endpoint_url, &request.profile_uris);
        GetEndpointsResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            endpoints,
        }
        .into()
    }

    pub fn register_server(
        &self,
        _server_state: Arc<RwLock<ServerState>>,
        request: &RegisterServerRequest,
    ) -> SupportedMessage {
        self.service_fault(&request.request_header, StatusCode::BadNotSupported)
    }

    pub fn register_server2(
        &self,
        _server_state: Arc<RwLock<ServerState>>,
        request: &RegisterServer2Request,
    ) -> SupportedMessage {
        self.service_fault(&request.request_header, StatusCode::BadNotSupported)
    }

    pub fn find_servers(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        request: &FindServersRequest,
    ) -> SupportedMessage {
        let server_state = trace_read_lock!(server_state);

        let application_description = {
            let config = trace_read_lock!(server_state.config);
            config.application_description()
        };

        // Fields within the request

        let mut servers = vec![application_description];

        // TODO endpoint URL

        // TODO localeids, filter out servers that do not support locale ids

        // Filter servers that do not have a matching application uri
        if let Some(ref server_uris) = request.server_uris {
            if !server_uris.is_empty() {
                // Filter the servers down
                servers
                    .retain(|server| server_uris.iter().any(|uri| *uri == server.application_uri));
            }
        }

        let servers = Some(servers);

        FindServersResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            servers,
        }
        .into()
    }
}
