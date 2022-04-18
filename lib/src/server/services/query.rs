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

/// The view service. Allows the client to browse the address space of the server.
pub(crate) struct QueryService;

impl Service for QueryService {
    fn name(&self) -> String {
        String::from("QueryService")
    }
}

impl QueryService {
    pub fn new() -> QueryService {
        QueryService {}
    }

    pub fn query_first(
        &self,
        _server_state: Arc<RwLock<ServerState>>,
        _session: Arc<RwLock<Session>>,
        _address_space: Arc<RwLock<AddressSpace>>,
        request: &QueryFirstRequest,
    ) -> SupportedMessage {
        self.service_fault(&request.request_header, StatusCode::BadNotSupported)
    }

    pub fn query_next(
        &self,
        _server_state: Arc<RwLock<ServerState>>,
        _session: Arc<RwLock<Session>>,
        _address_space: Arc<RwLock<AddressSpace>>,
        request: &QueryNextRequest,
    ) -> SupportedMessage {
        self.service_fault(&request.request_header, StatusCode::BadNotSupported)
    }
}
