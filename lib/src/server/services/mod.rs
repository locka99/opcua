// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::core::supported_message::SupportedMessage;
use crate::types::{status_code::StatusCode, RequestHeader, ServiceFault};

pub mod message_handler;

/// The implementation of a service, or a set of services will implement this trait
trait Service {
    fn name(&self) -> String;

    fn service_fault(
        &self,
        request_header: &RequestHeader,
        service_result: StatusCode,
    ) -> SupportedMessage {
        warn!(
            "Service {}, request handle {} generated a service fault with status code {}",
            self.name(),
            request_header.request_handle,
            service_result
        );
        ServiceFault::new(request_header, service_result).into()
    }
}

pub mod attribute;
pub mod discovery;
pub mod method;
pub mod monitored_item;
pub mod node_management;
pub mod query;
pub mod session;
pub mod subscription;
pub mod view;

mod audit;
