// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::core::supported_message::SupportedMessage;
use crate::types::{service_types::PublishRequest, status_code::StatusCode};

/// The publish request entry preserves the request_id which is part of the chunk layer but clients
/// are fickle about receiving responses from the same as the request. Normally this is easy because
/// request and response are synchronous, but publish requests are async, so we preserve the request_id
/// so that later we can send out responses that have the proper req id
#[derive(Clone)]
pub struct PublishRequestEntry {
    // The request id
    pub request_id: u32,
    // The request itself
    pub request: PublishRequest,
    // The result of clearing acknowledgments when the request was received.
    pub results: Option<Vec<StatusCode>>,
}

#[derive(Clone, Debug)]
pub struct PublishResponseEntry {
    pub request_id: u32,
    pub response: SupportedMessage,
}

/// This converts an OPC UA Duration into a time duration used for testing for interval elapsed
fn duration_from_ms(d: f64) -> chrono::Duration {
    // Duration is a floating point number in millis so turn to microseconds for greater accuracy
    // 1 millisecond = 1000 microsecond
    chrono::Duration::microseconds((d * 1000f64) as i64)
}

pub mod monitored_item;
pub mod subscription;
pub mod subscriptions;
