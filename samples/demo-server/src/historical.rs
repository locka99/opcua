// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2020 Adam Lock

//! Implementations of HistoricalDataProvider and HistoricalEventProvider
use std::sync::{Arc, RwLock};

use opcua_server::prelude::*;

// Register some historical data providers
pub fn add_providers(server: &mut Server) {
    let server_state = server.server_state();
    let mut server_state = server_state.write().unwrap();
    server_state.set_historical_data_provider(Box::new(DataProvider));
    server_state.set_historical_event_provider(Box::new(EventProvider));
}

pub struct DataProvider;

pub struct EventProvider;

impl HistoricalDataProvider for DataProvider {
    fn read_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadRawModifiedDetails, _timestamps_to_return: TimestampsToReturn, _release_continuation_points: bool, _nodes_to_read: &[HistoryReadValueId]) -> Result<Vec<HistoryReadResult>, StatusCode> {
        println!("Overridden read_raw_modified_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}

impl HistoricalEventProvider for EventProvider {
    //
}