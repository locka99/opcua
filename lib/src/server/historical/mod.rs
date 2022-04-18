// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{result::Result, sync::Arc};

use crate::sync::*;
use crate::types::status_code::StatusCode;
use crate::types::*;

use crate::server::address_space::AddressSpace;

/// Values that should be set in the address space via `AddressSpace::set_history_server_capabilities()`
/// to denote to clients what history capabilities the server has.
pub struct HistoryServerCapabilities {
    pub access_history_data: bool,
    pub access_history_events: bool,
    pub max_return_data: u32,
    pub max_return_events: u32,
    pub insert_data: bool,
    pub replace_data: bool,
    pub update_data: bool,
    pub delete_raw: bool,
    pub delete_at_time: bool,
    pub insert_event: bool,
    pub replace_event: bool,
    pub update_event: bool,
    pub delete_event: bool,
    pub insert_annotation: bool,
}

/// The `HistoricalEventProvider` trait provides the function stubs that a server will call
/// to process historical event operations. The implementor of this trait may provide their
///// own implementation as many functions as they desire leaving the remainder as stubs.
///
/// IMPORTANT NOTE: This trait is currently synchronous and may change in the future to some other
/// form. In the meantime it means if you are doing lengthy reads then use continuation points
/// to spawn a thread for that activity. Updates and deletes should be spawned on separate threads
/// if they are lengthy operations.
pub trait HistoricalEventProvider {
    fn read_event_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: ReadEventDetails,
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
        _nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_event_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_event_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: UpdateEventDetails,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented update_event_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_event_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: DeleteEventDetails,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented delete_event_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}

pub enum HistoryRawData {
    HistoryData(HistoryData),
    HistoryModifiedData(HistoryModifiedData),
}

/// The `HistoricalEventProvider` trait provides the function stubs that a server will call
/// to process historical data operations. The implementor of this trait may provide their
/// own implementation as many functions as they desire leaving the remainder as stubs.
///
/// IMPORTANT NOTE: This trait is currently synchronous and may change in the future to some other
/// form. In the meantime it means if you are doing lengthy reads then use continuation points
/// to spawn a thread for that activity. Updates and deletes should be spawned on separate threads
/// if they are lengthy operations.
pub trait HistoricalDataProvider {
    /// Note: Function returns an `HistoryRawData` enum containing *either* a `HistoryData` for a read raw action
    /// or a `HistoryModifiedData` for a read modified action.
    fn read_raw_modified_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: ReadRawModifiedDetails,
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
        _nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_raw_modified_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_processed_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: ReadProcessedDetails,
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
        _nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_processed_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_at_time_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: ReadAtTimeDetails,
        _timestamps_to_return: TimestampsToReturn,
        _release_continuation_points: bool,
        _nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_at_time_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_data_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: UpdateDataDetails,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented update_data_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_structure_data_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: UpdateStructureDataDetails,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented update_structure_data_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_raw_modified_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: DeleteRawModifiedDetails,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented delete_raw_modified_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_at_time_details(
        &self,
        _address_space: Arc<RwLock<AddressSpace>>,
        _request: DeleteAtTimeDetails,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented delete_at_time_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}
