use std::{
    result::Result,
    sync::{Arc, RwLock},
};

use opcua_types::*;
use opcua_types::status_code::StatusCode;

use crate::address_space::AddressSpace;

/// The traits describes the functions that a server must implement to process historical event operations
/// from the HistoryRead / HistoryUpdate commands.
///
/// IMPORTANT NOTE: This trait is currently synchronous and may change in the future to some other
/// form. In the meantime it means if you are doing lengthy reads then use continuation points
/// to spawn a thread for that activity. Updates and deletes should be spawned on separate threads
/// if they are lengthy operations.
pub trait HistoricalEventProvider {
    fn read_event_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadEventDetails, _timestamps_to_return: TimestampsToReturn, _release_continuation_points: bool, _nodes_to_read: &[HistoryReadValueId]) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_event_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_event_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: UpdateEventDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented update_event_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_event_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: DeleteEventDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented delete_event_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}

pub enum HistoryRawData {
    HistoryData(HistoryData),
    HistoryModifiedData(HistoryModifiedData),
}

/// The trait describes the functions that a server must implement to process historical data operations
/// from the HistoryRead / HistoryUpdate commands.
///
/// IMPORTANT NOTE: This trait is currently synchronous and may change in the future to some other
/// form. In the meantime it means if you are doing lengthy reads then use continuation points
/// to spawn a thread for that activity. Updates and deletes should be spawned on separate threads
/// if they are lengthy operations.
pub trait HistoricalDataProvider {
    /// Note: Function returns an `HistoryRawData` enum containing *either* a `HistoryData` for a read raw action
    /// or a `HistoryModifiedData` for a read modified action.
    fn read_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadRawModifiedDetails, _timestamps_to_return: TimestampsToReturn, _release_continuation_points: bool, _nodes_to_read: &[HistoryReadValueId]) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_raw_modified_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_processed_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadProcessedDetails, _timestamps_to_return: TimestampsToReturn, _release_continuation_points: bool, _nodes_to_read: &[HistoryReadValueId]) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_processed_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_at_time_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadAtTimeDetails, _timestamps_to_return: TimestampsToReturn, _release_continuation_points: bool, _nodes_to_read: &[HistoryReadValueId]) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("Unimplemented read_at_time_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_data_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: UpdateDataDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented update_data_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_structure_data_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: UpdateStructureDataDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented update_structure_data_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: DeleteRawModifiedDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented delete_raw_modified_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_at_time_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: DeleteAtTimeDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("Unimplemented delete_at_time_details");
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}
