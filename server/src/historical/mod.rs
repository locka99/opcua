use std::{
    result::Result,
    sync::{Arc, RwLock},
};

use opcua_types::*;
use opcua_types::status_code::StatusCode;

use crate::{
    address_space::AddressSpace,
};

/// The traits describes the functions that a server must implement to process historical event operations
/// from the HistoryRead / HistoryUpdate commands.
pub trait HistoricalEventProvider {
    fn read_event_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_event_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: UpdateEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_event_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: DeleteEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}

/// The trait describes the functions that a server must implement to process historical data operations
/// from the HistoryRead / HistoryUpdate commands.
pub trait HistoricalDataProvider {
    fn read_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadRawModifiedDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_processed_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadProcessedDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_at_time_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadAtTimeDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_data_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: UpdateDataDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_structure_data_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: UpdateStructureDataDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: DeleteRawModifiedDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_at_time_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: DeleteAtTimeDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}
