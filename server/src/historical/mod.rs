use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;

use crate::{
    address_space::AddressSpace,
};

/// The trait describes the functions that a server must implement to process historical data operations
/// from the HistoryRead / HistoryUpdate commands.
pub trait HistoricalDataProvider {
    fn read_event_details(address_space: &AddressSpace, details: ReadEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_raw_modified_details(address_space: &AddressSpace, details: ReadRawModifiedDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_processed_details(address_space: &AddressSpace, details: ReadProcessedDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn read_at_time_details(address_space: &AddressSpace, details: ReadAtTimeDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_data_details(address_space: &AddressSpace, request: UpdateDataDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_structure_data_details(address_space: &AddressSpace, request: UpdateStructureDataDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn update_event_details(address_space: &AddressSpace, request: UpdateEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_raw_modified_details(address_space: &AddressSpace, request: DeleteRawModifiedDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_at_time_details(address_space: &AddressSpace, request: DeleteAtTimeDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    fn delete_event_details(address_space: &AddressSpace, request: DeleteEventDetails) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }
}
