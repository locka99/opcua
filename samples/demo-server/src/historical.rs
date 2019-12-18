//! Implementations of HistoricalDataProvider and HistoricalEventProvider

use opcua_server::prelude::*;

// Register some historical data providers
pub fn add_providers(server: &mut Server) {}

pub struct DataProvider;

pub struct EventProvider;

impl HistoricalDataProvider for DataProvider {
    //
}

impl HistoricalEventProvider for EventProvider {
    //
}