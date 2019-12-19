//! Implementations of HistoricalDataProvider and HistoricalEventProvider

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
    //
}

impl HistoricalEventProvider for EventProvider {
    //
}