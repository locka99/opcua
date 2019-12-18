//! Implementations of HistoricalDataProvider and HistoricalEventProvider

use opcua_server::historical::{*};

// Register some historical data providers
pub fn add_providers(server: &mut Server) {

}

struct DataProvider;
struct EventProvider;

impl HistoricalDataProvider for DataProvider {
    //
}

impl HistoricalEventProvider for EventProvider {
    //
}