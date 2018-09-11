//! Provides a browse continuation point type for tracking a browse operation initiated by a client.

use std::sync::{Arc, Mutex};

use opcua_types::{ByteString};
use opcua_types::service_types::ReferenceDescription;

use DateTimeUtc;

use prelude::AddressSpace;

#[derive(Clone)]
pub struct BrowseContinuationPoint {
    pub id: ByteString,
    pub address_space_last_modified: DateTimeUtc,
    pub max_references_per_node: usize,
    pub starting_index: usize,
    pub reference_descriptions: Arc<Mutex<Vec<ReferenceDescription>>>
}

impl BrowseContinuationPoint {
    /// Test if the continuation point valid which is only true if address space has not been
    /// modified since the point was made.
    pub fn is_valid_browse_continuation_point(&self, address_space: &AddressSpace) -> bool {
        self.address_space_last_modified >= address_space.last_modified()
    }
}