use opcua_types::{ByteString, BrowseDescription};

use DateTimeUTC;

use prelude::AddressSpace;

pub struct BrowseContinuationPoint {
    pub id: ByteString,
    pub address_space_last_modified: DateTimeUTC,
    pub max_references_per_node: usize,
    pub starting_index: usize,
    pub node_to_browse: BrowseDescription,
}

impl BrowseContinuationPoint {
    /// Test if the continuation point valid which is only true if address space has not been
    /// modified since the point was made.
    pub fn is_valid_browse_continuation_point(&self, address_space: &AddressSpace) -> bool {
        self.address_space_last_modified >= address_space.last_modified
    }
}