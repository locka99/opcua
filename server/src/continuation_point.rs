// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2020 Adam Lock

//! Provides a browse continuation point type for tracking a browse operation initiated by a client.

use std::sync::{Arc, Mutex};

use opcua_types::{
    ByteString, DateTimeUtc,
    service_types::ReferenceDescription,
};

use crate::prelude::AddressSpace;

#[derive(Clone)]
pub struct BrowseContinuationPoint {
    pub id: ByteString,
    pub address_space_last_modified: DateTimeUtc,
    pub max_references_per_node: usize,
    pub starting_index: usize,
    pub reference_descriptions: Arc<Mutex<Vec<ReferenceDescription>>>,
}

impl BrowseContinuationPoint {
    /// Test if the continuation point valid which is only true if address space has not been
    /// modified since the point was made.
    pub fn is_valid_browse_continuation_point(&self, address_space: &AddressSpace) -> bool {
        self.address_space_last_modified >= address_space.last_modified()
    }
}