// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Provides functionality to create an address space, find nodes, add nodes, change attributes
//! and values on nodes.

pub use self::address_space::AddressSpace;

pub(crate) use self::generated::populate_address_space;

pub mod address_space;
pub mod base;
pub mod references;
pub mod relative_path;

#[rustfmt::skip]
#[cfg(feature = "generated-address-space")]
mod generated;
#[cfg(feature = "generated-address-space")]
mod method_impls;

pub use crate::async_server::address_space::EventNotifier;

pub mod types {
    pub use crate::async_server::address_space::*;
}
