// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

// Core pubsub types and traits
pub mod data_set;
pub mod data_set_message;
pub mod data_set_meta_data;
pub mod data_set_reader;
pub mod data_set_writer;
pub mod network_message;
pub mod published_data_set;
pub mod writer_group;

pub use data_set::*;
pub use data_set_message::*;
pub use data_set_meta_data::*;
pub use data_set_reader::*;
pub use data_set_writer::*;
pub use network_message::*;
pub use published_data_set::*;
pub use writer_group::*;

pub mod message_type {
    pub const DATA: &'static str = "ua-data";
    pub const METADATA: &'static str = "ua-metadata";
    pub const KEYFRAME: &'static str = "ua-keyframe";
    pub const DELTAFRAME: &'static str = "ua-deltaframe";
    pub const EVENT: &'static str = "ua-event";
    pub const KEEPALIVE: &'static str = "ua-keepalive";
}

pub struct DataSetClassId {}

/// Template declaring the content of of a DataSet
pub struct DataSetClass {}
