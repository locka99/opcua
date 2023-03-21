mod data_set;
mod data_set_message;
mod data_set_meta_data;
mod data_set_reader;
mod data_set_writer;
mod published_data_set;
mod writer_group;
mod network_message;

pub use data_set::*;
pub use data_set_message::*;
pub use data_set_meta_data::*;
pub use data_set_reader::*;
pub use data_set_writer::*;
pub use published_data_set::*;
pub use writer_group::*;
pub use network_message::*;

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
