// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use crate::types::*;

use super::*;

/// An entity creating DataSetMessages from DataSets and publishing them through a Message Oriented Middleware.
/// A DataSetWriter encodes a DataSet to a DataSetMessage and includes the DataSetMessage into a NetworkMessage for publishing
/// through a Message Oriented Middleware
pub trait DataSetWriter {
    /// The name of the dataset writer
    fn name(&self) -> String {
        String::new()
    }
    /// The enabled state of the dataset writer
    fn enabled(&self) -> bool {
        true
    }
    /// Returns the unique id of the dataset writer for a published dataset. Defined in 6.2.3.1
    fn id(&self) -> u16;
    /// Defined in 6.2.3.2
    fn content_mask(&self) -> DataSetFieldContentMask {
        DataSetFieldContentMask::RawData
    }
    // Defined in 6.2.3.3
    fn key_frame_count(&self) -> u32 {
        0
    }
    /// The name of the corresponding published data set
    fn data_set_name(&self) -> String {
        String::new()
    }
    // Defined in 6.2.3.4
    fn data_set_properties(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    //  Defined in 6.2.3.5.2
    //  fn transport_settings(&self) -> DataSetWriterTransportDataType {
    //    DataSetWriterTransportDataType:
    //  }

    //  Defined in 6.2.3.5.3
    //  fn message_data_type(&self) -> DataSetWriterMessageDataType {
    //
    //  }

    /// Writes a data set as a data set message
    fn write(&mut self, ds: &data_set::DataSet) -> Box<dyn DataSetMessage>;
}
