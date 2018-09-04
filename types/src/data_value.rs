//! Contains the implementation of `DataValue`.

use std::io::{Read, Write};

use ::StatusCodeBits;
use encoding::*;
use basic_types::*;
use date_time::*;
use variant::Variant;
use status_codes::StatusCode::Good;

bitflags! {
    struct DataValueFlags: u8 {
        /// False if the Value is Null.
        const HAS_VALUE = 0x1;
        /// False if the StatusCode is Good.
        const HAS_STATUS = 0x2;
        /// False if the Source Timestamp is DateTime.MinValue.
        const HAS_SOURCE_TIMESTAMP = 0x4;
        /// False if the Server Timestamp is DateTime.MinValue.
        const HAS_SERVER_TIMESTAMP = 0x8;
        /// False if the Source Picoseconds is 0.
        const HAS_SOURCE_PICOSECONDS = 0x10;
        /// False if the Server Picoseconds is 0.
        const HAS_SERVER_PICOSECONDS = 0x20;
    }
}

/// A data value is a value of a variable in the OPC UA server and contains information about its
/// value, status and change timestamps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataValue {
    /// The value. BaseDataType
    /// Not present if the Value bit in the EncodingMask is False.
    pub value: Option<Variant>,
    /// The status associated with the value.
    /// Not present if the StatusCode bit in the EncodingMask is False
    /// Note we don't use StatusCode enum because extra bits can be set on the value
    pub status: Option<UInt32>,
    /// The source timestamp associated with the value.
    /// Not present if the SourceTimestamp bit in the EncodingMask is False.
    pub source_timestamp: Option<DateTime>,
    /// The number of 10 picosecond intervals for the SourceTimestamp.
    /// Not present if the SourcePicoSeconds bit in the EncodingMask is False.
    /// If the source timestamp is missing the picoseconds are ignored.
    pub source_picoseconds: Option<Int16>,
    /// The Server timestamp associated with the value.
    /// Not present if the ServerTimestamp bit in the EncodingMask is False.
    pub server_timestamp: Option<DateTime>,
    /// The number of 10 picosecond intervals for the ServerTimestamp.
    /// Not present if the ServerPicoSeconds bit in the EncodingMask is False.
    /// If the Server timestamp is missing the picoseconds are ignored.
    pub server_picoseconds: Option<Int16>,
}

impl BinaryEncoder<DataValue> for DataValue {
    fn byte_len(&self) -> usize {
        let mut size = 1;
        let encoding_mask = self.encoding_mask();
        if encoding_mask.contains(DataValueFlags::HAS_VALUE) {
            size += self.value.as_ref().unwrap().byte_len();
        }
        if encoding_mask.contains(DataValueFlags::HAS_STATUS) {
            size += self.status.as_ref().unwrap().byte_len();
        }
        if encoding_mask.contains(DataValueFlags::HAS_SOURCE_TIMESTAMP) {
            size += self.source_timestamp.as_ref().unwrap().byte_len();
            if encoding_mask.contains(DataValueFlags::HAS_SOURCE_PICOSECONDS) {
                size += self.source_picoseconds.as_ref().unwrap().byte_len();
            }
        }
        if encoding_mask.contains(DataValueFlags::HAS_SERVER_TIMESTAMP) {
            size += self.server_timestamp.as_ref().unwrap().byte_len();
            if encoding_mask.contains(DataValueFlags::HAS_SERVER_PICOSECONDS) {
                size += self.server_picoseconds.as_ref().unwrap().byte_len();
            }
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;

        let encoding_mask = self.encoding_mask();
        size += encoding_mask.bits.encode(stream)?;

        if encoding_mask.contains(DataValueFlags::HAS_VALUE) {
            size += self.value.as_ref().unwrap().encode(stream)?;
        }
        if encoding_mask.contains(DataValueFlags::HAS_STATUS) {
            size += self.status.as_ref().unwrap().encode(stream)?;
        }
        if encoding_mask.contains(DataValueFlags::HAS_SOURCE_TIMESTAMP) {
            size += self.source_timestamp.as_ref().unwrap().encode(stream)?;
            if encoding_mask.contains(DataValueFlags::HAS_SOURCE_PICOSECONDS) {
                size += self.source_picoseconds.as_ref().unwrap().encode(stream)?;
            }
        }
        if encoding_mask.contains(DataValueFlags::HAS_SERVER_TIMESTAMP) {
            size += self.server_timestamp.as_ref().unwrap().encode(stream)?;
            if encoding_mask.contains(DataValueFlags::HAS_SERVER_PICOSECONDS) {
                size += self.server_picoseconds.as_ref().unwrap().encode(stream)?;
            }
        }
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let encoding_mask = DataValueFlags::from_bits_truncate(Byte::decode(stream)?);

        // Value
        let value = if encoding_mask.contains(DataValueFlags::HAS_VALUE) {
            Some(Variant::decode(stream)?)
        } else {
            None
        };

        // Status
        let status = if encoding_mask.contains(DataValueFlags::HAS_STATUS) {
            Some(UInt32::decode(stream)?)
        } else {
            None
        };

        // Source timestamp
        let source_timestamp = if encoding_mask.contains(DataValueFlags::HAS_SOURCE_TIMESTAMP) {
            Some(DateTime::decode(stream)?)
        } else {
            None
        };
        let source_picoseconds = if encoding_mask.contains(DataValueFlags::HAS_SOURCE_PICOSECONDS) {
            Some(Int16::decode(stream)?)
        } else {
            None
        };
        // Server timestamp
        let server_timestamp = if encoding_mask.contains(DataValueFlags::HAS_SERVER_TIMESTAMP) {
            Some(DateTime::decode(stream)?)
        } else {
            None
        };
        let server_picoseconds = if encoding_mask.contains(DataValueFlags::HAS_SERVER_PICOSECONDS) {
            Some(Int16::decode(stream)?)
        } else {
            None
        };
        // Pico second values are discarded if associated timestamp is not supplied
        Ok(DataValue {
            value,
            status,
            source_picoseconds: if source_timestamp.is_some() { source_picoseconds } else { None },
            source_timestamp,
            server_picoseconds: if server_timestamp.is_some() { server_picoseconds } else { None },
            server_timestamp,
        })
    }
}

impl From<Variant> for DataValue {
    fn from(v: Variant) -> Self {
        DataValue::new(v)
    }
}

impl DataValue {
    /// Creates a data value from the supplied value
    pub fn new<V>(value: V) -> DataValue where V: Into<Variant> {
        let now = DateTime::now();
        DataValue {
            value: Some(value.into()),
            status: Some(Good as UInt32),
            source_timestamp: Some(now.clone()),
            source_picoseconds: Some(0),
            server_timestamp: Some(now.clone()),
            server_picoseconds: Some(0),
        }
    }

    /// Creates an empty DataValue
    pub fn null() -> DataValue {
        DataValue {
            value: None,
            status: None,
            source_timestamp: None,
            source_picoseconds: None,
            server_timestamp: None,
            server_picoseconds: None,
        }
    }

    /// Sets the value of the data value, updating the timestamps at the same point
    pub fn set_value<V>(&mut self, value: V, source_timestamp: DateTime, server_timestamp: DateTime) where V: Into<Variant> {
        self.value = Some(value.into());
        self.source_timestamp = Some(source_timestamp);
        self.source_picoseconds = Some(0);
        self.server_timestamp = Some(server_timestamp);
        self.server_picoseconds = Some(0);
    }

    /// Returns the status code as a UInt32
    pub fn status(&self) -> UInt32 {
        if let Some(ref status) = self.status {
            *status
        } else {
            0
        }
    }

    /// Test if the value held by this data value is known to be good
    /// Anything other than Good is assumed to be invalid.
    pub fn is_valid(&self) -> bool {
        (self.status() & StatusCodeBits::STATUS_MASK.bits) == 0
    }

    fn encoding_mask(&self) -> DataValueFlags {
        let mut encoding_mask = DataValueFlags::empty();
        if self.value.is_some() {
            encoding_mask |= DataValueFlags::HAS_VALUE;
        }
        if self.status.is_some() {
            encoding_mask |= DataValueFlags::HAS_STATUS;
        }
        if self.source_timestamp.is_some() {
            encoding_mask |= DataValueFlags::HAS_SOURCE_TIMESTAMP;
            if self.source_picoseconds.is_some() {
                encoding_mask |= DataValueFlags::HAS_SOURCE_PICOSECONDS;
            }
        }
        if self.server_timestamp.is_some() {
            encoding_mask |= DataValueFlags::HAS_SERVER_TIMESTAMP;
            if self.server_picoseconds.is_some() {
                encoding_mask |= DataValueFlags::HAS_SERVER_PICOSECONDS;
            }
        }
        encoding_mask
    }
}