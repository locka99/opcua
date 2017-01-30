use std::io::{Read, Write};

use types::*;

/// False if the Value is Null.
const HAS_VALUE: u8 = 0x1;
/// False if the StatusCode is Good.
const HAS_STATUS: u8 = 0x2;
/// False if the Source Timestamp is DateTime.MinValue.
const HAS_SOURCE_TIMESTAMP: u8 = 0x4;
/// False if the Server Timestamp is DateTime.MinValue.
const HAS_SERVER_TIMESTAMP: u8 = 0x8;
/// False if the Source Picoseconds is 0.
const HAS_SOURCE_PICOSECONDS: u8 = 0x10;
/// False if the Server Picoseconds is 0.
const HAS_SERVER_PICOSECONDS: u8 = 0x20;

/// Data type ID 23
#[derive(PartialEq, Debug, Clone)]
pub struct DataValue {
    /// The value.
    /// Not present if the Value bit in the EncodingMask is False.
    pub value: Option<Box<Variant>>,
    /// The status associated with the value.
    /// Not present (set to GOOD) if the StatusCode bit in the EncodingMask is False
    pub status: Option<StatusCode>,
    /// The source timestamp associated with the value.
    /// Not present if the SourceTimestamp bit in the EncodingMask is False.
    pub source_timestamp: Option<DateTime>,
    /// The number of 10 picosecond intervals for the SourceTimestamp.
    /// Not present if the SourcePicoSeconds bit in the EncodingMask is False.
    /// If the source timestamp is missing the picoseconds are ignored.
    pub source_pico_seconds: Option<Int16>,
    /// The Server timestamp associated with the value.
    /// Not present if the ServerTimestamp bit in the EncodingMask is False.
    pub server_timestamp: Option<DateTime>,
    /// The number of 10 picosecond intervals for the ServerTimestamp.
    /// Not present if the ServerPicoSeconds bit in the EncodingMask is False.
    /// If the Server timestamp is missing the picoseconds are ignored.
    pub server_pico_seconds: Option<Int16>,
}

impl BinaryEncoder<DataValue> for DataValue {
    fn byte_len(&self) -> usize {
        let mut size = 1;
        let encoding_mask = self.encoding_mask();
        if encoding_mask & HAS_VALUE != 0 {
            size += self.value.as_ref().unwrap().byte_len();
        }
        if encoding_mask & HAS_STATUS != 0 {
            size += self.status.as_ref().unwrap().byte_len();
        }
        if encoding_mask & HAS_SOURCE_TIMESTAMP != 0 {
            size += self.source_timestamp.as_ref().unwrap().byte_len();
            if encoding_mask & HAS_SOURCE_PICOSECONDS != 0 {
                size += self.source_pico_seconds.as_ref().unwrap().byte_len();
            }
        }
        if encoding_mask & HAS_SERVER_TIMESTAMP != 0 {
            size += self.server_timestamp.as_ref().unwrap().byte_len();
            if encoding_mask & HAS_SERVER_PICOSECONDS != 0 {
                size += self.server_pico_seconds.as_ref().unwrap().byte_len();
            }
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;

        let encoding_mask = self.encoding_mask();
        size += encoding_mask.encode(stream)?;

        if encoding_mask & HAS_VALUE != 0 {
            size += self.value.as_ref().unwrap().encode(stream)?;
        }
        if encoding_mask & HAS_STATUS != 0 {
            size += self.status.as_ref().unwrap().encode(stream)?;
        }
        if encoding_mask & HAS_SOURCE_TIMESTAMP != 0 {
            size += self.source_timestamp.as_ref().unwrap().encode(stream)?;
            if encoding_mask & HAS_SOURCE_PICOSECONDS != 0 {
                size += self.source_pico_seconds.as_ref().unwrap().encode(stream)?;
            }
        }
        if encoding_mask & HAS_SERVER_TIMESTAMP != 0 {
            size += self.server_timestamp.as_ref().unwrap().encode(stream)?;
            if encoding_mask & HAS_SERVER_PICOSECONDS != 0 {
                size += self.server_pico_seconds.as_ref().unwrap().encode(stream)?;
            }
        }
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let encoding_mask = Byte::decode(stream)?;

        // Value
        let value = if encoding_mask & HAS_VALUE != 0 {
            Some(Box::new(Variant::decode(stream)?))
        } else {
            None
        };

        // Status
        let status = if encoding_mask & HAS_STATUS != 0 {
            Some(StatusCode::decode(stream)?)
        } else {
            None
        };

        // Source timestamp
        let source_timestamp = if encoding_mask & HAS_SOURCE_TIMESTAMP != 0 {
            Some(DateTime::decode(stream)?)
        } else {
            None
        };
        let source_pico_seconds = if encoding_mask & HAS_SOURCE_PICOSECONDS != 0 {
            Some(Int16::decode(stream)?)
        } else {
            None
        };
        // Server timestamp
        let server_timestamp = if encoding_mask & HAS_SERVER_TIMESTAMP != 0 {
            Some(DateTime::decode(stream)?)
        } else {
            None
        };
        let server_pico_seconds = if encoding_mask & HAS_SERVER_PICOSECONDS != 0 {
            Some(Int16::decode(stream)?)
        } else {
            None
        };
        // Pico second values are discarded if associated timestamp is not supplied
        Ok(DataValue {
            value: value,
            status: status,
            source_pico_seconds: if source_timestamp.is_some() { source_pico_seconds } else { None },
            source_timestamp: source_timestamp,
            server_pico_seconds: if server_timestamp.is_some() { server_pico_seconds } else { None },
            server_timestamp: server_timestamp,
        })
    }
}

impl DataValue {
    pub fn new(now: &DateTime, value: Variant) -> DataValue {
        DataValue {
            value: Some(Box::new(value)),
            status: Some(GOOD.clone()),
            source_timestamp: Some(now.clone()),
            source_pico_seconds: Some(0),
            server_timestamp: Some(now.clone()),
            server_pico_seconds: Some(0),
        }
    }

    fn encoding_mask(&self) -> Byte {
        let mut encoding_mask: Byte = 0;
        if self.value.is_some() {
            encoding_mask |= HAS_VALUE;
        }
        if self.status.is_some() {
            encoding_mask |= HAS_STATUS;
        }
        if self.source_timestamp.is_some() {
            encoding_mask |= HAS_SOURCE_TIMESTAMP;
            if self.source_pico_seconds.is_some() {
                encoding_mask |= HAS_SOURCE_PICOSECONDS;
            }
        }
        if self.server_timestamp.is_some() {
            encoding_mask |= HAS_SERVER_TIMESTAMP;
            if self.server_pico_seconds.is_some() {
                encoding_mask |= HAS_SERVER_PICOSECONDS;
            }
        }
        encoding_mask
    }
}