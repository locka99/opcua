use std::fmt;
use std::str::FromStr;
use std::io::{Read, Write};

use encoding::*;
use uuid::Uuid;

/// A 16 byte value that can be used as a globally unique identifier.
/// Data type ID 14
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct Guid {
    uuid: Uuid,
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.uuid.hyphenated())
    }
}

impl BinaryEncoder<Guid> for Guid {
    fn byte_len(&self) -> usize {
        16
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        size += process_encode_io_result(stream.write(self.uuid.as_bytes()))?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let mut bytes = [0u8; 16];
        process_decode_io_result(stream.read_exact(&mut bytes))?;
        Ok(Guid { uuid: Uuid::from_bytes(&bytes).unwrap() })
    }
}

impl FromStr for Guid {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s);
        if let Ok(uuid) = uuid {
            Ok(Guid { uuid })
        } else {
            println!("Error = {:?}", uuid.unwrap_err());
            error!("Guid cannot be parsed from string - wrong format");
            Err(())
        }
    }
}

impl Guid {
    /// Return a null guid, i.e. 00000000-0000-0000-0000-000000000000
    pub fn null() -> Guid {
        Guid { uuid: Uuid::nil() }
    }

    /// Creates a random Guid
    pub fn new() -> Guid {
        Guid { uuid: Uuid::new_v4() }
    }
}
