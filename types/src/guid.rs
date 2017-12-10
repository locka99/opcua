use std::fmt;
use std::str::FromStr;
use std::io::{Read, Write, Cursor};

use encoding::*;
use basic_types::*;

/// A 16 byte value that can be used as a globally unique identifier.
/// Data type ID 14
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct Guid {
    pub data1: UInt32,
    pub data2: UInt16,
    pub data3: UInt16,
    pub data4: [Byte; 8],
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_hyphenated_string())
    }
}

impl BinaryEncoder<Guid> for Guid {
    fn byte_len(&self) -> usize {
        16
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        let data = [(self.data1 >> 0) as u8,
            (self.data1 >> 8) as u8,
            (self.data1 >> 16) as u8,
            (self.data1 >> 24) as u8,
            (self.data2 >> 0) as u8,
            (self.data2 >> 8) as u8,
            (self.data3 >> 0) as u8,
            (self.data3 >> 8) as u8,
            self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7]
        ];
        size += process_encode_io_result(stream.write(&data))?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let mut data = [0u8; 16];
        process_decode_io_result(stream.read_exact(&mut data))?;
        let data1: UInt32 = (data[0] as UInt32).wrapping_shl(0) + (data[1] as UInt32).wrapping_shl(8) + (data[2] as UInt32).wrapping_shl(16) + (data[3] as UInt32).wrapping_shl(24);
        let data2: UInt16 = (data[4] as UInt16).wrapping_shl(0) + (data[5] as UInt16).wrapping_shl(8);
        let data3: UInt16 = (data[6] as UInt16).wrapping_shl(0) + (data[7] as UInt16).wrapping_shl(8);
        let data4 = [data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]];
        Ok(Guid { data1, data2, data3, data4 })
    }
}

const SIMPLE_LENGTH: usize = 32;
const HYPHENATED_LENGTH: usize = 36;

// Accumulated length of each hyphenated group in hex digits.
const ACC_GROUP_LENS: [u8; 5] = [8, 12, 16, 20, 32];

impl FromStr for Guid {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Adapted from Uuid::parse_str - https://github.com/rust-lang-nursery/uuid/blob/master/src/lib.rs
        // Main difference is we decode the Guid from the buffer at the end and there are no error
        // codes

        let len = s.len();
        if len != SIMPLE_LENGTH && len != HYPHENATED_LENGTH {
            return Err(());
        }

        let mut digit = 0;
        let mut group = 0;
        let mut acc = 0;
        let mut buffer = [0u8; 16];

        for (_, chr) in s.chars().enumerate() {
            if digit as usize >= SIMPLE_LENGTH && group == 0 {
                return Err(());
            }
            if digit % 2 == 0 {
                // First digit of the byte.
                match chr {
                    // Calculate upper half.
                    '0' ... '9' => acc = chr as u8 - '0' as u8,
                    'a' ... 'f' => acc = chr as u8 - 'a' as u8 + 10,
                    'A' ... 'F' => acc = chr as u8 - 'A' as u8 + 10,
                    // Found a group delimiter
                    '-' => {
                        if ACC_GROUP_LENS[group] != digit {
                            // Calculate how many digits this group consists of in the input.
                            return Err(());
                        }
                        // Next group, decrement digit, it is incremented again at the bottom.
                        group += 1;
                        digit -= 1;
                    }
                    _ => return Err(()),
                }
            } else {
                // Second digit of the byte, shift the upper half.
                acc *= 16;
                match chr {
                    '0' ... '9' => acc += chr as u8 - '0' as u8,
                    'a' ... 'f' => acc += chr as u8 - 'a' as u8 + 10,
                    'A' ... 'F' => acc += chr as u8 - 'A' as u8 + 10,
                    '-' => {
                        // The byte isn't complete yet.
                        return Err(());
                    }
                    _ => return Err(()),
                }
                buffer[(digit / 2) as usize] = acc;
            }
            digit += 1;
        }

        // Now check the last group.
        if group != 0 && group != 4 {
            return Err(());
        } else if ACC_GROUP_LENS[4] != digit {
            return Err(());
        }

        let mut stream = Cursor::new(&buffer);
        Ok(Guid::decode(&mut stream).unwrap())
    }
}

impl Guid {
    pub fn null() -> Guid {
        Guid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0u8; 8],
        }
    }

    pub fn as_hyphenated_string(&self) -> String {
        format!("{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                self.data1, self.data2, self.data3, self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7])
    }
}
