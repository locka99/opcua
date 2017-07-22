use std::io::{Read, Write};
use std::fmt;

use encoding::*;
use basic_types::*;
use date_time::*;
use generated::StatusCode::*;

/// This primitive data type is a UInt32 that identifies an element of an array.
pub type Index = UInt32;

/// This primitive data type is a UInt32 that is used as an identifier, such as a handle.
/// All values, except for 0, are valid. IntegerId = 288,
pub type IntegerId = UInt32;

pub const MESSAGE_SECURITY_MODE_NONE: &'static str = "None";
pub const MESSAGE_SECURITY_MODE_SIGN: &'static str = "Sign";
pub const MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT: &'static str = "SignAndEncrypt";

/// The MessageSecurityMode is an enumeration that specifies what security should be applied to messages exchanges during a Session.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum MessageSecurityMode {
    /// The MessageSecurityMode is invalid.
    /// This value is the default value to avoid an accidental choice of no security is applied.
    /// This choice will always be rejected.
    Invalid = 0,
    /// No security is applied.
    None = 1,
    /// All messages are signed but not encrypted.
    Sign = 2,
    /// All messages are signed and encrypted.
    SignAndEncrypt = 3,
}

impl BinaryEncoder<MessageSecurityMode> for MessageSecurityMode {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        Ok(match value {
            0 => MessageSecurityMode::Invalid,
            1 => MessageSecurityMode::None,
            2 => MessageSecurityMode::Sign,
            3 => MessageSecurityMode::SignAndEncrypt,
            _ => {
                error!("Mode value is invalid = {}", value);
                MessageSecurityMode::Invalid
            }
        })
    }
}

impl fmt::Display for MessageSecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            &MessageSecurityMode::None => MESSAGE_SECURITY_MODE_NONE,
            &MessageSecurityMode::Sign => MESSAGE_SECURITY_MODE_SIGN,
            &MessageSecurityMode::SignAndEncrypt => MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT,
            _ => "",
        };
        write!(f, "{}", name)
    }
}

impl MessageSecurityMode {
    pub fn from_str(str: &str) -> MessageSecurityMode {
        match str {
            MESSAGE_SECURITY_MODE_NONE => MessageSecurityMode::None,
            MESSAGE_SECURITY_MODE_SIGN => MessageSecurityMode::Sign,
            MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT => MessageSecurityMode::SignAndEncrypt,
            _ => {
                error!("Specified security policy {} is not recognized", str);
                MessageSecurityMode::Invalid
            }
        }
    }
}

/// This Simple DataType is a Double that defines an interval of time in milliseconds (fractions can
/// be used to define sub-millisecond values). Negative values are generally invalid but may have
/// special meanings where the Duration is used. Duration = 290,
pub type Duration = Double;

/// UtcTime = 294,
pub type UtcTime = DateTime;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MonitoringMode {
    Disabled = 0,
    Sampling = 1,
    Reporting = 2,
}

impl BinaryEncoder<MonitoringMode> for MonitoringMode {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(MonitoringMode::Disabled),
            1 => Ok(MonitoringMode::Sampling),
            2 => Ok(MonitoringMode::Reporting),
            _ => {
                error!("Don't know what monitoring mode {} is", value);
                Err(BAD_MONITORING_MODE_INVALID)
            }
        }
    }
}
