use std::io;

pub use status_codes::StatusCode;

/// Bits for status code
bitflags! {
    pub struct StatusCodeBits: u32 {
        // Mask for the status code section
        const STATUS_MASK = 0xffff_0000;
        // Mask for the bits section
        const BIT_MASK = 0x0000_ffff;

        // Historian bits 0:4
        const HISTORICAL_RAW          = 0b0000_0000_0000_0000;
        const HISTORICAL_CALCULATED   = 0b0000_0000_0000_0001;
        const HISTORICAL_INTERPOLATED = 0b0000_0000_0000_0010;
        const HISTORICAL_RESERVED     = 0b0000_0000_0000_0011;
        const HISTORICAL_PARTIAL      = 0b0000_0000_0000_0100;
        const HISTORICAL_EXTRA_DATA   = 0b0000_0000_0000_1000;
        const HISTORICAL_MULTI_VALUE  = 0b0000_0000_0001_0000;
        // Overflow bit 7
        const OVERFLOW                = 0b0000_0000_1000_0000;
        // Limit bits 8:9
        const LIMIT_LOW               = 0b0000_0001_0000_0000;
        const LIMIT_HIGH              = 0b0000_0010_0000_0000;
        const LIMIT_CONSTANT          = 0b0000_0011_0000_0000;
        // Info type bits 10:11
        const LIMIT_DATA_VALUE        = 0b0000_0010_0000_0000;
        // Semantics changed bit 14
        const SEMANTICS_CHANGED       = 0b0100_0000_0000_0000;
        // Semantics changed bit 15
        const STRUCTURE_CHANGED       = 0b1000_0000_0000_0000;
    }
}

impl From<StatusCode> for io::Error {
    fn from(e: StatusCode) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("StatusCode {:?}", e))
    }
}
