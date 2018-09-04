
pub use status_codes::StatusCode;

/// Bits for status code
bitflags! {
    pub struct StatusCodeBits: u32 {
        // Mask for the status code section
        const STATUS_MASK = 0xffff0000;
        // Mask for the bits section
        const BIT_MASK = 0x0000ffff;

        // Historian bits 0:4
        const HISTORICAL_RAW          = 0b00000000_00000000;
        const HISTORICAL_CALCULATED   = 0b00000000_00000001;
        const HISTORICAL_INTERPOLATED = 0b00000000_00000010;
        const HISTORICAL_RESERVED     = 0b00000000_00000011;
        const HISTORICAL_PARTIAL      = 0b00000000_00000100;
        const HISTORICAL_EXTRA_DATA   = 0b00000000_00001000;
        const HISTORICAL_MULTI_VALUE  = 0b00000000_00010000;
        // Overflow bit 7
        const OVERFLOW                = 0b00000000_10000000;
        // Limit bits 8:9
        const LIMIT_LOW               = 0b00000001_00000000;
        const LIMIT_HIGH              = 0b00000010_00000000;
        const LIMIT_CONSTANT          = 0b00000011_00000000;
        // Info type bits 10:11
        const LIMIT_DATA_VALUE        = 0b00000010_00000000;
        // Semantics changed bit 14
        const SEMANTICS_CHANGED       = 0b01000000_00000000;
        // Semantics changed bit 15
        const STRUCTURE_CHANGED       = 0b10000000_00000000;
    }
}