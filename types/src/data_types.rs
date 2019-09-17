use crate::date_time::DateTime;

/// This primitive data type is a UInt32 that is used as an identifier, such as a handle.
/// All values, except for 0, are valid. IntegerId = 288,
pub type IntegerId = u32;

/// This Simple DataType is a Double that defines an interval of time in milliseconds (fractions can
/// be used to define sub-millisecond values). Negative values are generally invalid but may have
/// special meanings where the Duration is used. Duration = 290,
pub type Duration = f64;

/// UtcTime = 294,
pub type UtcTime = DateTime;
