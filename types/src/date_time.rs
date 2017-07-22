use std::io::{Read, Write};

use chrono::{self, UTC, TimeZone, Timelike, Datelike};

use {BinaryEncoder, EncodingResult};
use basic_types::*;
use helpers::{write_i64, read_i64};

const NANOS_PER_SECOND: i64 = 1_000_000_000;
const NANOS_PER_TICK: i64 = 100;
const TICKS_PER_SECOND: i64 = NANOS_PER_SECOND / NANOS_PER_TICK;

const MIN_YEAR: UInt16 = 1601;
const MAX_YEAR: UInt16 = 9999;

/// Data type ID 13
//
/// Holds a date/time broken down into constituent parts
#[derive(PartialEq, Debug, Clone)]
pub struct DateTime {
    // Year in full format, e.g. 2016
    pub year: UInt16,
    // Month [1,12]
    pub month: UInt16,
    // Day of month [1,31]
    pub day: UInt16,
    // Hour [0,23]
    pub hour: UInt16,
    // Minutes [0,59]
    pub min: UInt16,
    // Seconds [0,59]
    pub sec: UInt16,
    // Nanoseconds past the second [0 to 10^9 - 1]
    pub nano_sec: UInt32,
}

/// DateTime encoded as 64-bit signed int
impl BinaryEncoder<DateTime> for DateTime {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let ticks = self.checked_ticks();
        write_i64(stream, ticks)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let ticks = read_i64(stream)?;
        Ok(DateTime::from_ticks(ticks))
    }
}

impl DateTime {
    /// Constructs from the current time
    pub fn now() -> DateTime {
        DateTime::from_chrono(&UTC::now())
    }

    /// Constructs from a year, month, day 
    pub fn ymd(year: UInt16, month: UInt16, day: UInt16) -> DateTime {
        DateTime::ymd_hms_nano(year, month, day, 0, 0, 0, 0)
    }

    /// Constructs from a year, month, day, hour, minute, second
    pub fn ymd_hms(year: UInt16,
                   month: UInt16,
                   day: UInt16,
                   hour: UInt16,
                   minute: UInt16,
                   second: UInt16)
                   -> DateTime {
        DateTime::ymd_hms_nano(year, month, day, hour, minute, second, 0)
    }

    /// Constructs from a year, month, day, hour, minute, second, nanosecond
    pub fn ymd_hms_nano(year: UInt16,
                        month: UInt16,
                        day: UInt16,
                        hour: UInt16,
                        minute: UInt16,
                        second: UInt16,
                        nanos: UInt32) -> DateTime {
        if month < 1 || month > 12 {
            panic!("Invalid month");
        }
        if day < 1 || day > 31 {
            panic!("Invalid day");
        }
        if hour > 23 {
            panic!("Invalid hour");
        }
        if minute > 59 {
            panic!("Invalid minute");
        }
        if second > 59 {
            panic!("Invalid second");
        }
        if nanos as i64 >= NANOS_PER_SECOND {
            panic!("Invalid nanosecond");
        }
        DateTime {
            year: year,
            month: month,
            day: day,
            hour: hour,
            min: minute,
            sec: second,
            nano_sec: (nanos / NANOS_PER_TICK as u32) * NANOS_PER_TICK as u32,
        }
    }

    /// Converts from the equivalent chrono type
    pub fn from_chrono(dt: &chrono::DateTime<UTC>) -> DateTime {
        DateTime {
            year: dt.year() as UInt16,
            month: dt.month() as UInt16,
            day: dt.day() as UInt16,
            hour: dt.hour() as UInt16,
            min: dt.minute() as UInt16,
            sec: dt.second() as UInt16,
            nano_sec: (dt.nanosecond() / NANOS_PER_TICK as u32) * NANOS_PER_TICK as u32,
        }
    }

    /// Returns the equivalent chrono type
    pub fn as_chrono(&self) -> chrono::DateTime<UTC> {
        UTC.ymd(self.year as i32, self.month as u32, self.day as u32)
            .and_hms_nano(self.hour as u32,
                          self.min as u32,
                          self.sec as u32,
                          self.nano_sec as u32)
    }

    /// Create a date time in ticks, of 100 nanosecond intervals relative to the UA epoch
    pub fn from_ticks(ticks: i64) -> DateTime {
        DateTime::from_chrono(&(epoch_chrono() + ticks_to_duration(ticks)))
    }

    /// Returns the time in ticks, of 100 nanosecond intervals
    pub fn ticks(&self) -> i64 {
        duration_to_ticks(self.as_chrono().signed_duration_since(epoch_chrono()))
    }

    /// To checked ticks. Function returns 0 or MAX_INT64
    /// if date exceeds valid OPC UA range
    pub fn checked_ticks(&self) -> i64 {
        let nanos = self.ticks();
        if nanos < 0 {
            return 0;
        }
        if nanos > max_ticks() {
            return i64::max_value();
        }
        nanos
    }
}

/// The OPC UA epoch - Jan 1 1601 00:00:00
pub fn epoch_chrono() -> chrono::DateTime<UTC> {
    UTC.ymd(MIN_YEAR as i32, 1, 1).and_hms(0, 0, 0)
}

/// The OPC UA endtimes - Dec 31 9999 23:59:59 i.e. the date after which dates are returned as MAX_INT64 ticks 
/// Spec doesn't say what happens in the last second before midnight...
pub fn endtimes_chrono() -> chrono::DateTime<UTC> {
    UTC.ymd(MAX_YEAR as i32, 12, 31).and_hms(23, 59, 59)
}

/// Turns a duration to ticks
fn duration_to_ticks(duration: chrono::Duration) -> i64 {
    // We can't directly ask for nanos because it will exceed i64,
    // so we have to subtract the total seconds before asking for the nano portion
    let seconds_part = chrono::Duration::seconds(duration.num_seconds());
    let seconds = seconds_part.num_seconds();
    let nanos = (duration - seconds_part).num_nanoseconds().unwrap();
    // Put it back together in ticks
    seconds * TICKS_PER_SECOND + nanos / NANOS_PER_TICK
}

/// Turns ticks to a duration
fn ticks_to_duration(ticks: i64) -> chrono::Duration {
    let secs = ticks / TICKS_PER_SECOND;
    let nanos = (ticks - secs * TICKS_PER_SECOND) * NANOS_PER_TICK;
    chrono::Duration::seconds(secs) + chrono::Duration::nanoseconds(nanos)
}

fn max_ticks() -> i64 {
    duration_to_ticks(endtimes_chrono().signed_duration_since(epoch_chrono()))
}
