// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the implementation of `DataTime`.

use std::{
    cmp::Ordering,
    fmt,
    io::{Read, Write},
    ops::{Add, Sub},
    str::FromStr,
};

use chrono::{Datelike, Duration, TimeZone, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::encoding::*;

const NANOS_PER_SECOND: i64 = 1_000_000_000;
const NANOS_PER_TICK: i64 = 100;
const TICKS_PER_SECOND: i64 = NANOS_PER_SECOND / NANOS_PER_TICK;

const MIN_YEAR: u16 = 1601;
const MAX_YEAR: u16 = 9999;

pub type DateTimeUtc = chrono::DateTime<Utc>;

/// A date/time value. This is a wrapper around the chrono type with extra functionality
/// for obtaining ticks in OPC UA measurements, endtimes, epoch etc.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct DateTime {
    date_time: DateTimeUtc,
}

impl Serialize for DateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ticks = self.checked_ticks();
        ticks.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DateTime {
    fn deserialize<D>(deserializer: D) -> Result<DateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ticks = i64::deserialize(deserializer)?;
        Ok(DateTime::from(ticks))
    }
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

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let ticks = read_i64(stream)?;
        let date_time = DateTime::from(ticks);
        // Client offset is a value that can be overridden to account for time discrepancies between client & server -
        // note perhaps it is not a good idea to do it right here but it is the lowest point to intercept DateTime values.
        Ok(date_time - decoding_options.client_offset)
    }
}

impl Default for DateTime {
    fn default() -> Self {
        DateTime::epoch()
    }
}

impl Add<Duration> for DateTime {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        DateTime::from(self.date_time + duration)
    }
}

impl Sub<DateTime> for DateTime {
    type Output = Duration;

    fn sub(self, other: Self) -> Duration {
        self.date_time - other.date_time
    }
}

impl Sub<Duration> for DateTime {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self {
        DateTime::from(self.date_time - duration)
    }
}

impl PartialOrd for DateTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.date_time.cmp(&other.date_time))
    }
}

// From ymd_hms
impl From<(u16, u16, u16, u16, u16, u16)> for DateTime {
    fn from(dt: (u16, u16, u16, u16, u16, u16)) -> Self {
        let (year, month, day, hour, minute, second) = dt;
        DateTime::from((year, month, day, hour, minute, second, 0))
    }
}

// From ymd_hms
impl From<(u16, u16, u16, u16, u16, u16, u32)> for DateTime {
    fn from(dt: (u16, u16, u16, u16, u16, u16, u32)) -> Self {
        let (year, month, day, hour, minute, second, nanos) = dt;
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
        let dt = Utc.ymd(year as i32, month as u32, day as u32).and_hms_nano(
            hour as u32,
            minute as u32,
            second as u32,
            nanos,
        );
        DateTime::from(dt)
    }
}

impl From<DateTimeUtc> for DateTime {
    fn from(date_time: DateTimeUtc) -> Self {
        // OPC UA date time is more granular with nanos, so the value supplied is made granular too
        let year = date_time.year();
        let month = date_time.month();
        let day = date_time.day();
        let hour = date_time.hour();
        let minute = date_time.minute();
        let second = date_time.second();
        let nanos = (date_time.nanosecond() / NANOS_PER_TICK as u32) * NANOS_PER_TICK as u32;
        let date_time = Utc
            .ymd(year, month, day)
            .and_hms_nano(hour, minute, second, nanos);
        DateTime { date_time }
    }
}

impl From<i64> for DateTime {
    fn from(value: i64) -> Self {
        if value == i64::max_value() {
            // Max signifies end times
            Self::endtimes()
        } else {
            let secs = value / TICKS_PER_SECOND;
            let nanos = (value - secs * TICKS_PER_SECOND) * NANOS_PER_TICK;
            let duration = Duration::seconds(secs) + Duration::nanoseconds(nanos);
            Self::from(Self::epoch_chrono() + duration)
        }
    }
}

impl Into<i64> for DateTime {
    fn into(self) -> i64 {
        self.checked_ticks()
    }
}

impl Into<DateTimeUtc> for DateTime {
    fn into(self) -> DateTimeUtc {
        self.as_chrono()
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.date_time.to_rfc3339())
    }
}

impl FromStr for DateTime {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DateTimeUtc::from_str(s).map(DateTime::from).map_err(|e| {
            error!("Cannot parse date {}, error = {}", s, e);
        })
    }
}

impl DateTime {
    /// Constructs from the current time
    pub fn now() -> DateTime {
        DateTime::from(Utc::now())
    }

    /// Constructs from the current time with an offset
    pub fn now_with_offset(offset: Duration) -> DateTime {
        DateTime::from(Utc::now() + offset)
    }

    /// Creates a null date time (i.e. the epoch)
    pub fn null() -> DateTime {
        // The epoch is 0, so effectively null
        DateTime::epoch()
    }

    /// Tests if the date time is null (i.e. equal to epoch)
    pub fn is_null(&self) -> bool {
        self.ticks() == 0i64
    }

    /// Constructs a date time for the epoch
    pub fn epoch() -> DateTime {
        DateTime::from(Self::epoch_chrono())
    }

    /// Constructs a date time for the endtimes
    pub fn endtimes() -> DateTime {
        DateTime::from(Self::endtimes_chrono())
    }

    /// Returns the maximum tick value, corresponding to the end of time
    pub fn endtimes_ticks() -> i64 {
        Self::duration_to_ticks(Self::endtimes_chrono().signed_duration_since(Self::epoch_chrono()))
    }

    /// Constructs from a year, month, day
    pub fn ymd(year: u16, month: u16, day: u16) -> DateTime {
        DateTime::ymd_hms(year, month, day, 0, 0, 0)
    }

    /// Constructs from a year, month, day, hour, minute, second
    pub fn ymd_hms(
        year: u16,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
    ) -> DateTime {
        DateTime::from((year, month, day, hour, minute, second))
    }

    /// Constructs from a year, month, day, hour, minute, second, nanosecond
    pub fn ymd_hms_nano(
        year: u16,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        nanos: u32,
    ) -> DateTime {
        DateTime::from((year, month, day, hour, minute, second, nanos))
    }

    /// Returns the time in ticks, of 100 nanosecond intervals
    pub fn ticks(&self) -> i64 {
        Self::duration_to_ticks(self.date_time.signed_duration_since(Self::epoch_chrono()))
    }

    /// To checked ticks. Function returns 0 or MAX_INT64
    /// if date exceeds valid OPC UA range
    pub fn checked_ticks(&self) -> i64 {
        let nanos = self.ticks();
        if nanos < 0 {
            return 0;
        }
        if nanos > Self::endtimes_ticks() {
            return i64::max_value();
        }
        nanos
    }

    /// Time as chrono
    pub fn as_chrono(&self) -> DateTimeUtc {
        self.date_time
    }

    /// The OPC UA epoch - Jan 1 1601 00:00:00
    fn epoch_chrono() -> DateTimeUtc {
        Utc.ymd(MIN_YEAR as i32, 1, 1).and_hms(0, 0, 0)
    }

    /// The OPC UA endtimes - Dec 31 9999 23:59:59 i.e. the date after which dates are returned as MAX_INT64 ticks
    /// Spec doesn't say what happens in the last second before midnight...
    fn endtimes_chrono() -> DateTimeUtc {
        Utc.ymd(MAX_YEAR as i32, 12, 31).and_hms(23, 59, 59)
    }

    /// Turns a duration to ticks
    fn duration_to_ticks(duration: Duration) -> i64 {
        // We can't directly ask for nanos because it will exceed i64,
        // so we have to subtract the total seconds before asking for the nano portion
        let seconds_part = Duration::seconds(duration.num_seconds());
        let seconds = seconds_part.num_seconds();
        let nanos = (duration - seconds_part).num_nanoseconds().unwrap();
        // Put it back together in ticks
        seconds * TICKS_PER_SECOND + nanos / NANOS_PER_TICK
    }
}
