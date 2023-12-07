use std::str::FromStr;

use crate::*;

#[test]
fn null() {
    assert_eq!(DateTime::null().checked_ticks(), 0i64);
}

#[test]
fn epoch() {
    let epoch = DateTime::ymd_hms_nano(1601, 1, 1, 0, 0, 0, 0);
    assert_eq!(epoch.ticks(), 0);
    assert_eq!(epoch.checked_ticks(), 0);

    let epoch = DateTime::epoch();
    assert_eq!(epoch.ticks(), 0);
    assert_eq!(epoch.checked_ticks(), 0);
}

#[test]
fn before_epoch() {
    let epoch = DateTime::ymd_hms_nano(1600, 12, 31, 23, 59, 59, 999_999);
    assert_eq!(epoch.checked_ticks(), 0);
}

#[test]
fn epoch_plus_1tick() {
    let epoch = DateTime::ymd_hms_nano(1601, 1, 1, 0, 0, 0, 100);
    assert_eq!(epoch.ticks(), 1);
}

#[test]
fn endtimes() {
    let endtimes = DateTime::ymd_hms_nano(9999, 12, 31, 23, 59, 59, 999_999);
    assert_eq!(endtimes.checked_ticks(), i64::max_value());

    let endtimes = DateTime::ymd_hms_nano(10000, 1, 1, 0, 0, 0, 0);
    assert_eq!(endtimes.checked_ticks(), i64::max_value());
}

#[test]
fn time() {
    use chrono::Datelike;
    let now = DateTime::now();
    let now = now.as_chrono();
    assert!(now.year() > 2000 && now.year() < 2050);
    assert!(now.month() >= 1 && now.month() <= 12);
}

#[test]
fn string() {
    let now = DateTime::now();
    let now_s = format!("{}", now);
    let now2 = DateTime::from_str(&now_s).unwrap();
    // Note: This parsing is potentially lossy so now != now2 and will be off by a small amount
    // so this code may have to change to compare an interval delta
    assert_eq!(now, now2);
}

#[test]
fn iso8601() {
    let min_date = "0001-01-01T00:00:00.000Z";
    let epoch = "1601-01-01T00:00:00.000Z";
    let max_date = "9999-12-31T23:59:59.000Z";

    // Json's min date is clipped to internal epoch
    let dt = DateTime::parse_from_rfc3339(min_date).unwrap();
    assert_eq!(epoch, dt.to_rfc3339());

    // A null date should match min date but there is a mismatch between JSON and the DateTime definition
    // which says DateTime is the number of 100 nanosecond intervals since January 1 1601. So
    // how can null be both 0001 and 1601 at the same time and what does it mean for dates before 1601 which
    // are negative.

    let dt = DateTime::null();
    assert_eq!(epoch, dt.to_rfc3339());

    // Max date
    let dt = DateTime::parse_from_rfc3339(max_date).unwrap();
    assert_eq!(max_date, dt.to_rfc3339());

    // Less than than min date
    let lt_min_date = "0000-12-31T23:59:59Z";
    let dt = DateTime::parse_from_rfc3339(lt_min_date).unwrap();
    assert_eq!(epoch, dt.to_rfc3339());
}
