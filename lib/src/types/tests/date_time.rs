use std::str::FromStr;

use crate::types::*;

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
