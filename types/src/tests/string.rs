use crate::string::UAString;

#[test]
fn null_string() {
    let s = UAString::null();
    assert!(s.is_null());
    assert!(s.is_empty());
    assert_eq!(s.len(), -1);
}

#[test]
fn empty_string() {
    let s = UAString::from("");
    assert!(!s.is_null());
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}
