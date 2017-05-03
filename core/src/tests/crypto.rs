use crypto;

#[test]
#[cfg(not(feature = "crypto"))]
fn no_crypto() {
    assert!(!crypto::is_crypto_enabled());
}

#[test]
#[cfg(feature = "crypto")]
fn have_crypto() {
    assert!(crypto::is_crypto_enabled());
}
