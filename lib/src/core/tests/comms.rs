use crate::crypto::SecurityPolicy;
use crate::types::*;

use crate::core::comms::secure_channel::*;

#[test]
pub fn secure_channel_nonce_basic128rsa15() {
    let mut sc = SecureChannel::new_no_certificate_store();
    sc.set_security_mode(MessageSecurityMode::SignAndEncrypt);
    sc.set_security_policy(SecurityPolicy::Basic128Rsa15);
    // Nonce which is not 32 bytes long is an error
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::null())
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b""))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"1"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"012345678901234"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"01234567890123456"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(
            b"01234567890123456789012345678901".as_ref()
        ))
        .is_err());
    // Nonce which is 16 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"0123456789012345"))
        .is_ok());
}

#[test]
pub fn secure_channel_nonce_basic256() {
    let mut sc = SecureChannel::new_no_certificate_store();
    sc.set_security_mode(MessageSecurityMode::SignAndEncrypt);
    sc.set_security_policy(SecurityPolicy::Basic256);
    // Nonce which is not 32 bytes long is an error
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::null())
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b""))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"1"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"0123456789012345678901234567890"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(
            b"012345678901234567890123456789012".as_ref()
        ))
        .is_err());
    // Nonce which is 32 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"01234567890123456789012345678901"))
        .is_ok());
}

#[test]
pub fn secure_channel_nonce_none() {
    // When the security policy is none, you can set the nonce, but it doesn't care what length it is
    let mut sc = SecureChannel::new_no_certificate_store();
    sc.set_security_mode(MessageSecurityMode::None);
    sc.set_security_policy(SecurityPolicy::None);
    // Nonce which is 32 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"01234567890123456789012345678901"))
        .is_ok());
    // Nonce which is not 32 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"012"))
        .is_ok());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b""))
        .is_ok());
}
