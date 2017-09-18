use prelude::*;

#[test]
fn user_name_identity_token_valid() {
    let mut id = UserNameIdentityToken {
        policy_id: UAString::null(),
        user_name: UAString::null(),
        password: ByteString::null(),
        encryption_algorithm: UAString::null(),
    };
    assert!(!id.is_valid());
    id.user_name = UAString::from("x");
    assert!(!id.is_valid());
    id.user_name = UAString::null();
    id.password = ByteString::from(b"xyz".as_ref());
    assert!(!id.is_valid());
    id.user_name = UAString::from("x");
    assert!(id.is_valid());
}

#[test]
fn user_name_identity_token_plaintext() {
    let mut id = UserNameIdentityToken {
        policy_id: UAString::null(),
        user_name: UAString::from("xyz"),
        password: ByteString::from(b"pwd1".as_ref()),
        encryption_algorithm: UAString::null(),
    };

    let result = id.authenticate("xyz", b"pwd1");
    assert!(result.is_ok());

    let result = id.authenticate("xyz", b"pwd2");
    assert!(result.is_err());

    let result = id.authenticate("xyz2", b"pwd1");
    assert!(result.is_err());

    id.password = ByteString::from(b"".as_ref());
    let result = id.authenticate("xyz", b"");
    assert!(result.is_ok());

    id.user_name = UAString::from("");
    let result = id.authenticate("", b"");
    assert!(result.is_ok());
}