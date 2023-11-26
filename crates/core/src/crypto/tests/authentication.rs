use crate::crypto::{
    self as crypto, decrypt_user_identity_token_password, make_user_name_identity_token, random,
    tests::*, SecurityPolicy,
};

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
    id.password = ByteString::from(b"xyz");
    assert!(!id.is_valid());
    id.user_name = UAString::from("x");
    assert!(id.is_valid());
}

#[test]
fn user_name_identity_token_plaintext() {
    let mut id = UserNameIdentityToken {
        policy_id: UAString::null(),
        user_name: UAString::from("xyz"),
        password: ByteString::from(b"pwd1"),
        encryption_algorithm: UAString::null(),
    };

    let result = id.authenticate("xyz", b"pwd1");
    assert!(result.is_ok());

    let result = id.authenticate("xyz", b"pwd2");
    assert!(result.is_err());

    let result = id.authenticate("xyz2", b"pwd1");
    assert!(result.is_err());

    id.password = ByteString::from(b"");
    let result = id.authenticate("xyz", b"");
    assert!(result.is_ok());

    id.user_name = UAString::from("");
    let result = id.authenticate("", b"");
    assert!(result.is_ok());
}

#[test]
fn user_name_identity_token_encrypted() {
    let password = String::from("abcdef123456");
    let nonce = random::byte_string(20);
    let (cert, pkey) = make_test_cert_1024();
    let cert = Some(cert);

    let mut user_token_policy = crate::types::service_types::UserTokenPolicy {
        policy_id: UAString::from("x"),
        token_type: UserTokenType::UserName,
        issued_token_type: UAString::null(),
        issuer_endpoint_url: UAString::null(),
        security_policy_uri: UAString::null(),
    };

    // These tests correspond to rows in OPC UA Part 4, table 179. Using various combinations
    // of secure channel security policy and user token security policy, we expect plaintext,
    // or the correct encryption to happen.

    // #1 This should be plaintext since channel security policy is none, token policy is empty
    let token = make_user_name_identity_token(
        SecurityPolicy::None,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert!(token.encryption_algorithm.is_null());
    assert_eq!(token.password.as_ref(), password.as_bytes());
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);

    // #2 This should be plaintext since channel security policy is none, token policy is none
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::None.to_uri());
    let token = make_user_name_identity_token(
        SecurityPolicy::None,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert!(token.encryption_algorithm.is_null());
    assert_eq!(token.password.as_ref(), password.as_bytes());
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);

    // #3 This should be Rsa15 since channel security policy is none, token policy is Rsa15
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::Basic128Rsa15.to_uri());
    let token = make_user_name_identity_token(
        SecurityPolicy::None,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_15
    );
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);

    // #4 This should be Rsa-15 since channel security policy is Rsa15, token policy is empty
    user_token_policy.security_policy_uri = UAString::null();
    let token = make_user_name_identity_token(
        SecurityPolicy::Basic128Rsa15,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_15
    );
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);

    // #5 This should be Rsa-OAEP since channel security policy is Rsa-15, token policy is Rsa-OAEP
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::Basic256Sha256.to_uri());
    let token = make_user_name_identity_token(
        SecurityPolicy::Basic128Rsa15,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_OAEP
    );
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);

    // #6 This should be Rsa-OAEP since channel security policy is Rsa-OAEP,  token policy is Rsa-OAEP
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::Basic256Sha256.to_uri());
    let token = make_user_name_identity_token(
        SecurityPolicy::Basic256Sha256,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_OAEP
    );
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);

    // #7 This should be None since channel security policy is Rsa-15, token policy is None
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::None.to_uri());
    let token = make_user_name_identity_token(
        SecurityPolicy::Basic128Rsa15,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        "user1",
        &password,
    )
    .unwrap();
    assert!(token.encryption_algorithm.is_empty());
    let password1 = decrypt_user_identity_token_password(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(password, password1);
}
