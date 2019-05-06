use crate::tests::*;

use crate::builder::ServerBuilder;
use crate::state::{POLICY_ID_USER_PASS_NONE, POLICY_ID_USER_PASS_RSA_15, POLICY_ID_USER_PASS_RSA_OAEP};
use opcua_types::service_types::{ActivateSessionRequest, SignatureData, RequestHeader};
use opcua_core::crypto::user_identity::make_user_name_identity_token;
use opcua_core::crypto::SecurityPolicy;

fn dummy_activate_session_request() -> ActivateSessionRequest {
    ActivateSessionRequest {
        request_header: RequestHeader::dummy(),
        client_signature: SignatureData { algorithm: UAString::null(), signature: ByteString::null() },
        client_software_certificates: None,
        locale_ids: None,
        user_identity_token: ExtensionObject::null(),
        user_token_signature: SignatureData { algorithm: UAString::null(), signature: ByteString::null() },
    }
}

#[test]
fn anonymous_user_token() {
    let server = ServerBuilder::new_sample().server().unwrap();
    let server_state = server.server_state();
    let server_state = server_state.read().unwrap();

    // Makes an anonymous token and sticks it into an extension object
    let token = AnonymousIdentityToken {
        policy_id: UAString::from("anonymous")
    };
    let token = ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary, &token);

    let server_nonce = ByteString::random(20);

    let request = dummy_activate_session_request();

    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    trace!("result = {:?}", result);
    assert!(result.is_ok());

    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/x", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    trace!("result = {:?}", result);
    assert_eq!(result.unwrap_err(), StatusCode::BadTcpEndpointUrlInvalid);

    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/noaccess", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    trace!("result = {:?}", result);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);
}

fn make_encrypted_user_name_identity_token(policy_id: &str, security_policy: SecurityPolicy, server_nonce: &ByteString, server_cert: &Option<X509>, user: &str, pass: &str) -> ExtensionObject {
    let user_token_policy = opcua_types::service_types::UserTokenPolicy {
        policy_id: UAString::from(policy_id),
        token_type: UserTokenType::Username,
        issued_token_type: UAString::null(),
        issuer_endpoint_url: UAString::null(),
        security_policy_uri: UAString::null(),
    };
    let token = make_user_name_identity_token(security_policy, &user_token_policy, server_nonce.as_ref(), server_cert, user, pass).unwrap();
    ExtensionObject::from_encodable(ObjectId::UserNameIdentityToken_Encoding_DefaultBinary, &token)
}

fn make_unencrypted_user_name_identity_token(user: &str, pass: &str) -> ExtensionObject {
    let token = UserNameIdentityToken {
        policy_id: UAString::from(POLICY_ID_USER_PASS_NONE),
        user_name: UAString::from(user),
        password: ByteString::from(pass.as_bytes()),
        encryption_algorithm: UAString::null(),
    };
    ExtensionObject::from_encodable(ObjectId::UserNameIdentityToken_Encoding_DefaultBinary, &token)
}

#[test]
fn user_name_pass_token() {
    let server = ServerBuilder::new_sample().server().unwrap();
    let server_state = server.server_state();
    let server_state = server_state.read().unwrap();

    let server_nonce = ByteString::random(20);

    let request = dummy_activate_session_request();

    // Test that a good user authenticates in unencrypt and encrypted policies
    let token = make_unencrypted_user_name_identity_token("sample", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    assert!(result.is_ok());

    let server_cert = server_state.server_certificate.clone();
    let token = make_encrypted_user_name_identity_token(POLICY_ID_USER_PASS_RSA_15, SecurityPolicy::Basic128Rsa15, &server_nonce, &server_cert, "sample", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt, &token, &server_nonce);
    assert!(result.is_ok());

    let token = make_encrypted_user_name_identity_token(POLICY_ID_USER_PASS_RSA_OAEP, SecurityPolicy::Basic256, &server_nonce, &server_cert, "sample", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt, &token, &server_nonce);
    assert!(result.is_ok());

    let token = make_encrypted_user_name_identity_token(POLICY_ID_USER_PASS_RSA_OAEP, SecurityPolicy::Basic256Sha256, &server_nonce, &server_cert, "sample", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, &token, &server_nonce);
    assert!(result.is_ok());

    // Invalid tests

    // Invalid user
    let token = make_unencrypted_user_name_identity_token("samplex", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);

    // Invalid password
    let token = make_unencrypted_user_name_identity_token("sample", "sample");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);

    // Empty user
    let token = make_unencrypted_user_name_identity_token("", "sample");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token, &server_nonce);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);

    // Mismatch between security policy and encryption
    let token = make_encrypted_user_name_identity_token(POLICY_ID_USER_PASS_RSA_15, SecurityPolicy::Basic256Sha256, &server_nonce, &server_cert, "sample", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, &token, &server_nonce);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);

    // No encryption policy when encryption is required
    let token = make_encrypted_user_name_identity_token(POLICY_ID_USER_PASS_NONE, SecurityPolicy::Basic128Rsa15, &server_nonce, &server_cert, "sample", "sample1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, &token, &server_nonce);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);

    // Invalid password (encrypted)
    let token = make_encrypted_user_name_identity_token(POLICY_ID_USER_PASS_RSA_OAEP, SecurityPolicy::Basic128Rsa15, &server_nonce, &server_cert, "sample", "samplexx1");
    let result = server_state.authenticate_endpoint(&request, "opc.tcp://localhost:4855/", SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, &token, &server_nonce);
    assert_eq!(result.unwrap_err(), StatusCode::BadIdentityTokenRejected);
}
