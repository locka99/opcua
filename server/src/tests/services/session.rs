use opcua_types::{AnonymousIdentityToken, UserNameIdentityToken, UAString, ByteString, MessageSecurityMode, ExtensionObject, ObjectId};
use opcua_types::StatusCode::*;

use opcua_core;
use opcua_core::crypto::SecurityPolicy;

use config::*;
use server::Server;

#[test]
fn anonymous_user_token() {
    opcua_core::init_logging();

    let config = ServerConfig::new_sample();
    let server = Server::new(config);
    let server_state = server.server_state.read().unwrap();

    // Makes an anonymous token and sticks it into an extension object
    let token = AnonymousIdentityToken {
        policy_id: UAString::from(SecurityPolicy::None.to_uri())
    };
    let token = ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary, token);

    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token);
    trace!("result = {:?}", result);
    assert!(result.is_good());

    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/x", SecurityPolicy::None, MessageSecurityMode::None, &token);
    trace!("result = {:?}", result);
    assert_eq!(result, BadTcpEndpointUrlInvalid);

    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/noaccess", SecurityPolicy::None, MessageSecurityMode::None, &token);
    trace!("result = {:?}", result);
    assert_eq!(result, BadIdentityTokenRejected);
}

fn make_user_name_identity_token(user: &str, pass: &[u8]) -> ExtensionObject {
    let token = UserNameIdentityToken {
        policy_id: UAString::from(SecurityPolicy::None.to_uri()),
        user_name: UAString::from(user),
        password: ByteString::from(pass),
        encryption_algorithm: UAString::null()
    };
    ExtensionObject::from_encodable(ObjectId::UserNameIdentityToken_Encoding_DefaultBinary, token)
}

#[test]
fn user_name_pass_token() {
    opcua_core::init_logging();

    let config = ServerConfig::new_sample();
    let server = Server::new(config);
    let server_state = server.server_state.read().unwrap();

    // Test that a good user authenticates
    let token = make_user_name_identity_token("sample", b"sample1");
    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token);
    assert!(result.is_good());

    // Invalid tests
    let token = make_user_name_identity_token("samplex", b"sample1");
    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token);
    assert_eq!(result, BadIdentityTokenRejected);

    let token = make_user_name_identity_token("sample", b"sample");
    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token);
    assert_eq!(result, BadIdentityTokenRejected);

    let token = make_user_name_identity_token("", b"sample");
    let result = server_state.authenticate_endpoint("opc.tcp://localhost:4855/", SecurityPolicy::None, MessageSecurityMode::None, &token);
    assert_eq!(result, BadIdentityTokenRejected);
}
