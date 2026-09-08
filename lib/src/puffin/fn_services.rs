use std::vec;

use puffin::algebra::error::FnError;

use crate::crypto::{SecurityPolicy, X509, legacy_password_encrypt};
use crate::puffin::messages::ServiceMessage;
use crate::puffin::signature::fn_impl::{fn_basic256sha256, fn_oscar_cert, fn_oscar_endpoint, Certificate};
use crate::puffin::signature::{CipherSuite};
use crate::types::{ActivateSessionRequest, AnonymousIdentityToken, ApplicationDescription, ApplicationType, AttributeId, BinaryEncoder, ByteString, CloseSessionRequest, CreateSessionRequest, EndpointDescription, ExtensionObject, GetEndpointsResponse, Identifier, LocalizedText, MessageSecurityMode, NodeId, ObjectId, QualifiedName, ReadRequest, ReadValueId, RequestHeader, ResponseHeader, SignatureData, TimestampsToReturn, UAString, UserNameIdentityToken, UserTokenPolicy, UserTokenType, VariableId, X509IdentityToken};

pub fn fn_create_request (
    request_header: &RequestHeader,
    endpoint_url: &UAString,
    client_nonce: &ByteString,
    client_certificate: &Certificate
) -> Result<ServiceMessage, FnError> {
    let request = CreateSessionRequest {
        request_header: request_header.clone(),
        client_description: ApplicationDescription {
            application_uri: UAString::from("opc.tcp://localhost:4840/opcuapuffin.mallory"),
            product_uri: UAString::from("urn:Puffin"),
            application_name: LocalizedText::from("Puffin"),
            application_type: ApplicationType::Client,
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: None,
        },
        server_uri:  UAString::null(),
        endpoint_url: endpoint_url.clone(),
        session_name: UAString::null(),
        client_nonce: client_nonce.clone(),
        client_certificate: client_certificate.0.clone(),
        requested_session_timeout: 1200000.0,
        max_response_message_size: 0,
    };
    Ok(ServiceMessage::CreateSessionRequest(request))
}

pub fn fn_signature_data (
    certificate: &Certificate,
    nonce: &ByteString,
) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::with_capacity(certificate.byte_len() + nonce.byte_len());
    if let Some(cert) = certificate.0.clone().value {
        buffer.extend(cert);
    };
    if let Some(n) = nonce.clone().value {
        buffer.extend(n);
    };
    Ok(buffer)
}

// taken from client/session/services/session.rs

fn create_signature (
    security_policy: SecurityPolicy,
    signature: &Vec<u8>,
) -> SignatureData {
    if signature.len() == 0 || security_policy == SecurityPolicy::None {
        SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null()
        }
    } else {
        SignatureData {
            algorithm: UAString::from(security_policy.asymmetric_signature_algorithm()),
            signature: ByteString::from(&signature)
        }
    }
}

pub fn fn_activate_request(
    request_header: &RequestHeader,
    cipher_suite: &CipherSuite,
    client_signature: &Vec<u8>,
    user_identity_token: &ExtensionObject,
    user_token_signature: &Vec<u8>
) -> Result<ServiceMessage, FnError> {
    let security_policy = cipher_suite.security_policy();
    let request = ActivateSessionRequest {
        request_header: request_header.clone(),
        client_signature: create_signature(
            security_policy, client_signature),
        client_software_certificates: None,
        locale_ids: Some(vec![UAString::from("en-US")]),
        user_identity_token: user_identity_token.clone(),
        user_token_signature: create_signature(
            security_policy, user_token_signature)
    };
    Ok(ServiceMessage::ActivateSessionRequest(request))
}

pub fn fn_anonymous(
    policy_id: &UAString
) -> Result<ExtensionObject, FnError> {
    let identity_token = AnonymousIdentityToken {
        policy_id: policy_id.clone()
    };
    let identity_token = ExtensionObject::from_encodable(
        ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary,
        &identity_token,
    );
    Ok(identity_token)
}

// fn rsa_password_encrypt(
//     password: &str,
//     server_nonce: &[u8],
//     server_cert: &X509,
//     padding: RsaPadding
// ) -> Result<ByteString, FnError> {

//     // This should create the RsaEncryptedSecret structure in the ByteString
//     let buffer = Vec::<u8>::new();
//     Ok(ByteString::null())
// }

// pub fn fn_user_pwd(
//     policy_id: &UAString,
//     cipher_suite: &CipherSuite,
//     user_name: &UAString,
//     password: &UAString,
//     server_cert: &Certificate,
//     server_nonce: &ByteString,
// ) -> Result<ExtensionObject, FnError> {

//     // taken from crypto/user_identity.rs: make_user_name_identity_token
//     let security_policy: SecurityPolicy = cipher_suite.security_policy();
//     let pass: &str = if password.is_empty() {
//         return Err(FnError::Crypto("No password for user name authentication".to_string()))
//     } else {
//         password.as_ref()
//     };
//     let (encrypted_password, encryption_algorithm) = match security_policy {
//         // The fuzzer can send a password in clear even if it is forgotten in mode Sign!
//         SecurityPolicy::None => (ByteString::from(pass.as_bytes()), UAString::null()),
//         security_policy => {
//             // Create a password which is encrypted using the user token policy
//             if server_cert.is_null_or_empty() {
//                 (ByteString::from(pass.as_bytes()), UAString::null())
//             } else {
//                 let cert = X509::from_der(server_cert.as_ref())
//                    .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
//                 let encrypted_password = rsa_password_encrypt(
//                     pass,
//                     server_nonce.as_ref(),
//                     &cert,
//                     security_policy.asymmetric_encryption_padding(),
//                 ).map_err ( |e| {return FnError::Crypto(format!("Error in legacy password encrypt: {:?}", e))})?;
//                 let encryption_algorithm =
//                     UAString::from(security_policy.asymmetric_encryption_algorithm());
//                 (encrypted_password, encryption_algorithm)
//             }
//         }
//     };
//     let identity_token = UserNameIdentityToken {
//         policy_id: policy_id.clone(),
//         user_name: user_name.clone(),
//         password: encrypted_password,
//         encryption_algorithm,
//     };
//     let identity_token = ExtensionObject::from_encodable(
//         ObjectId::UserNameIdentityToken_Encoding_DefaultBinary,
//         &identity_token,
//     );
//     Ok(identity_token)
// }

pub fn fn_legacy_user_pwd(
    policy_id: &UAString,
    cipher_suite: &CipherSuite,
    user_name: &UAString,
    password: &UAString,
    server_cert: &Certificate,
    server_nonce: &ByteString,
) -> Result<ExtensionObject, FnError> {

    // taken from crypto/user_identity.rs: make_user_name_identity_token
    let security_policy: SecurityPolicy = cipher_suite.security_policy();
    let pass: &str = if password.is_empty() {
        return Err(FnError::Crypto("No password for user name authentication".to_string()))
    } else {
        password.as_ref()
    };
    let (encrypted_password, encryption_algorithm) = match security_policy {
        // The fuzzer can send a password in clear even if it is forgotten in mode Sign!
        SecurityPolicy::None => (ByteString::from(pass.as_bytes()), UAString::null()),
        security_policy => {
            // Create a password which is encrypted using the user token policy
            if server_cert.is_null_or_empty() {
                (ByteString::from(pass.as_bytes()), UAString::null())
            } else {
                let cert = X509::from_der(server_cert.as_ref())
                   .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
                let encrypted_password = legacy_password_encrypt(
                    pass,
                    server_nonce.as_ref(),
                    &cert,
                    security_policy.asymmetric_encryption_padding(),
                ).map_err ( |e| {return FnError::Crypto(format!("Error in legacy password encrypt: {:?}", e))})?;
                let encryption_algorithm =
                    UAString::from(security_policy.asymmetric_encryption_algorithm());
                (encrypted_password, encryption_algorithm)
            }
        }
    };
    let identity_token = UserNameIdentityToken {
        policy_id: policy_id.clone(),
        user_name: user_name.clone(),
        password: encrypted_password,
        encryption_algorithm,
    };
    let identity_token = ExtensionObject::from_encodable(
        ObjectId::UserNameIdentityToken_Encoding_DefaultBinary,
        &identity_token,
    );
    Ok(identity_token)
}

pub fn fn_user_cert(
    policy_id: &UAString,
    user_cert: &Certificate,
) -> Result<ExtensionObject, FnError> {
    let identity_token = X509IdentityToken {
        policy_id: policy_id.clone(),
        certificate_data: user_cert.0.clone(),
    };
    let identity_token = ExtensionObject::from_encodable(
        ObjectId::X509IdentityToken_Encoding_DefaultBinary,
        &identity_token,
    );
    Ok(identity_token)
}

pub fn fn_close_request(
    request_header: &RequestHeader
) -> Result<ServiceMessage, FnError> {
    let request = CloseSessionRequest {
        request_header: request_header.clone(),
        delete_subscriptions: true,
    };
    Ok(ServiceMessage::CloseSessionRequest(request))
}

// Request server's current time.
pub fn fn_read_current_time(
    request_header: &RequestHeader
) -> Result<ServiceMessage, FnError> {
    let id = ReadValueId {
        node_id: NodeId {
            namespace: 0,
            identifier: Identifier::from(VariableId::Server_ServerStatus_CurrentTime as u32)
        },
        attribute_id: AttributeId::Value as u32,
        index_range: UAString::null(),
        data_encoding: QualifiedName::null(),
    };
    let request = ReadRequest {
        request_header: request_header.clone(),
        max_age: 0.0,
        timestamps_to_return: TimestampsToReturn::Neither,
        nodes_to_read: Some(vec![id]),
    };
    Ok(ServiceMessage::ReadRequest(request))
}

pub fn fn_endpoints(
    response_header: &ResponseHeader
) -> Result<ServiceMessage, FnError> {
    let response = GetEndpointsResponse {
        response_header: response_header.clone(),
        endpoints: Some(vec![
            EndpointDescription {
                endpoint_url: fn_oscar_endpoint().unwrap(),
                server: ApplicationDescription {
                    application_uri: fn_oscar_endpoint().unwrap(),
                    product_uri: UAString::from("https://github.com/tlspuffin/tlspuffin.git"),
                    application_name: LocalizedText::from("OPC UA Puffin"),
                    application_type: ApplicationType::Server,
                    gateway_server_uri: UAString::null(),
                    discovery_profile_uri: UAString::null(),
                    discovery_urls: Some(vec![ fn_oscar_endpoint().unwrap() ]) },
                server_certificate: fn_oscar_cert().unwrap().0,
                security_mode: MessageSecurityMode::Sign,
                security_policy_uri: fn_basic256sha256().unwrap().security_policy().to_uri().into(),
                user_identity_tokens: Some(vec![
                    UserTokenPolicy{
                        policy_id: UAString::from("open62541-certificate-policy-sign#Basic256Sha256"),
                        token_type: UserTokenType::Certificate,
                        issued_token_type: UAString::null(),
                        issuer_endpoint_url: UAString::null(),
                        security_policy_uri: UAString::null() },
                ]),
                transport_profile_uri: UAString::from("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"),
                security_level: 20,
            } ])
    };
    Ok(ServiceMessage::GetEndpointsResponse(response))
}