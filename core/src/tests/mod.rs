use std::fmt::Debug;
use std::cmp::PartialEq;
use std::io::Cursor;

use tempdir::TempDir;

use opcua_types::*;

use crypto::pkey::PKey;
use crypto::x509::{X509, X509Data};
use crypto::certificate_store::*;

pub fn serialize_test_and_return<T>(value: T) -> T
    where T: BinaryEncoder<T> + Debug + PartialEq
{
    // Ask the struct for its byte length
    let byte_len = value.byte_len();
    let mut stream = Cursor::new(vec![0u8; byte_len]);

    // Encode to stream
    let start_pos = stream.position();
    let result = value.encode(&mut stream);
    let end_pos = stream.position();
    assert!(result.is_ok());

    // This ensures the size reported is the same as the byte length impl
    assert_eq!(result.unwrap(), byte_len);

    // Test that the position matches the byte_len
    assert_eq!((end_pos - start_pos) as usize, byte_len);

    let actual = stream.into_inner();
    println!("value = {:?}", value);
    println!("encoded bytes = {:?}", actual);
    let mut stream = Cursor::new(actual);

    let new_value: T = T::decode(&mut stream).unwrap();
    println!("new value = {:?}", new_value);
    assert_eq!(value, new_value);
    new_value
}

pub fn serialize_test<T>(value: T)
    where T: BinaryEncoder<T> + Debug + PartialEq
{
    let _ = serialize_test_and_return(value);
}


fn make_certificate_store() -> (TempDir, CertificateStore) {
    let tmp_dir = TempDir::new("pki").unwrap();
    let cert_store = CertificateStore::new(&tmp_dir.path());
    assert!(cert_store.ensure_pki_path().is_ok());
    (tmp_dir, cert_store)
}

fn make_test_cert() -> (X509, PKey) {
    let args = X509Data {
        key_size: 2048,
        common_name: "x".to_string(),
        organization: "x.org".to_string(),
        organizational_unit: "x.org ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec!["host1".to_string(), "host2".to_string()],
        certificate_duration_days: 60,
    };
    let cert = CertificateStore::create_cert_and_pkey(&args);
    cert.unwrap()
}

fn make_open_secure_channel_response() -> OpenSecureChannelResponse {
    OpenSecureChannelResponse {
        response_header: ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 444,
            service_result: BAD_PROTOCOL_VERSION_UNSUPPORTED,
            service_diagnostics: DiagnosticInfo::new(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        },
        server_protocol_version: 0,
        security_token: ChannelSecurityToken {
            channel_id: 1,
            token_id: 2,
            created_at: DateTime::now(),
            revised_lifetime: 777,
        },
        server_nonce: ByteString::null(),
    }
}

fn make_sample_message() -> SupportedMessage {
    SupportedMessage::GetEndpointsRequest(GetEndpointsRequest {
        request_header: RequestHeader {
            authentication_token: NodeId::new(0, 99),
            timestamp: DateTime::now(),
            request_handle: 1,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: 123456,
            additional_header: ExtensionObject::null(),
        },
        endpoint_url: UAString::null(),
        locale_ids: None,
        profile_uris: None,
    })
}

struct Test;

impl Test {
    pub fn setup() -> Test {
        ::init_logging();
        Test {}
    }
}

mod chunk;
mod services;
mod comms;
mod authentication;
mod crypto;
mod secure_channel;