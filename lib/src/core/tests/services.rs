use crate::core::tests::*;

fn request_header() -> RequestHeader {
    RequestHeader {
        authentication_token: NodeId::null(),
        timestamp: DateTime::now(),
        request_handle: 77,
        return_diagnostics: DiagnosticBits::empty(),
        audit_entry_id: UAString::from("audit entry"),
        timeout_hint: 23456,
        additional_header: ExtensionObject::null(),
    }
}

#[test]
fn get_endpoints_request() {
    let r = GetEndpointsRequest {
        request_header: request_header(),
        endpoint_url: UAString::from("opc.tcp://localhost/my_path"),
        locale_ids: Some(vec![UAString::from("en-EN")]),
        profile_uris: Some(vec![UAString::from("xyz")]),
    };
    serialize_test(r);
}
