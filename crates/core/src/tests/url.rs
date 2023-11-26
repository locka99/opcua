use crate::types::url::*;

#[test]
fn endpoint_match() {
    assert!(url_matches_except_host(
        "opc.tcp://foo:4855/",
        "opc.tcp://bar:4855"
    ));
    assert!(url_matches_except_host(
        "opc.tcp://127.0.0.1:4855/",
        "opc.tcp://bar:4855"
    ));
    assert!(url_matches_except_host(
        "opc.tcp://foo:4855/",
        "opc.tcp://127.0.0.1:4855"
    ));
    assert!(url_matches_except_host(
        "opc.tcp://foo:4855/UAServer",
        "opc.tcp://127.0.0.1:4855/UAServer"
    ));
    assert!(!url_matches_except_host(
        "opc.tcp://foo:4855/UAServer",
        "opc.tcp://127.0.0.1:8888/UAServer"
    ));
}
