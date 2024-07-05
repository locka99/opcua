use std::{sync::atomic::Ordering, time::Duration};

use log::debug;
use opcua::{
    client::IdentityToken,
    core::prelude::ErrorMessage,
    crypto::SecurityPolicy,
    types::{
        BinaryEncoder, DecodingOptions, MessageSecurityMode, NodeId, ReadValueId, StatusCode,
        TimestampsToReturn, VariableId,
    },
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use utils::hostname;

mod utils;

use crate::utils::{
    client_user_token, client_x509_token, default_server, Tester, CLIENT_USERPASS_ID, TEST_COUNTER,
};

#[tokio::test]
async fn hello_timeout() {
    opcua::console_logging::init();

    let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = default_server()
        .discovery_urls(vec![format!("opc.tcp://{}:{}", hostname(), port)])
        .pki_dir(format!("./pki-server/{test_id}"))
        .hello_timeout(1);
    let (server, _handle) = server.build().unwrap();
    let token = CancellationToken::new();
    let addr = listener.local_addr().unwrap();

    tokio::task::spawn(server.run_with(listener, token.clone()));

    let _guard = token.drop_guard();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    debug!("Connected to {addr}");

    let mut buf = [0u8; 1024];

    // Wait a bit more than the hello timeout (1 second)
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let result = stream.read(&mut buf).await;
    // Should first read the error message from the server.
    let read = result.unwrap();
    assert!(read > 0);
    let msg = ErrorMessage::decode(&mut buf.as_slice(), &DecodingOptions::default()).unwrap();
    assert_eq!(msg.error, StatusCode::BadTimeout.bits());

    let result = stream.read(&mut buf).await;

    match result {
        Ok(v) => {
            if v > 0 {
                panic!(
                    "Hello timeout exceeded and socket is still open, result = {}",
                    v
                )
            } else {
                // From
                debug!("Client got a read of 0 bytes on the socket, so treating by terminating with success");
            }
        }
        Err(err) => {
            debug!(
                "Client got an error {:?} on the socket terminating successfully",
                err
            );
        }
    }
    debug!("Test passed, closing server");
}

#[tokio::test]
async fn get_endpoints() {
    let tester = Tester::new_default_server(false).await;
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint())
        .await
        .unwrap();
    assert_eq!(endpoints.len(), tester.handle.info().config.endpoints.len());
}

async fn conn_test(policy: SecurityPolicy, mode: MessageSecurityMode, token: IdentityToken) {
    let mut tester = Tester::new_default_server(false).await;
    let (session, handle) = tester.connect(policy, mode, token).await.unwrap();
    let _h = handle.spawn();

    tokio::time::timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn connect_none() {
    conn_test(
        SecurityPolicy::None,
        MessageSecurityMode::None,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_sign() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic256_sign() {
    conn_test(
        SecurityPolicy::Basic256,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic256_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Basic256,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsaoaep_sign() {
    conn_test(
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsaoaep_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsapss_sign() {
    conn_test(
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsapss_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_with_username_password() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        client_user_token(),
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_with_x509_token() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        client_x509_token(),
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa_15_with_invalid_token() {
    let mut tester = Tester::new_default_server(true).await;
    let (_, handle) = tester
        .connect(
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::UserName(CLIENT_USERPASS_ID.to_owned(), "invalid".to_owned()),
        )
        .await
        .unwrap();
    let res = handle.spawn().await.unwrap();
    assert_eq!(res, StatusCode::BadUserAccessDenied);
}
