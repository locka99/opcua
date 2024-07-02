use std::{sync::atomic::Ordering, time::Duration};

use log::debug;
use opcua::{
    core::prelude::ErrorMessage,
    types::{BinaryEncoder, DecodingOptions, StatusCode},
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

use crate::utils::{default_server, TEST_COUNTER};

#[tokio::test]
async fn hello_timeout() {
    opcua::console_logging::init();

    let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = default_server(port, test_id).hello_timeout(1);
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
