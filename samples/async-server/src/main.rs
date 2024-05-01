use std::{path::PathBuf, sync::Arc};

use log::info;
use opcua::{
    async_server::{
        node_manager::{
            memory::{CoreNodeManager, InMemoryNodeManager},
            NodeManager,
        },
        ServerConfig, ServerCore,
    },
    client::{Client, ClientConfig},
    core::config::Config,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    opcua::console_logging::init();
    let node_managers = vec![Arc::new(InMemoryNodeManager::new(CoreNodeManager::new()))
        as Arc<dyn NodeManager + Send + Sync + 'static>];

    let server = ServerCore::new(
        ServerConfig::load(&PathBuf::from("../server.conf")).unwrap(),
        node_managers,
    )
    .unwrap();

    let handle = tokio::task::spawn(server.run(CancellationToken::new()));

    let mut client = Client::new(ClientConfig::load(&PathBuf::from("../client.conf")).unwrap());

    let (session, event_loop) = client
        .new_session_from_endpoint(
            "opc.tcp://127.0.0.1:4855",
            opcua::client::IdentityToken::Anonymous,
        )
        .await
        .unwrap();

    let client_handle = tokio::task::spawn(event_loop.run());

    session.wait_for_connection().await;

    info!("Connected to server, yay!");

    session.disconnect().await.unwrap();
    client_handle.await.unwrap();

    info!("Closed session");
    handle.await.unwrap().unwrap();
}
