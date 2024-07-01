use std::{path::PathBuf, sync::Arc, time::Duration};

use log::info;
use opcua::{
    async_server::{
        node_manager::{
            memory::{CoreNodeManagerImpl, DiagnosticsNodeManager, InMemoryNodeManager},
            NodeManager,
        },
        ServerConfig, ServerCore, ServerHandle,
    },
    client::{Client, ClientConfig},
    core::config::Config,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    opcua::console_logging::init();
    let core_node_manager = Arc::new(InMemoryNodeManager::new(CoreNodeManagerImpl::new()));
    let diagnostics_node_manager = Arc::new(DiagnosticsNodeManager::new());
    let node_managers = vec![
        core_node_manager.clone() as Arc<dyn NodeManager + Send + Sync + 'static>,
        diagnostics_node_manager.clone(),
    ];

    let (server, handle) = ServerCore::new(
        ServerConfig::load(&PathBuf::from("../server.conf")).unwrap(),
        node_managers,
    )
    .unwrap();

    let token = CancellationToken::new();
    let token_clone = token.clone();
    ctrlc::set_handler(move || token.cancel()).unwrap();

    let join_handle = tokio::task::spawn(server.run(token_clone));

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
    tokio::select! {
        r = join_handle => { r.unwrap() },
        _ = gen_values(&handle) => { unreachable!() }
    }
    .unwrap();
}

async fn gen_values(handle: &ServerHandle) {
    let mut counter = 0u8;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        handle.set_service_level(counter);
        counter = counter.wrapping_add(1);
    }
}
