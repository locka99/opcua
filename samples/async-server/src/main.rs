use std::{path::PathBuf, sync::Arc, time::Duration};

use log::info;
use opcua::{
    async_server::{
        node_manager::{
            memory::{CoreNodeManager, InMemoryNodeManager},
            NodeManager,
        },
        ServerConfig, ServerCore, SubscriptionCache,
    },
    client::{Client, ClientConfig},
    core::config::Config,
    types::{AttributeId, NodeId, VariableId, Variant},
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    opcua::console_logging::init();
    let core_node_manager = Arc::new(InMemoryNodeManager::new(CoreNodeManager::new()));
    let node_managers =
        vec![core_node_manager.clone() as Arc<dyn NodeManager + Send + Sync + 'static>];

    let server = ServerCore::new(
        ServerConfig::load(&PathBuf::from("../server.conf")).unwrap(),
        node_managers,
    )
    .unwrap();

    let subscriptions = server.subscriptions();

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
    tokio::select! {
        r = handle => { r.unwrap() },
        _ = gen_values(core_node_manager, subscriptions) => { unreachable!() }
    }
    .unwrap();
}

async fn gen_values(
    node_manager: Arc<InMemoryNodeManager<CoreNodeManager>>,
    subscriptions: Arc<SubscriptionCache>,
) {
    let id: NodeId = VariableId::Server_ServiceLevel.into();

    let mut counter = 0u8;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        node_manager
            .modify_value(
                &subscriptions,
                &id,
                AttributeId::Value,
                Variant::Byte(counter),
            )
            .unwrap();
        counter = counter.wrapping_add(1);
    }
}
