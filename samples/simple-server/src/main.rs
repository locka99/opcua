// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This is a simple server for OPC UA. Our sample creates a server with the default settings
//! adds some variables to the address space and the listeners for connections. It also has
//! a timer that updates those variables so anything monitoring variables sees the values changing.
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use opcua::server::address_space::Variable;
use opcua::server::node_manager::memory::{
    InMemoryNodeManager, NamespaceMetadata, SimpleNodeManager, SimpleNodeManagerImpl,
};
use opcua::server::{ServerBuilder, SubscriptionCache};
use opcua::types::{DataValue, NodeId, UAString};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    // This enables logging via env_logger & log crate macros. If you don't need logging or want
    // to implement your own, omit this line.
    opcua::console_logging::init();

    // Create an OPC UA server with sample configuration and default node set

    let ns = 2;
    let node_manager = Arc::new(SimpleNodeManager::new_simple(
        NamespaceMetadata {
            namespace_index: ns,
            namespace_uri: "urn:SimpleServer".to_owned(),
            ..Default::default()
        },
        "simple",
    ));

    let (server, handle) = ServerBuilder::new()
        .with_config_from("../server.conf")
        .with_node_manager(node_manager.clone())
        .build()
        .unwrap();

    // Add some variables of our own
    add_example_variables(ns, node_manager, handle.subscriptions().clone());

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run(CancellationToken::new()).await.unwrap();
}

/// Creates some sample variables, and some push / pull examples that update them
fn add_example_variables(
    ns: u16,
    manager: Arc<InMemoryNodeManager<SimpleNodeManagerImpl>>,
    subscriptions: Arc<SubscriptionCache>,
) {
    // These will be the node ids of the new variables
    let v1_node = NodeId::new(ns, "v1");
    let v2_node = NodeId::new(ns, "v2");
    let v3_node = NodeId::new(ns, "v3");
    let v4_node = NodeId::new(ns, "v4");

    let address_space = manager.address_space();

    // The address space is guarded so obtain a lock to change it
    {
        let mut address_space = address_space.write();

        // Create a sample folder under objects folder
        let sample_folder_id = NodeId::new(ns, "folder");
        address_space.add_folder(
            &sample_folder_id,
            "Sample",
            "Sample",
            &NodeId::objects_folder_id(),
        );

        // Add some variables to our sample folder. Values will be overwritten by the timer
        let _ = address_space.add_variables(
            vec![
                Variable::new(&v1_node, "v1", "v1", 0 as i32),
                Variable::new(&v2_node, "v2", "v2", false),
                Variable::new(&v3_node, "v3", "v3", UAString::from("")),
                Variable::new(&v4_node, "v4", "v4", 0f64),
            ],
            &sample_folder_id,
        );
    }

    // Depending on your choice of node manager, you can use different methods to provide the value of a node.
    // The simple node manager lets you set dynamic getters:
    {
        let counter = AtomicI32::new(0);
        manager
            .inner()
            .add_read_callback(v3_node.clone(), move |_, _, _| {
                Ok(DataValue::new_now(UAString::from(format!(
                    "Hello World times {}",
                    counter.fetch_add(1, Ordering::Relaxed)
                ))))
            });

        let start_time = Instant::now();
        manager
            .inner()
            .add_read_callback(v4_node.clone(), move |_, _, _| {
                let elapsed = (Instant::now() - start_time).as_millis();
                let moment = (elapsed % 10_000) as f64 / 10_000.0;
                Ok(DataValue::new_now(
                    (2.0 * std::f64::consts::PI * moment).sin(),
                ))
            });
    }

    // Alternatively, you can set the value in the node manager on a timer.
    // This is typically a better choice if updates are relatively rare, and you always know when
    // an update occurs. Fundamentally, the server is event-driven. When using a getter like above,
    // the node manager will sample the value if a user subscribes to it. When publishing a value like below,
    // clients will only be notified when a change actually happens, but we will need to store each new value.

    // Typically, you will use a getter or a custom node manager for dynamic values, and direct modification for
    // properties or other less-commonly changing values.
    {
        // Store a counter and a flag in a tuple
        let counter = AtomicI32::new(0);
        let flag = AtomicBool::new(false);
        tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(300));
            loop {
                interval.tick().await;

                manager
                    .set_values(
                        &subscriptions,
                        [
                            (
                                &v1_node,
                                None,
                                DataValue::new_now(counter.fetch_add(1, Ordering::Relaxed)),
                            ),
                            (
                                &v2_node,
                                None,
                                DataValue::new_now(flag.fetch_xor(true, Ordering::Relaxed)),
                            ),
                        ]
                        .into_iter(),
                    )
                    .unwrap();
            }
        });
    }
}
