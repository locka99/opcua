// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This is a sample OPC UA Client that connects to the specified server, fetches some
//! values before exiting.
use std::{path::PathBuf, sync::Arc, time::Duration};

use rumqttc::{AsyncClient as MqttClient, MqttOptions, QoS};

use opcua::{
    client::{Client, ClientConfig, DataChangeCallback, Session},
    core::config::Config,
    sync::Mutex,
    types::{DataValue, MonitoredItemCreateRequest, NodeId, StatusCode, TimestampsToReturn},
};
use tokio::{select, sync::mpsc};

struct Args {
    help: bool,
    config: String,
    endpoint_id: String,
    host: String,
    port: u16,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            config: args
                .opt_value_from_str("--config")?
                .unwrap_or_else(|| String::from(DEFAULT_CONFIG_FILE)),
            endpoint_id: args
                .opt_value_from_str("--config")?
                .unwrap_or_else(|| String::from("")),
            host: args
                .opt_value_from_str("--host")?
                .unwrap_or_else(|| String::from(DEFAULT_MQTT_HOST)),
            port: args
                .opt_value_from_str("--port")?
                .unwrap_or(DEFAULT_MQTT_PORT),
        })
    }

    pub fn usage() {
        println!(
            r#"MQTT client
Usage:
  -h, --help        Show help
  --config file     Sets the configuration file to read settings and endpoints from (default: {})
  --endpoint-id id  Sets the endpoint id from the config file to connect to
  --host host       Address or name of the MQTT server to connect with (default: {})
  --port port       Port number of MQTT server to connect with (default: {})"#,
            DEFAULT_CONFIG_FILE, DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT
        );
    }
}

const DEFAULT_CONFIG_FILE: &str = "samples/client.conf";
const DEFAULT_MQTT_HOST: &str = "broker.hivemq.com";
const DEFAULT_MQTT_PORT: u16 = 1883;

// This client will do the following:
//
// 1. Read a configuration file (either default or the one specified using --config)
// 2. Connect & create a session on one of those endpoints that match with its config (you can override which using --endpoint-id arg)
// 3. Subscribe to values and loop forever printing out their values (using --subscribe)
// 4. Publish those values to an MQTT broker (default broker.hivemq.com:1883)
// 5. User can observe result on the broker (e.g. http://www.mqtt-dashboard.com/)

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
        return Ok(());
    }
    let mqtt_host = args.host;
    let mqtt_port = args.port;
    let config_file = args.config;
    let endpoint_id = args.endpoint_id;

    // Optional - enable OPC UA logging
    opcua::console_logging::init();

    // The way this will work is the mqtt connection will live in its own thread, listening for
    // events that are sent to it.
    let (tx, mut rx) = mpsc::unbounded_channel::<(NodeId, DataValue)>();
    let _mqtt_handle = tokio::task::spawn(async move {
        let mut mqtt_options = MqttOptions::new("test-id", mqtt_host, mqtt_port);
        mqtt_options.set_keep_alive(Duration::from_secs(5));
        let (mqtt_client, mut event_loop) = MqttClient::new(mqtt_options, 10);

        select! {
            _ = event_loop.poll() => {},
            r = rx.recv() => {
                let Some((node_id, data_value)) = r else {
                    return;
                };
                let topic = format!(
                    "opcua-rust/mqtt-client/{}/{}",
                    node_id.namespace, node_id.identifier
                );
                let value = if let Some(ref value) = data_value.value {
                    format!("{:?}", value)
                } else {
                    "null".to_string()
                };
                println!("Publishing {} = {}", topic, value);

                let value = value.into_bytes();
                let _ = mqtt_client.publish(topic, QoS::AtLeastOnce, false, value).await;
            }
        }
    });

    // Use the sample client config to set up a client. The sample config has a number of named
    // endpoints one of which is marked as the default.
    let mut client = Client::new(ClientConfig::load(&PathBuf::from(config_file)).unwrap());
    let endpoint_id: Option<&str> = if !endpoint_id.is_empty() {
        Some(&endpoint_id)
    } else {
        None
    };
    let ns = 2;
    let (session, event_loop) = client.connect_to_endpoint_id(endpoint_id).await.unwrap();
    let handle = event_loop.spawn();

    session.wait_for_connection().await;

    subscribe_to_events(session, tx, ns).await.map_err(|err| {
        println!("ERROR: Got an error while performing action - {}", err);
    })?;

    handle.await.unwrap();
    Ok(())
}

async fn subscribe_to_events(
    session: Arc<Session>,
    tx: mpsc::UnboundedSender<(NodeId, DataValue)>,
    ns: u16,
) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // Creates our subscription - one update every second. The update is sent as a message
    // to the MQTT thread to be published.
    let tx = Arc::new(Mutex::new(tx));
    let subscription_id = session
        .create_subscription(
            Duration::from_secs(1),
            10,
            30,
            0,
            0,
            true,
            DataChangeCallback::new(move |dv, item| {
                println!("Data change from server:");
                let tx = tx.lock();
                let _ = tx.send((item.item_to_monitor().node_id.clone(), dv));
            }),
        )
        .await?;
    println!("Created a subscription with id = {}", subscription_id);

    // Create some monitored items
    let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"]
        .iter()
        .map(|v| NodeId::new(ns, *v).into())
        .collect();
    let _ = session
        .create_monitored_items(subscription_id, TimestampsToReturn::Both, items_to_create)
        .await?;

    Ok(())
}
