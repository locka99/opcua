// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! This is a sample OPC UA Client that connects to the specified server, fetches some
//! values before exiting.
use std::{
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
};

use rumqtt::{MqttClient, MqttOptions, QoS};

use opcua::client::prelude::*;
use opcua::sync::{Mutex, RwLock};

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

const DEFAULT_CONFIG_FILE: &str = "../client.conf/";
const DEFAULT_MQTT_HOST: &str = "broker.hivemq.com";
const DEFAULT_MQTT_PORT: u16 = 1883;

// This client will do the following:
//
// 1. Read a configuration file (either default or the one specified using --config)
// 2. Connect & create a session on one of those endpoints that match with its config (you can override which using --endpoint-id arg)
// 3. Subscribe to values and loop forever printing out their values (using --subscribe)
// 4. Publish those values to an MQTT broker (default broker.hivemq.com:1883)
// 5. User can observe result on the broker (e.g. http://www.mqtt-dashboard.com/)

fn main() -> Result<(), ()> {
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
    } else {
        let mqtt_host = args.host;
        let mqtt_port = args.port;
        let config_file = args.config;
        let endpoint_id = args.endpoint_id;

        // Optional - enable OPC UA logging
        opcua::console_logging::init();

        // The way this will work is the mqtt connection will live in its own thread, listening for
        // events that are sent to it.
        let (tx, rx) = mpsc::channel::<(NodeId, DataValue)>();
        let _ = thread::spawn(move || {
            let mqtt_options = MqttOptions::new("test-id", mqtt_host, mqtt_port).set_keep_alive(10);
            let (mut mqtt_client, _) = MqttClient::start(mqtt_options).unwrap();

            loop {
                let (node_id, data_value) = rx.recv().unwrap();
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
                mqtt_client.publish(topic, QoS::AtLeastOnce, value).unwrap();
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
        if let Ok(session) = client.connect_to_endpoint_id(endpoint_id) {
            let _ = subscription_loop(session, tx, ns).map_err(|err| {
                println!("ERROR: Got an error while performing action - {}", err);
            });
        }
    }
    Ok(())
}

fn subscription_loop(
    session: Arc<RwLock<Session>>,
    tx: mpsc::Sender<(NodeId, DataValue)>,
    ns: u16,
) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let session = session.read();

        // Creates our subscription - one update every second. The update is sent as a message
        // to the MQTT thread to be published.
        let tx = Arc::new(Mutex::new(tx));
        let subscription_id = session.create_subscription(
            1000f64,
            10,
            30,
            0,
            0,
            true,
            DataChangeCallback::new(move |items| {
                println!("Data change from server:");
                let tx = tx.lock();
                items.iter().for_each(|item| {
                    let node_id = item.item_to_monitor().node_id.clone();
                    let value = item.last_value().clone();
                    let _ = tx.send((node_id, value));
                });
            }),
        )?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"]
            .iter()
            .map(|v| NodeId::new(ns, *v).into())
            .collect();
        let _ = session.create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            &items_to_create,
        )?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    let _ = Session::run(session);

    Ok(())
}
