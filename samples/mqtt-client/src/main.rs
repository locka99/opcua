//! This is a sample OPC UA Client that connects to the specified server, fetches some
//! values before exiting.
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, RwLock, mpsc},
    thread,
};

use rumqtt::{MqttClient, MqttOptions, QoS};
use clap::{App, Arg, value_t_or_exit};

use opcua_client::prelude::*;

// This client will do the following:
//
// 1. Read a configuration file (either default or the one specified using --config)
// 2. Connect & create a session on one of those endpoints that match with its config (you can override which using --endpoint-id arg)
// 3. Subscribe to values and loop forever printing out their values (using --subscribe)
// 4. Publish those values to an MQTT broker (default broker.hivemq.com:1883)
// 5. User can observe result on the broker (e.g. http://www.mqtt-dashboard.com/)

fn main() {
    // Read command line arguments
    let m = App::new("Simple OPC UA Client")
        .arg(Arg::with_name("config")
            .long("config")
            .help("Sets the configuration file to read settings and endpoints from")
            .takes_value(true)
            .default_value("../client.conf")
            .required(false))
        .arg(Arg::with_name("id")
            .long("endpoint-id")
            .help("Sets the endpoint id from the config file to connect to")
            .takes_value(true)
            .default_value("")
            .required(false))
        .arg(Arg::with_name("host")
            .long("host")
            .help("Address or name of the MQTT server to connect with")
            .default_value("broker.hivemq.com")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("port")
            .long("port")
            .help("Port number of MQTT server to connect with")
            .default_value("1883")
            .takes_value(true)
            .required(true))
        .get_matches();

    let mqtt_host = m.value_of("host").unwrap().to_string();
    let mqtt_port = value_t_or_exit!(m, "port", u16);
    let config_file = m.value_of("config").unwrap().to_string();
    let endpoint_id = m.value_of("id").unwrap().to_string();

    // Optional - enable OPC UA logging
    opcua_console_logging::init();

    // The way this will work is the mqtt connection will live in its own thread, listening for
    // events that are sent to it.
    let (tx, rx) = mpsc::channel::<(NodeId, DataValue)>();
    let _ = thread::spawn(move || {
        let mqtt_options = MqttOptions::new("test-id", mqtt_host, mqtt_port).set_keep_alive(10);
        let (mut mqtt_client, _) = MqttClient::start(mqtt_options).unwrap();

        loop {
            let (node_id, data_value) = rx.recv().unwrap();
            let topic = format!("opcua-rust/mqtt-client/{}/{}", node_id.namespace, node_id.identifier);
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
    let endpoint_id: Option<&str> = if !endpoint_id.is_empty() { Some(&endpoint_id) } else { None };
    if let Ok(session) = client.connect_to_endpoint_id(endpoint_id) {
        let _ = subscription_loop(session, tx).map_err(|err| {
            println!("ERROR: Got an error while performing action - {}", err);
        });
    }
}

fn subscription_loop(session: Arc<RwLock<Session>>, tx: mpsc::Sender<(NodeId, DataValue)>) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription - one update every second. The update is sent as a message
        // to the MQTT thread to be published.
        let tx = Arc::new(Mutex::new(tx));
        let subscription_id = session.create_subscription(1000f64, 10, 30, 0, 0, true, DataChangeCallback::new(move |items| {
            println!("Data change from server:");
            let tx = tx.lock().unwrap();
            items.iter().for_each(|item| {
                let node_id = item.item_to_monitor().node_id.clone();
                let value = item.value().clone();
                let _ = tx.send((node_id, value));
            });
        }))?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
            .map(|v| NodeId::new(2, *v).into()).collect();
        let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create)?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    let _ = Session::run(session);

    Ok(())
}
