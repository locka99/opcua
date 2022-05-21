// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! This simple OPC UA client will do the following:
//!
//! 1. Create a client configuration
//! 2. Connect to an endpoint specified by the url with security None
//! 3. Subscribe to values and loop forever printing out their values
use std::sync::Arc;

use opcua::client::prelude::*;
use opcua::sync::RwLock;

struct Args {
    help: bool,
    url: String,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            url: args
                .opt_value_from_str("--url")?
                .unwrap_or_else(|| String::from(DEFAULT_URL)),
        })
    }

    pub fn usage() {
        println!(
            r#"Simple Client
Usage:
  -h, --help   Show help
  --url [url]  Url to connect to (default: {})"#,
            DEFAULT_URL
        );
    }
}

const DEFAULT_URL: &str = "opc.tcp://localhost:4855";

fn main() -> Result<(), ()> {
    // Read command line arguments
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
    } else {
        // Optional - enable OPC UA logging
        opcua::console_logging::init();

        // Make the client configuration
        let mut client = ClientBuilder::new()
            .application_name("Simple Client")
            .application_uri("urn:SimpleClient")
            .product_uri("urn:SimpleClient")
            .trust_server_certs(true)
            .create_sample_keypair(true)
            .session_retry_limit(3)
            .client()
            .unwrap();

        if let Ok(session) = client.connect_to_endpoint(
            (
                args.url.as_ref(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
                UserTokenPolicy::anonymous(),
            ),
            IdentityToken::Anonymous,
        ) {
            if let Err(result) = subscribe_to_variables(session.clone(), 2) {
                println!(
                    "ERROR: Got an error while subscribing to variables - {}",
                    result
                );
            } else {
                // Loops forever. The publish thread will call the callback with changes on the variables
                let _ = Session::run(session);
            }
        }
    }
    Ok(())
}

fn subscribe_to_variables(session: Arc<RwLock<Session>>, ns: u16) -> Result<(), StatusCode> {
    let session = session.read();
    // Creates a subscription with a data change callback
    let subscription_id = session.create_subscription(
        2000.0,
        10,
        30,
        0,
        0,
        true,
        DataChangeCallback::new(|changed_monitored_items| {
            println!("Data change from server:");
            changed_monitored_items
                .iter()
                .for_each(|item| print_value(item));
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

    Ok(())
}

fn print_value(item: &MonitoredItem) {
    let node_id = &item.item_to_monitor().node_id;
    let data_value = item.last_value();
    if let Some(ref value) = data_value.value {
        println!("Item \"{}\", Value = {:?}", node_id, value);
    } else {
        println!(
            "Item \"{}\", Value not found, error: {}",
            node_id,
            data_value.status.as_ref().unwrap()
        );
    }
}
