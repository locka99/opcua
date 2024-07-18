// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This is a demo server for OPC UA. It demonstrates most of the features of OPC UA for Rust.
//!
//! * Variables for each type
//! * Variables with arrays of types
//! * Stress variables that change rapidly
//! * Method
//! * Events
//! * Http server with metrics (http://localhost:8585)
//!
//! If you want a simpler`simple-server`
//!
//! Use simple-server to understand a terse and simple example.
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

use std::{path::PathBuf, sync::Arc};

use tokio;

use opcua::server::{
    node_manager::memory::{NamespaceMetadata, SimpleNodeManager},
    ServerBuilder,
};

mod control;
mod machine;
mod methods;
mod scalar;

struct Args {
    help: bool,
    raise_events: bool,
    config_path: PathBuf,
    content_path: PathBuf,
}

impl Default for Args {
    fn default() -> Self {
        let mut raise_events = false;

        let mut config_path = PathBuf::from("../server.test.conf");
        if !config_path.exists() {
            raise_events = true;
            config_path = PathBuf::from("server.conf");
            if !config_path.exists() {
                config_path = PathBuf::from("../server.conf");
            }
        }

        let content_path = if PathBuf::from("./index.html").exists() {
            // For docker image or custom deployment
            PathBuf::from(".")
        } else {
            // Server src dir
            PathBuf::from("../../lib/src/server/html")
        };

        Self {
            help: false,
            raise_events,
            config_path,
            content_path,
        }
    }
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();

        let default = Args::default();
        let config_path: PathBuf = args
            .value_from_str(["-c", "--config"])
            .unwrap_or(default.config_path.clone());
        let raise_events = if args.contains(["-r", "--raise-events"]) {
            true
        } else {
            (config_path == default.config_path) && default.raise_events
        };
        let content_path = default.content_path;

        Ok(Args {
            help: args.contains(["-h", "--help"]),
            raise_events,
            config_path,
            content_path,
        })
    }

    pub fn usage() {
        let args = Args::default();
        println!(
            r#"Demo Server
Usage:
  -h, --help                 Show help
  -r, --raise-events         Raise events on a timer (default: {:?})"
  -c, --config [config-file] Path to a configuration file (default: {})"#,
            args.raise_events,
            args.config_path.to_str().as_ref().unwrap()
        );
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse_args().unwrap();
    if args.help {
        Args::usage();
    } else {
        // More powerful logging than a console logger
        log4rs::init_file("log4rs.yaml", Default::default()).unwrap();
        let ns = 2;

        let node_manager = Arc::new(SimpleNodeManager::new_simple(
            NamespaceMetadata {
                namespace_index: ns,
                namespace_uri: "urn:DemoServer".to_owned(),
                ..Default::default()
            },
            "demo",
        ));

        // Create an OPC UA server with sample configuration and default node set
        let (server, handle) = ServerBuilder::new()
            .with_config_from(&args.config_path)
            .with_node_manager(node_manager.clone())
            .build()
            .unwrap();

        let token = handle.token();

        // Add some objects representing machinery
        machine::add_machinery(
            ns,
            node_manager.clone(),
            handle.subscriptions().clone(),
            args.raise_events,
            token.clone(),
        );

        // Add some scalar variables
        scalar::add_scalar_variables(node_manager.clone(), handle.subscriptions().clone(), ns);

        // Add some rapidly changing values
        scalar::add_stress_variables(node_manager.clone(), handle.subscriptions().clone(), ns);

        // Add some control switches, e.g. abort flag
        control::add_control_switches(
            ns,
            node_manager.clone(),
            handle.subscriptions().clone(),
            token.clone(),
        );

        // Add some methods
        methods::add_methods(node_manager, ns);

        server.run().await.unwrap();
    }
}
