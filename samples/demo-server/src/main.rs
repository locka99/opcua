// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

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

use std::path::PathBuf;

use opcua::server::{http, prelude::*};

mod control;
mod historical;
mod machine;
mod methods;
mod scalar;

struct Args {
    help: bool,
    raise_events: bool,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            raise_events: args.contains(["-r", "--raise-events"]),
        })
    }

    pub fn usage() {
        println!(
            r#"Demo Server
Usage:
  -h, --help   Show help
  -r, --raise-events Raise events on a timer (default: false)"#
        );
    }
}

fn main() {
    let args = Args::parse_args().unwrap();
    if args.help {
        Args::usage();
    } else {
        // More powerful logging than a console logger
        log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

        let mut raise_events = args.raise_events;

        // Create an OPC UA server with sample configuration and default node set
        let mut config_path = PathBuf::from("../server.test.conf");
        if !config_path.exists() {
            config_path = PathBuf::from("../server.conf");
            raise_events = true;
        }

        let mut server = Server::new(ServerConfig::load(&config_path).unwrap());

        let ns = {
            let address_space = server.address_space();
            let mut address_space = address_space.write();
            address_space.register_namespace("urn:demo-server").unwrap()
        };

        // Add some objects representing machinery
        machine::add_machinery(&mut server, ns, raise_events);

        // Add some scalar variables
        scalar::add_scalar_variables(&mut server, ns);

        // Add some rapidly changing values
        scalar::add_stress_variables(&mut server, ns);

        // Add some control switches, e.g. abort flag
        control::add_control_switches(&mut server, ns);

        // Add some methods
        methods::add_methods(&mut server, ns);

        // Add historical data providers
        historical::add_providers(&mut server);

        // Start the http server, used for metrics
        start_http_server(&server);

        // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
        server.run();
    }
}

fn start_http_server(server: &Server) {
    let server_state = server.server_state();
    let connections = server.connections();
    let metrics = server.server_metrics();
    // The index.html is in a path relative to the working dir.
    let _ = http::run_http_server(
        "127.0.0.1:8585",
        "../../server/html",
        server_state,
        connections,
        metrics,
    );
}
