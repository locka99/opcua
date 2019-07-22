//! This is a demo server for OPC UA. It will expose variables simulating a real-world application
//! as well as a full collection of variables of every standard type.
//!
//! Use simple-server to understand a terse and simple example.
use std::path::PathBuf;

#[macro_use]
extern crate lazy_static;

use opcua_server::{
    prelude::*,
    http,
};

mod control;
mod machine;
mod scalar;

fn main() {
    // More powerful logging than a console logger
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add some objects representing machinery
    machine::add_machinery(&mut server);

    // Add some scalar variables
    scalar::add_scalar_variables(&mut server);

    // Add some rapidly changing values
    scalar::add_stress_variables(&mut server);

    // Add some control switches, e.g. abort flag
    control::add_control_switches(&mut server);

    // Start the http server, used for metrics
    {
        let server_state = server.server_state();
        let connections = server.connections();
        let metrics = server.server_metrics();
        // The index.html is in a path relative to the working dir.
        let _ = http::run_http_server("127.0.0.1:8585", "../../server/html", server_state, connections, metrics);
    }

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();
}
