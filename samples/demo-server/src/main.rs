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
use std::path::PathBuf;

#[macro_use]
extern crate lazy_static;

use opcua_server::{
    prelude::*,
    http,
};

mod control;
mod machine;
mod methods;
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

    // Add some methods
    methods::add_methods(&mut server);

    // Start the http server, used for metrics
    start_http_server(&server);

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();
}

fn start_http_server(server: &Server) {
    let server_state = server.server_state();
    let connections = server.connections();
    let metrics = server.server_metrics();
    // The index.html is in a path relative to the working dir.
    let _ = http::run_http_server("127.0.0.1:8585", "../../server/html", server_state, connections, metrics);
}
