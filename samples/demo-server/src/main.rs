//! This is a demo server for OPC UA. It will expose variables simulating a real-world application
//! as well as a full collection of variables of every standard type.
//!
//! Use simple-server to understand a terse and simple example.

#[macro_use]
extern crate log;
extern crate chrono;
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_server;

use std::sync::{Arc, Mutex};
use std::path::PathBuf;

use opcua_server::prelude::*;

fn main() {
    // This enables logging via env_logger & log crate macros. If you don't need logging or want
    // to implement your own, omit this line.
    opcua_core::init_logging();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add some variables of our own
    let update_timers = add_example_variables(&mut server);

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();

    // This explicit drop statement prevents the compiler complaining that update_timers is unused.
    drop(update_timers);
}

/// Creates some sample variables, and some push / pull examples that update them
fn add_example_variables(server: &mut Server) -> Vec<PollingAction> {
    vec![]
}