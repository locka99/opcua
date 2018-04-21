extern crate chrono;
extern crate futures;
#[macro_use]
extern crate log;
extern crate opcua_client;
extern crate opcua_core;
extern crate opcua_server;
extern crate opcua_types;

fn main() {
    trace!("Needs to be run with cargo test");
    panic!("I do not do anything, run with cargo test");
}

#[cfg(test)]
mod tests;
