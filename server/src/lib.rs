#[macro_use]
extern crate log;

extern crate chrono;

extern crate serde;
extern crate serde_yaml;

extern crate opcua_core;
extern crate byteorder;

pub mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

mod services;
mod server;
mod comms;

pub mod types;

pub use server::*;


#[cfg(test)]
mod tests;