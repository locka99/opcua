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

mod server;
pub use server::*;

pub mod session;
pub mod subscription;
pub mod monitored_item;

mod handshake;

#[cfg(test)]
mod tests;