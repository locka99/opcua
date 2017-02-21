#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_yaml;
extern crate rand;

#[macro_use]
extern crate log;

extern crate chrono;
extern crate timer;

extern crate opcua_core;

mod services;
mod comms;
mod session;

pub mod server;

pub mod types;

pub mod config;

pub mod address_space;

pub mod prelude {
    pub use server::*;
    pub use types::*;
    pub use config::*;
    pub use address_space::*;
}

#[cfg(test)]
mod tests;
