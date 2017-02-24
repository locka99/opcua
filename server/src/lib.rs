#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_yaml;
extern crate rand;
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

extern crate time;
extern crate chrono;
extern crate timer;

extern crate opcua_core;

mod services;
mod comms;
mod session;

pub mod server;

pub mod subscriptions;

pub mod config;

pub mod address_space;

pub mod prelude {
    pub use server::*;
    pub use subscriptions::*;
    pub use config::*;
    pub use address_space::*;
}

#[cfg(test)]
mod tests;
