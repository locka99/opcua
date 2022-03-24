#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(test)]
extern crate tempdir;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "http")]
extern crate actix_web;
#[cfg(test)]
extern crate serde_json;
#[macro_use]
extern crate derivative;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "console_logging")]
mod console_logging;
mod core;
mod crypto;
#[cfg(feature = "server")]
mod server;
