//! The OPC UA Core module holds functionality that is common to server and clients that make use of OPC UA
//! It contains functionality such as message chunking, cryptography / pki and standard handshake messages.

#[macro_use]
extern crate log;
extern crate chrono;
extern crate regex;
extern crate ring;
extern crate openssl;
#[cfg(test)]
extern crate tempdir;
extern crate serde;
extern crate serde_yaml;
extern crate tokio;
extern crate tokio_io;

extern crate opcua_types;

pub mod comms;
pub mod crypto;

// A convenience macro for deadlocks.

#[macro_export]
macro_rules! trace_lock_unwrap {
    ( $x:expr ) => {
        {
//            use std::thread;
//            trace!("Thread {:?}, {} locking at {}, line {}", thread::current().id(), stringify!($x), file!(), line!());
            let v = $x.lock().unwrap();
//            trace!("Thread {:?}, {} lock completed", thread::current().id(), stringify!($x));
            v
        }
    }
}

#[macro_export]
macro_rules! trace_read_lock_unwrap {
    ( $x:expr ) => {
        {
//            use std::thread;
//            trace!("Thread {:?}, {} read locking at {}, line {}", thread::current().id(), stringify!($x), file!(), line!());
            let v = $x.read().unwrap();
//            trace!("Thread {:?}, {} read lock completed", thread::current().id(), stringify!($x));
            v
        }
    }
}

#[macro_export]
macro_rules! trace_write_lock_unwrap {
    ( $x:expr ) => {
        {
//            use std::thread;
//            trace!("Thread {:?}, {} write locking at {}, line {}", thread::current().id(), stringify!($x), file!(), line!());
            let v = $x.write().unwrap();
//            trace!("Thread {:?}, {} write lock completed", thread::current().id(), stringify!($x));
            v
        }
    }
}

/// OPC UA for Rust uses the standard log crate for internal logging purposes. This function
/// can be called by executable targets (e.g. inside main() set up) to enable logging. The default
/// implementation uses env_logger to provide console based output. Set the `RUST_OPCUA_LOG`
/// environment variable with the default log level, e.g. `RUST_OPCUA_LOG=debug` for more logging.
/// See `env_logger` for more filtering options.
///
/// Alternatively, don't call it and call another implementation that supports the log macros.
///
/// See here for more information
///
/// https://crates.io/crates/log
#[macro_export]
macro_rules! opcua_init_env_logger {
    () => {
        ::opcua_core::init_env_logger();
    }
}

/// Contains debugging utility helper functions
pub mod debug {
    pub const SUBSCRIPTION: &'static str = "subscription";

    /// Prints out the content of a slice in hex and visible char format to aid debugging. Format
    /// is similar to corresponding functionality in node-opcua
    pub fn log_buffer(message: &str, buf: &[u8]) {
        use log;
        // No point doing anything unless debug level is on
        if !log_enabled!(log::Level::Trace) {
            return;
        }

        let line_len = 32;
        let len = buf.len();
        let last_line_padding = ((len / line_len) + 1) * line_len - len;

        trace!("{}", message);

        let mut char_line = String::new();
        let mut hex_line = format!("{:08x}: ", 0);

        for (i, b) in buf.iter().enumerate() {
            let value = *b as u8;
            if i > 0 && i % line_len == 0 {
                trace!(target: "hex", "{} {}", hex_line, char_line);
                hex_line = format!("{:08}: ", i);
                char_line.clear();
            }
            hex_line = format!("{} {:02x}", hex_line, value);
            char_line.push(if value >= 32 && value <= 126 { value as char } else { '.' });
        }
        if last_line_padding > 0 {
            for _ in 0..last_line_padding {
                hex_line.push_str("   ");
            }
            trace!(target: "hex", "{} {}", hex_line, char_line);
        }
    }
}

#[cfg(test)]
mod tests;

pub mod config;

/// The prelude mod contains all the things you typically need to access from a client / server.
pub mod prelude {
    pub use opcua_types::*;
    pub use opcua_types::status_codes::StatusCode;
    pub use comms::prelude::*;
    pub use crypto::*;
    pub use config::Config;
}
