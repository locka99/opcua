// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! The OPC UA Core module holds functionality that is common to server and clients that make use of OPC UA.
//! It contains message chunking, cryptography / pki, communications and standard handshake messages.

#[macro_export]
macro_rules! supported_message_as {
    ($v: expr, $i: ident) => {
        if let SupportedMessage::$i(value) = $v {
            *value
        } else {
            panic!("Cannot convert to {:?}", stringify!($i));
        }
    };
}

lazy_static! {
    pub static ref RUNTIME: crate::core::runtime::Runtime =
        crate::core::runtime::Runtime::default();
}

/// Returns a vector of all currently existing runtime components as a vector of strings.
#[macro_export]
macro_rules! runtime_components {
    () => {{
        use $crate::core::RUNTIME;
        RUNTIME.components()
    }};
}

/// This macro is for debugging purposes - code register a running component (e.g. tokio task) when it starts
/// and calls the corresponding deregister macro when it finishes. This enables the code to print
/// out a list of components in existence at any time to ensure they were properly cleaned up.
#[macro_export]
macro_rules! register_runtime_component {
    ( $component_name:expr ) => {
        RUNTIME.register_component($component_name);
    };
}

/// See `register_runtime_component`
#[macro_export]
macro_rules! deregister_runtime_component {
    ( $component_name:expr ) => {
        RUNTIME.deregister_component($component_name);
    };
}

/// Contains debugging utility helper functions
pub mod debug {
    /// Prints out the content of a slice in hex and visible char format to aid debugging. Format
    /// is similar to corresponding functionality in node-opcua
    pub fn log_buffer(message: &str, buf: &[u8]) {
        // No point doing anything unless debug level is on
        if !log_enabled!(target: "hex", log::Level::Trace) {
            return;
        }

        let line_len = 32;
        let len = buf.len();
        let last_line_padding = ((len / line_len) + 1) * line_len - len;

        trace!(target: "hex", "{}", message);

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
            char_line.push(if value >= 32 && value <= 126 {
                value as char
            } else {
                '.'
            });
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
pub mod tests;

pub mod constants {
    /// Default OPC UA port number. Used by a discovery server. Other servers would normally run
    /// on a different port. So OPC UA for Rust does not use this nr by default but it is used
    /// implicitly in opc.tcp:// urls and elsewhere.
    pub const DEFAULT_OPC_UA_SERVER_PORT: u16 = 4840;
}

pub mod comms;
pub mod config;
pub mod handle;
pub mod runtime;
#[rustfmt::skip]
pub mod supported_message;

/// Contains most of the things that are typically required from a client / server.
pub mod prelude {
    pub use super::{comms::prelude::*, config::Config, supported_message::*};
    pub use crate::types::{status_code::StatusCode, *};
}
