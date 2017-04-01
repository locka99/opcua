

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate chrono;
extern crate regex;
extern crate rand;
#[cfg(feature = "crypto")]
extern crate openssl;

pub mod types;
pub mod comms;
pub mod services;
#[cfg(feature = "crypto")]
pub mod crypto;

/// Tests if crypto is enabled, true for yes it is otherwise false
pub fn is_crypto_enabled() -> bool {
    cfg!(feature = "crypto")
}

/// The prelude mod contains all the things you typically need to access from a client / server.
pub mod prelude {
    pub use types::*;
    pub use comms::*;
    pub use services::*;
}

use log::*;

use std::collections::HashSet;

/// Simple logger (as the name suggests) is a bare bones implementation of the log::Log trait
/// that may be used to print debug information out to the console.
struct SimpleLogger {
    target_map: HashSet<&'static str>,
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Debug
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            if !self.target_map.is_empty() && !self.target_map.contains(record.metadata().target()) {
                return;
            }

            match record.metadata().level() {
                LogLevel::Error => {
                    println!("\x1b[37m\x1b[41m{}\x1b[0m - {} - {}", record.level(), record.metadata().target(), record.args());
                },
                LogLevel::Warn => {
                    println!("\x1b[33m{}\x1b[0m - {} - {}", record.level(), record.metadata().target(), record.args());
                },
                LogLevel::Info => {
                    println!("\x1b[36m{}\x1b[0m - {} - {}", record.level(), record.metadata().target(), record.args());
                },
                _ => {
                    println!("{} - {} - {}", record.level(), record.metadata().target(), record.args());
                }
            }
        }
    }
}

/// Initialise OPC UA logging on the executable.
pub fn init_logging() -> Result<(), SetLoggerError> {
    log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Debug);
        Box::new(SimpleLogger {
            target_map: HashSet::new(),
        })
    })
}

///Contains constants recognized by OPC UA clients and servers to describe various protocols and
/// profiles used during communication and encryption.
pub mod profiles {
    pub const TRANSPORT_BINARY: &'static str = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";

    pub const SECURITY_POLICY_NONE: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#None";
    pub const SECURITY_POLICY_BASIC128RSA15: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
    pub const SECURITY_POLICY_BASIC256: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
    pub const SECURITY_POLICY_BASIC256SHA256: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

    pub const SECURITY_USER_TOKEN_POLICY_ANONYMOUS: &'static str = "http://opcfoundation.org/UA-Profile/Security/UserToken/Anonymous";
    pub const SECURITY_USER_TOKEN_POLICY_USERPASS: &'static str = "http://opcfoundation.org/UA-Profile/ Security/UserToken-Server/UserNamePassword";
}

/// Contains debugging utility helper functions
pub mod debug {
    pub const SUBSCRIPTION: &'static str = "subscription";

    /// Prints out the content of a slice in hex and visible char format to aid debugging. Format
    /// is similar to corresponding functionality in node-opcua
    pub fn debug_buffer(buf: &[u8]) {
        use log::LogLevel::Debug;
        // No point doing anything unless debug level is on
        if log_enabled!(Debug) {
            let line_len = 32;
            let len = buf.len();
            let last_line_padding = ((len / line_len) + 1) * line_len - len;

            let mut char_line = String::new();
            let mut hex_line = format!("{:08x}: ", 0);

            for (i, b) in buf.iter().enumerate() {
                let value = *b as u8;
                if i > 0 && i % line_len == 0 {
                    debug!(target: "hex", "{} {}", hex_line, char_line);
                    hex_line = format!("{:08x}: ", i);
                    char_line.clear();
                }
                hex_line = format!("{} {:02x}", hex_line, value);
                char_line.push(if value >= 32 && value <= 126 { value as char } else { '.' });
            }
            if last_line_padding > 0 {
                for _ in 0..last_line_padding {
                    hex_line.push_str("   ");
                }
                debug!(target: "hex", "{} {}", hex_line, char_line);
            }
        }
    }
}

#[cfg(test)]
mod tests;
