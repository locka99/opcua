#[macro_use]
extern crate log;
extern crate env_logger;
extern crate chrono;
extern crate regex;
extern crate rand;
extern crate openssl;
#[cfg(test)]
extern crate tempdir;

extern crate opcua_types;

pub mod comms;
pub mod crypto;

/// OPC UA for Rust uses the standard log crate for internal logging purposes. This function
/// can be called by executable targets (e.g. inside main() set up) to enable logging. The default
/// implementation uses env_logger to provide console based output. Set the RUST_OPCUA_LOG
/// environment variable with the default log level, e.g. RUST_OPCUA_LOG=debug for more logging.
/// See env_logger for more filtering options.
///
/// Alternatively, don't call it and call another implementation that supports the log macros. e.g.
/// use the fern crate and configure your own logging
pub fn init_logging() {
    use std::env;
    // This is env_logger::init() but taking logging values from  instead of RUST_LOG.
    // env_logger/RUST_LOG is used by cargo and other rust tools so console fills with garbage from
    // other processes  when we're only interested in our own garbage!
    let result = {
        let mut builder = env_logger::LogBuilder::new();
        builder.format(|record: &log::LogRecord| {
            use chrono;
            let now = chrono::UTC::now();
            let time_fmt = now.format("%Y-%m-%d %H:%M:%S%.3f");

            match record.metadata().level() {
                log::LogLevel::Error => {
                    format!("{} - \x1b[37m\x1b[41m{}\x1b[0m - {} - {}", time_fmt, record.level(), record.location().module_path(), record.args())
                }
                log::LogLevel::Warn => {
                    format!("{} - \x1b[33m{}\x1b[0m - {} - {}", time_fmt, record.level(), record.location().module_path(), record.args())
                }
                log::LogLevel::Info => {
                    format!("{} - \x1b[36m{}\x1b[0m - {} - {}", time_fmt, record.level(), record.location().module_path(), record.args())
                }
                _ => {
                    format!("{} - {} - {} - {}", time_fmt, record.level(), record.location().module_path(), record.args())
                }
            }
        });
        // Try to get filter from environment var, else default
        let filters = if let Ok(env_filters) = env::var("RUST_OPCUA_LOG") {
            env_filters
        } else {
            "info".to_string()
        };
        builder.parse(&filters);
        builder.init()
    };
    if result.is_err() {
        println!("Logger error, check error = {}", result.unwrap_err());
    } else {
        info!("Logging is enabled, use RUST_OPCUA_LOG environment variable to control filtering, logging level");
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
        if !log_enabled!(log::LogLevel::Trace) {
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

/// The prelude mod contains all the things you typically need to access from a client / server.
pub mod prelude {
    pub use opcua_types::*;
    pub use comms::prelude::*;
    pub use crypto::*;
}
