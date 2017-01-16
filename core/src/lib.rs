#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
extern crate byteorder;
extern crate chrono;
extern crate regex;
// extern crate openssl;

pub mod types;
pub mod address_space;
pub mod comms;
pub mod services;

use log::*;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Debug
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}

pub fn init_logging() -> Result<(), SetLoggerError> {
    log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Debug);
        Box::new(SimpleLogger)
    })
}

pub mod debug {
    /// Prints out the content of a slice in a form similar to node-opcua
    /// to aid with debugging.
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
                    debug!("{} {}", hex_line, char_line);
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
                debug!("{} {}", hex_line, char_line);
            }
        }
    }
}

#[cfg(test)]
mod tests;
