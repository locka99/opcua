#[macro_use]
extern crate log;
extern crate byteorder;
extern crate chrono;
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



#[cfg(test)]
mod tests;
