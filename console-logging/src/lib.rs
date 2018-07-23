extern crate env_logger;
extern crate chrono;
#[macro_use]
extern crate log;

pub fn init() {
    use std::env;

    /// White on red
    const ANSI_ERROR: &str = "\x1b[37m\x1b[41m";
    /// Yellow on black
    const ANSI_WARN: &str = "\x1b[33m";
    /// Blue on black
    const ANSI_INFO: &str = "\x1b[36m";
    /// Reset code
    const ANSI_RESET: &str = "\x1b[0m";

    // This is env_logger::init() but taking logging values from  instead of RUST_LOG.
    // env_logger/RUST_LOG is used by cargo and other rust tools so console fills with garbage from
    // other processes  when we're only interested in our own garbage!
    let result = {
        let mut builder = env_logger::LogBuilder::new();
        builder.format(|record: &log::LogRecord| {
            use chrono;
            let now = chrono::Utc::now();
            let time_fmt = now.format("%Y-%m-%d %H:%M:%S%.3f");

            match record.metadata().level() {
                log::LogLevel::Error => {
                    format!("{} - {}{}{} - {} - {}", time_fmt, ANSI_ERROR, record.level(), ANSI_RESET, record.location().module_path(), record.args())
                }
                log::LogLevel::Warn => {
                    format!("{} - {}{}{} - {} - {}", time_fmt, ANSI_WARN, record.level(), ANSI_RESET, record.location().module_path(), record.args())
                }
                log::LogLevel::Info => {
                    format!("{} - {}{}{} - {} - {}", time_fmt, ANSI_INFO, record.level(), ANSI_RESET, record.location().module_path(), record.args())
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
        eprintln!("Logger error, check error = {}", result.unwrap_err());
    } else {
        info!("Logging is enabled, use RUST_OPCUA_LOG environment variable to control filtering, logging level");
    }
}