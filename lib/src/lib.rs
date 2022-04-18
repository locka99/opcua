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

// Synchronization structs. This is a wrapper mod around `parking_lot` types so opcua users don't have
// to reference that other crate.
pub mod sync {
    pub type RwLock<T> = parking_lot::RwLock<T>;
    pub type Mutex<T> = parking_lot::Mutex<T>;
}

/// Tracing macro for obtaining a lock on a `Mutex`. Sometimes deadlocks can happen in code,
/// and if they do, this macro is useful for finding out where they happened.
#[macro_export]
macro_rules! trace_lock {
    ( $x:expr ) => {
        {
//            use std::thread;
//            trace!("Thread {:?}, {} locking at {}, line {}", thread::current().id(), stringify!($x), file!(), line!());
            let v = $x.lock();
//            trace!("Thread {:?}, {} lock completed", thread::current().id(), stringify!($x));
            v
        }
    }
}

/// Tracing macro for obtaining a read lock on a `RwLock`.
#[macro_export]
macro_rules! trace_read_lock {
    ( $x:expr ) => {
        {
//            use std::thread;
//            trace!("Thread {:?}, {} read locking at {}, line {}", thread::current().id(), stringify!($x), file!(), line!());
            let v = $x.read();
//            trace!("Thread {:?}, {} read lock completed", thread::current().id(), stringify!($x));
            v
        }
    }
}

/// Tracing macro for obtaining a write lock on a `RwLock`.
#[macro_export]
macro_rules! trace_write_lock {
    ( $x:expr ) => {
        {
//            use std::thread;
//            trace!("Thread {:?}, {} write locking at {}, line {}", thread::current().id(), stringify!($x), file!(), line!());
            let v = $x.write();
//            trace!("Thread {:?}, {} write lock completed", thread::current().id(), stringify!($x));
            v
        }
    }
}

#[cfg(feature = "async-client")]
pub mod async_client;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "console-logging")]
pub mod console_logging;
pub mod core;
pub mod crypto;
#[cfg(feature = "server")]
pub mod server;
pub mod types;

mod prelude {
    #[cfg(feature = "client")]
    pub use crate::client::prelude::*;
    pub use crate::core::prelude::*;
    #[cfg(feature = "server")]
    pub use crate::server::prelude::*;
}
