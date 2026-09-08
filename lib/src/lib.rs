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

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "console-logging")]
pub mod console_logging;
pub mod core;
pub mod crypto;
#[cfg(feature = "server")]
pub mod server;
pub mod types;
pub mod puffin;

// Turns hex string to array bytes. Function was extracted & adapted from the deprecated
// crate rustc-serialize. Function panics if the string is invalid.
//
// https://github.com/rust-lang-deprecated/rustc-serialize/blob/master/src/hex.rs
#[cfg(test)]
fn from_hex(v: &str) -> Vec<u8> {
    // This may be an overestimate if there is any whitespace
    let mut b = Vec::with_capacity(v.len() / 2);
    let mut modulus = 0;
    let mut buf = 0;

    for (idx, byte) in v.bytes().enumerate() {
        buf <<= 4;

        match byte {
            b'A'..=b'F' => buf |= byte - b'A' + 10,
            b'a'..=b'f' => buf |= byte - b'a' + 10,
            b'0'..=b'9' => buf |= byte - b'0',
            b' ' | b'\r' | b'\n' | b'\t' => {
                buf >>= 4;
                continue;
            }
            _ => {
                let ch = v[idx..].chars().next().unwrap();
                panic!("Invalid hex character {} at {}", ch, idx);
            }
        }

        modulus += 1;
        if modulus == 2 {
            modulus = 0;
            b.push(buf);
        }
    }

    match modulus {
        0 => b.into_iter().collect(),
        _ => panic!("Invalid hex length"),
    }
}

mod prelude {
    #[cfg(feature = "server")]
    pub use crate::server::prelude::*;
}
