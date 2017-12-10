//! This is a demo server for OPC UA. It will expose variables simulating a real-world application
//! as well as a full collection of variables of every standard type.
//!
//! Use simple-server to understand a terse and simple example.

#[macro_use]
extern crate log;
extern crate chrono;
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_server;

use std::sync::{Arc, Mutex};
use std::path::PathBuf;

use opcua_server::prelude::*;

fn main() {
    // This enables logging via env_logger & log crate macros. If you don't need logging or want
    // to implement your own, omit this line.
    opcua_core::init_logging();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add some variables of our own
    let update_timers = add_scalar_variables(&mut server);

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();

    // This explicit drop statement prevents the compiler complaining that update_timers is unused.
    drop(update_timers);
}

enum Scalar {
    Boolean,
    Byte,
    SByte,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    String,
    DateTime,
    Guid,
    // ByteString
    // XmlElement
}

impl Scalar {
    pub fn name(&self) -> &'static str {
        match *self {
            Scalar::Boolean => "Boolean",
            Scalar::Byte => "Byte",
            Scalar::SByte => "SByte",
            Scalar::Int16 => "Int16",
            Scalar::UInt16 => "UInt16",
            Scalar::Int32 => "Int32",
            Scalar::UInt32 => "UInt32",
            Scalar::Int64 => "Int64",
            Scalar::UInt64 => "UInt64",
            Scalar::Float => "Float",
            Scalar::Double => "Double",
            Scalar::String => "String",
            Scalar::DateTime => "DateTime",
            Scalar::Guid => "Guid",
        }
    }
    pub fn node_id(&self) -> NodeId {
        NodeId::new_string(2, self.name())
    }

    pub fn default_value(&self) -> Variant {
        match *self {
            Scalar::Boolean => Variant::new(false),
            Scalar::Byte => Variant::new(0u8),
            Scalar::SByte => Variant::new(0i8),
            Scalar::Int16 => Variant::new(0i16),
            Scalar::UInt16 => Variant::new(0u16),
            Scalar::Int32 => Variant::new(0i32),
            Scalar::UInt32 => Variant::new(0u32),
            Scalar::Int64 => Variant::new(0i64),
            Scalar::UInt64 => Variant::new(0u64),
            Scalar::Float => Variant::new(0f32),
            Scalar::Double => Variant::new(0f64),
            Scalar::String => Variant::new(""),
            Scalar::DateTime => Variant::new(DateTime::epoch()),
            Scalar::Guid => Variant::new(Guid::null())
        }
    }

    pub fn values() -> Vec<Scalar> {
        vec![
            Scalar::Boolean,
            Scalar::Byte,
            Scalar::SByte,
            Scalar::Int16,
            Scalar::UInt16,
            Scalar::Int32,
            Scalar::UInt32,
            Scalar::Int64,
            Scalar::UInt64,
            Scalar::String,
            Scalar::Float,
            Scalar::Double,
            Scalar::DateTime,
            Scalar::Guid,
        ]
    }
}


/// Creates some sample variables, and some push / pull examples that update them
fn add_scalar_variables(server: &mut Server) -> Vec<PollingAction> {
    // The address space is guarded so obtain a lock to change it
    let mut address_space = server.address_space.write().unwrap();

    // Create a sample folder under objects folder
    let scalar_folder_id = address_space
        .add_folder("Scalar", "Scalar", &AddressSpace::objects_folder_id())
        .unwrap();

    for sn in Scalar::values().iter() {
        let node_id = sn.node_id();
        let name = sn.name();
        let default_value = sn.default_value();
        let _ = address_space.add_variable(Variable::new(&node_id, name, name, &format!("{} value", name), default_value), &scalar_folder_id);
    }

    vec![]
}
