//! This is a demo server for OPC UA. It will expose variables simulating a real-world application
//! as well as a full collection of variables of every standard type.
//!
//! Use simple-server to understand a terse and simple example.

extern crate chrono;
extern crate futures;
extern crate hyper;
extern crate log;
extern crate opcua_core;
extern crate opcua_server;
extern crate opcua_types;
extern crate rand;
extern crate serde;
extern crate serde_json;

use opcua_server::prelude::*;
use rand::Rng;
use std::path::PathBuf;

mod http;

fn main() {
    // This enables logging via env_logger & log crate macros. If you don't need logging or want
    // to implement your own, omit this line.
    opcua_core::init_logging();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add static scalar values
    add_static_scalar_variables(&mut server);

    // Add dynamically changing scalar values
    let dynamic_scalar_timers = add_dynamic_scalar_variables(&mut server);

    // Start the http server, used for metrics
    http::run_http_server("127.0.0.1:8585", server.server_state.clone(), server.connections.clone(), server.server_metrics.clone());

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();

    // This explicit drop statement prevents the compiler complaining that update_timers is unused.
    drop(dynamic_scalar_timers);
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
    pub fn node_id(&self, dynamic: bool) -> NodeId {
        let mut name = self.name().to_string();
        if dynamic {
            name.push_str("Dynamic");
        }
        NodeId::new_string(2, &name)
    }

    /// Returns the default value for any particular type
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
            Scalar::DateTime => Variant::new(DateTime::default()),
            Scalar::Guid => Variant::new(Guid::default())
        }
    }

    /// Generates a randomized value of the appropriate type in a Variant
    pub fn random_value(&self) -> Variant {
        let mut rng = rand::thread_rng();
        match *self {
            Scalar::Boolean => Variant::new(rng.gen::<bool>()),
            Scalar::Byte => Variant::new(rng.gen::<u8>()),
            Scalar::SByte => Variant::new(rng.gen::<i8>()),
            Scalar::Int16 => Variant::new(rng.gen::<i16>()),
            Scalar::UInt16 => Variant::new(rng.gen::<u16>()),
            Scalar::Int32 => Variant::new(rng.gen::<i32>()),
            Scalar::UInt32 => Variant::new(rng.gen::<u32>()),
            Scalar::Int64 => Variant::new(rng.gen::<i64>()),
            Scalar::UInt64 => Variant::new(rng.gen::<u64>()),
            Scalar::Float => Variant::new(rng.gen::<f32>()),
            Scalar::Double => Variant::new(rng.gen::<f64>()),
            Scalar::String => {
                let s: String = rng.gen_ascii_chars().take(10).collect();
                Variant::new(UAString::from(s))
            }
            Scalar::DateTime => Variant::new(DateTime::from(rng.gen_range::<i64>(0, DateTime::endtimes_ticks()))),
            Scalar::Guid => Variant::new(Guid::new()),
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
fn add_static_scalar_variables(server: &mut Server) {
    // The address space is guarded so obtain a lock to change it
    let mut address_space = server.address_space.write().unwrap();

    let static_folder_id = address_space
        .add_folder("Static", "Static", &AddressSpace::objects_folder_id())
        .unwrap();

    // Create a folder under static folder
    let scalar_folder_id = address_space
        .add_folder("Scalar", "Scalar", &static_folder_id)
        .unwrap();

    for sn in Scalar::values().iter() {
        let node_id = sn.node_id(false);
        let name = sn.name();
        let default_value = sn.default_value();
        let _ = address_space.add_variable(Variable::new(&node_id, name, name, &format!("{} value", name), default_value), &scalar_folder_id);
    }
}

fn add_dynamic_scalar_variables(server: &mut Server) -> Vec<PollingAction> {
    // The address space is guarded so obtain a lock to change it
    {
        let mut address_space = server.address_space.write().unwrap();

        let dynamic_folder_id = address_space
            .add_folder("Dynamic", "Dynamic", &AddressSpace::objects_folder_id())
            .unwrap();

        // Create a folder under static folder
        let scalar_folder_id = address_space
            .add_folder("Scalar", "Scalar", &dynamic_folder_id)
            .unwrap();

        for sn in Scalar::values().iter() {
            let node_id = sn.node_id(true);
            let name = sn.name();
            let default_value = sn.default_value();
            let _ = address_space.add_variable(Variable::new(&node_id, name, name, &format!("{} value", name), default_value), &scalar_folder_id);
        }
    }

    let timers = {
        let address_space = server.address_space.clone();
        vec![
            server.create_polling_action(250, move || {
                let mut address_space = address_space.write().unwrap();
                for sn in Scalar::values().iter() {
                    let node_id = sn.node_id(true);
                    let _ = address_space.set_value_by_node_id(&node_id, sn.random_value());
                }
            })
        ]
    };

    timers
}
