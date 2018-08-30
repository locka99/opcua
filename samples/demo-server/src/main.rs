//! This is a demo server for OPC UA. It will expose variables simulating a real-world application
//! as well as a full collection of variables of every standard type.
//!
//! Use simple-server to understand a terse and simple example.

extern crate chrono;
extern crate log;
extern crate rand;
extern crate log4rs;

extern crate opcua_core;
extern crate opcua_server;
extern crate opcua_types;
extern crate opcua_console_logging;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::iter::repeat;

use rand::Rng;
use rand::distributions::Alphanumeric;

use opcua_server::http;
use opcua_server::prelude::*;

fn main() {
    // More powerful logging than a console logger
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add static scalar values
    add_static_scalar_variables(&mut server);

    // Add dynamically changing scalar values
    add_dynamic_scalar_variables(&mut server);

    // Add some rapidly changing values
    add_stress_scalar_variables(&mut server);

    // Add some control switches, e.g. abort flag
    add_control_switches(&mut server);

    // Start the http server, used for metrics
    http::run_http_server("127.0.0.1:8585", server.server_state.clone(), server.connections.clone(), server.server_metrics.clone());

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    Server::run(Arc::new(RwLock::new(server)));
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
        NodeId::new(2, name)
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
            Scalar::Boolean => rng.gen::<bool>().into(),
            Scalar::Byte => rng.gen::<u8>().into(),
            Scalar::SByte => rng.gen::<i8>().into(),
            Scalar::Int16 => rng.gen::<i16>().into(),
            Scalar::UInt16 => rng.gen::<u16>().into(),
            Scalar::Int32 => rng.gen::<i32>().into(),
            Scalar::UInt32 => rng.gen::<u32>().into(),
            Scalar::Int64 => rng.gen::<i64>().into(),
            Scalar::UInt64 => rng.gen::<u64>().into(),
            Scalar::Float => rng.gen::<f32>().into(),
            Scalar::Double => rng.gen::<f64>().into(),
            Scalar::String => {
                let s = repeat(()).take(10).map(|_| rng.sample(Alphanumeric)).collect::<String>();
                UAString::from(s).into()
            }
            Scalar::DateTime => DateTime::from(rng.gen_range::<i64>(0, DateTime::endtimes_ticks())).into(),
            Scalar::Guid => Guid::new().into(),
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

fn add_control_switches(server: &mut Server) {
    // The address space is guarded so obtain a lock to change it
    let abort_node_id = NodeId::new(2u16, "abort");
    {
        let mut address_space = server.address_space.write().unwrap();

        let folder_id = address_space
            .add_folder("Control", "Control", &AddressSpace::objects_folder_id())
            .unwrap();

        let mut variable = Variable::new(&abort_node_id, "Abort", "Abort", "Abort", Variant::Boolean(false));
        variable.set_writable(true);
        let _ = address_space.add_variable(variable, &folder_id);
    }

    let server_state = server.server_state.clone();
    let address_space = server.address_space.clone();
    server.add_polling_action(250, move || {
        let address_space = address_space.read().unwrap();
        // Test for abort flag
        let abort = if let Ok(v) = address_space.get_variable_value(abort_node_id.clone()) {
            match v.value {
                Some(Variant::Boolean(v)) => v,
                _ => {
                    panic!("Abort value should be true or false");
                }
            }
        } else {
            panic!("Abort value should be in address space");
        };
        // Check if abort has been set to true, in which case abort
        if abort {
            let mut server_state = server_state.write().unwrap();
            server_state.abort();
        }
    });
}

/// Creates some sample variables, and some push / pull examples that update them
fn add_static_scalar_variables(server: &mut Server) {
    // The address space is guarded so obtain a lock to change it
    let mut address_space = server.address_space.write().unwrap();

    let static_folder_id = address_space
        .add_folder("Static", "Static", &AddressSpace::objects_folder_id())
        .unwrap();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Scalar", "Scalar", &static_folder_id)
        .unwrap();

    for sn in Scalar::values().iter() {
        let node_id = sn.node_id(false);
        let name = sn.name();
        let default_value = sn.default_value();
        let _ = address_space.add_variable(Variable::new(&node_id, name, name, &format!("{} value", name), default_value), &folder_id);
    }
}

fn add_dynamic_scalar_variables(server: &mut Server) {
    // The address space is guarded so obtain a lock to change it
    {
        let mut address_space = server.address_space.write().unwrap();

        let folder_id = address_space
            .add_folder("Dynamic", "Dynamic", &AddressSpace::objects_folder_id())
            .unwrap();

        // Create a folder under static folder
        let scalar_folder_id = address_space
            .add_folder("Scalar", "Scalar", &folder_id)
            .unwrap();

        Scalar::values().iter().for_each(|sn| {
            let node_id = sn.node_id(true);
            let name = sn.name();
            let default_value = sn.default_value();
            let _ = address_space.add_variable(Variable::new(&node_id, name, name, &format!("{} value", name), default_value), &scalar_folder_id);
        });
    }

    let address_space = server.address_space.clone();
    server.add_polling_action(250, move || {
        let mut address_space = address_space.write().unwrap();
        Scalar::values().iter().for_each(|sn| {
            let node_id = sn.node_id(true);
            let _ = address_space.set_variable_value(node_id, sn.random_value());
        });
    });
}


fn add_stress_scalar_variables(server: &mut Server) {
    // The address space is guarded so obtain a lock to change it
    {
        let mut address_space = server.address_space.write().unwrap();

        let folder_id = address_space
            .add_folder("Stress", "Stress", &AddressSpace::objects_folder_id())
            .unwrap();

        for i in 0..1000 {
            let node_id = NodeId::new(2, format!("v{:04}", i));
            let name = format!("v{:04}", i);
            let default_value = Variant::Int32(0);
            let _ = address_space.add_variable(Variable::new(&node_id, &name, &name, &format!("{} value", name), default_value), &folder_id);
        }
    }

    let address_space = server.address_space.clone();
    server.add_polling_action(100, move || {
        let mut address_space = address_space.write().unwrap();
        let mut rng = rand::thread_rng();
        for i in 0..1000 {
            let node_id = NodeId::new(2, format!("v{:04}", i));
            let value: Variant = rng.gen::<i32>().into();
            let _ = address_space.set_variable_value(node_id, value);
        }
    });
}
