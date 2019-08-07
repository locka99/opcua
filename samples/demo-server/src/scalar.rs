use rand::Rng;
use rand::distributions::Alphanumeric;

use opcua_server::{
    prelude::*,
};

pub fn add_scalar_variables(server: &mut Server) {
    let (static_folder_id, dynamic_folder_id) = {
        let address_space = server.address_space();
        let mut address_space = address_space.write().unwrap();
        (
            address_space
                .add_folder("Static", "Static", &NodeId::objects_folder_id())
                .unwrap(),
            address_space
                .add_folder("Dynamic", "Dynamic", &NodeId::objects_folder_id())
                .unwrap()
        )
    };


    // Add static scalar values
    add_static_scalar_variables(server, &static_folder_id);
    add_static_array_variables(server, &static_folder_id);

    // Add dynamically changing scalar values
    add_dynamic_scalar_variables(server, &dynamic_folder_id);
    add_dynamic_array_variables(server, &dynamic_folder_id);
    set_dynamic_timers(server);
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
        match self {
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
    pub fn node_id(&self, is_dynamic: bool, is_array: bool) -> NodeId {
        let mut name = self.name().to_string();
        if is_dynamic {
            name.push_str("Dynamic");
        }
        if is_array {
            name.push_str("Array");
        }
        NodeId::new(2, name)
    }

    /// Returns the default value for any particular type
    pub fn default_value(&self) -> Variant {
        match self {
            Scalar::Boolean => false.into(),
            Scalar::Byte => 0u8.into(),
            Scalar::SByte => 0i8.into(),
            Scalar::Int16 => 0i16.into(),
            Scalar::UInt16 => 0u16.into(),
            Scalar::Int32 => 0i32.into(),
            Scalar::UInt32 => 0u32.into(),
            Scalar::Int64 => 0i64.into(),
            Scalar::UInt64 => 0u64.into(),
            Scalar::Float => 0f32.into(),
            Scalar::Double => 0f64.into(),
            Scalar::String => "".into(),
            Scalar::DateTime => DateTime::default().into(),
            Scalar::Guid => Guid::default().into()
        }
    }

    /// Generates a randomized value of the appropriate type in a Variant
    pub fn random_value(&self) -> Variant {
        let mut rng = rand::thread_rng();
        match self {
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
                let s = (0..10).map(|_| rng.sample(Alphanumeric)).collect::<String>();
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


/// Creates some sample variables, and some push / pull examples that update them
fn add_static_scalar_variables(server: &mut Server, static_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Scalar", "Scalar", &static_folder_id)
        .unwrap();

    for sn in Scalar::values().iter() {
        let node_id = sn.node_id(false, false);
        let name = sn.name();
        VariableBuilder::new(&node_id, name, name)
            .value(sn.default_value())
            .organized_by(&folder_id)
            .insert(&mut address_space);
    }
}

fn add_static_array_variables(server: &mut Server, static_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Array", "Array", &static_folder_id)
        .unwrap();

    Scalar::values().iter().for_each(|sn| {
        let node_id = sn.node_id(false, true);
        let name = sn.name();
        let values = (0..100).map(|_| sn.default_value()).collect::<Vec<Variant>>();
        VariableBuilder::new(&node_id, name, name)
            .value(values)
            .organized_by(&folder_id)
            .insert(&mut address_space);
    });
}

fn add_dynamic_scalar_variables(server: &mut Server, dynamic_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Scalar", "Scalar", &dynamic_folder_id)
        .unwrap();

    Scalar::values().iter().for_each(|sn| {
        let node_id = sn.node_id(true, false);
        let name = sn.name();
        VariableBuilder::new(&node_id, name, name)
            .value(sn.default_value())
            .organized_by(&folder_id)
            .insert(&mut address_space);
    });
}

fn add_dynamic_array_variables(server: &mut Server, dynamic_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Array", "Array", &dynamic_folder_id)
        .unwrap();

    Scalar::values().iter().for_each(|sn| {
        let node_id = sn.node_id(true, true);
        let name = sn.name();
        let values = (0..10).map(|_| sn.default_value()).collect::<Vec<Variant>>();
        VariableBuilder::new(&node_id, name, name)
            .value(values)
            .organized_by(&folder_id)
            .insert(&mut address_space);
    });
}

fn set_dynamic_timers(server: &mut Server) {
    let address_space = server.address_space();

    // Standard change timers
    server.add_polling_action(250, move || {
        let mut address_space = address_space.write().unwrap();
        // Scalar
        let now = DateTime::now();
        Scalar::values().iter().for_each(|sn| {
            let node_id = sn.node_id(true, false);
            let _ = address_space.set_variable_value_by_ref(&node_id, sn.random_value(), &now, &now);

            let node_id = sn.node_id(true, true);
            let values = (0..10).map(|_| sn.random_value()).collect::<Vec<Variant>>();
            let _ = address_space.set_variable_value_by_ref(&node_id, values, &now, &now);
        });
    });
}

pub fn add_stress_variables(server: &mut Server) {
    let node_ids = (0..1000).map(|i| NodeId::new(2, format!("v{:04}", i))).collect::<Vec<NodeId>>();

    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    let folder_id = address_space
        .add_folder("Stress", "Stress", &NodeId::objects_folder_id())
        .unwrap();

    node_ids.iter().enumerate().for_each(|(i, node_id)| {
        let name = format!("v{:04}", i);
        VariableBuilder::new(&node_id, &name, &name)
            .value(0i32)
            .organized_by(&folder_id)
            .insert(&mut address_space);
    });

    set_stress_timer(server, node_ids);
}

fn set_stress_timer(server: &mut Server, node_ids: Vec<NodeId>) {
    let address_space = server.address_space();
    server.add_polling_action(100, move || {
        let mut rng = rand::thread_rng();
        let mut address_space = address_space.write().unwrap();
        let now = DateTime::now();
        node_ids.iter().for_each(|node_id| {
            let value: Variant = rng.gen::<i32>().into();
            let _ = address_space.set_variable_value_by_ref(node_id, value, &now, &now);
        });
    });
}
