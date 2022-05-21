// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use rand::distributions::Alphanumeric;
use rand::Rng;

use opcua::server::prelude::*;

pub fn add_scalar_variables(server: &mut Server, ns: u16) {
    let (static_folder_id, dynamic_folder_id) = {
        let address_space = server.address_space();
        let mut address_space = address_space.write();
        (
            address_space
                .add_folder("Static", "Static", &NodeId::objects_folder_id())
                .unwrap(),
            address_space
                .add_folder("Dynamic", "Dynamic", &NodeId::objects_folder_id())
                .unwrap(),
        )
    };

    // Add static scalar values
    add_static_scalar_variables(server, ns, &static_folder_id);
    add_static_array_variables(server, ns, &static_folder_id);

    // Add dynamically changing scalar values
    add_dynamic_scalar_variables(server, ns, &dynamic_folder_id);
    add_dynamic_array_variables(server, ns, &dynamic_folder_id);
    set_dynamic_timers(server, ns);
}

const SCALAR_TYPES: [DataTypeId; 14] = [
    DataTypeId::Boolean,
    DataTypeId::Byte,
    DataTypeId::SByte,
    DataTypeId::Int16,
    DataTypeId::UInt16,
    DataTypeId::Int32,
    DataTypeId::UInt32,
    DataTypeId::Int64,
    DataTypeId::UInt64,
    DataTypeId::Float,
    DataTypeId::Double,
    DataTypeId::String,
    DataTypeId::DateTime,
    DataTypeId::Guid,
    //    DataTypeId::ByteString, DataTypeId::Duration, DataTypeId::Integer, DataTypeId::LocaleId,
    //    DataTypeId::LocalizedText, DataTypeId::NodeId, DataTypeId::Number, DataTypeId::QualifiedName,
    //    DataTypeId::Time, DataTypeId::UInteger, DataTypeId::UtcTime, DataTypeId::XmlElement,
    //    DataTypeId::Variant, DataTypeId::Decimal, DataTypeId::ImageBMP,
    //    DataTypeId::ImageGIF, DataTypeId::ImageJPG, DataTypeId::ImagePNG,
];

pub fn scalar_node_id(ns: u16, id: DataTypeId, is_dynamic: bool, is_array: bool) -> NodeId {
    let mut name = scalar_name(id).to_string();
    if is_dynamic {
        name.push_str("Dynamic");
    }
    if is_array {
        name.push_str("Array");
    }
    NodeId::new(ns, name)
}

pub fn scalar_name(id: DataTypeId) -> &'static str {
    match id {
        DataTypeId::Boolean => "Boolean",
        DataTypeId::Byte => "Byte",
        DataTypeId::SByte => "SByte",
        DataTypeId::Int16 => "Int16",
        DataTypeId::UInt16 => "UInt16",
        DataTypeId::Int32 => "Int32",
        DataTypeId::UInt32 => "UInt32",
        DataTypeId::Int64 => "Int64",
        DataTypeId::UInt64 => "UInt64",
        DataTypeId::Float => "Float",
        DataTypeId::Double => "Double",
        DataTypeId::String => "String",
        DataTypeId::DateTime => "DateTime",
        DataTypeId::Guid => "Guid",

        DataTypeId::ByteString => "ByteString",
        DataTypeId::Duration => "Duration",
        DataTypeId::Integer => "Integer",
        DataTypeId::LocaleId => "LocaleId",
        DataTypeId::LocalizedText => "LocalizedText",
        DataTypeId::NodeId => "NodeId",
        DataTypeId::Number => "Number",
        DataTypeId::QualifiedName => "QualifiedName",
        DataTypeId::UInteger => "UInteger",
        DataTypeId::UtcTime => "UtcTime",
        DataTypeId::XmlElement => "XmlElement",
        DataTypeId::Decimal => "Decimal",
        DataTypeId::ImageBMP => "ImageBMP",
        DataTypeId::ImageGIF => "ImageGIF",
        DataTypeId::ImageJPG => "ImageJPG",
        DataTypeId::ImagePNG => "ImagePNG",

        _ => panic!(),
    }
}

/// Returns the default value for any particular type
pub fn scalar_default_value(id: DataTypeId) -> Variant {
    match id {
        DataTypeId::Boolean => false.into(),
        DataTypeId::Byte => 0u8.into(),
        DataTypeId::SByte => 0i8.into(),
        DataTypeId::Int16 => 0i16.into(),
        DataTypeId::UInt16 => 0u16.into(),
        DataTypeId::Int32 => 0i32.into(),
        DataTypeId::UInt32 => 0u32.into(),
        DataTypeId::Int64 => 0i64.into(),
        DataTypeId::UInt64 => 0u64.into(),
        DataTypeId::Float => 0f32.into(),
        DataTypeId::Double => 0f64.into(),
        DataTypeId::String => "".into(),
        DataTypeId::DateTime => DateTime::default().into(),
        DataTypeId::Guid => Guid::default().into(),

        DataTypeId::ByteString => ByteString::default().into(),
        DataTypeId::Duration => 0f64.into(),
        DataTypeId::LocaleId => "".into(),
        DataTypeId::LocalizedText => LocalizedText::default().into(),
        DataTypeId::NodeId => NodeId::null().into(),
        DataTypeId::QualifiedName => QualifiedName::null().into(),
        DataTypeId::UtcTime => DateTime::epoch().into(),
        DataTypeId::XmlElement => Variant::XmlElement(XmlElement::default()),
        DataTypeId::ImageBMP => ByteString::default().into(),
        DataTypeId::ImageGIF => ByteString::default().into(),
        DataTypeId::ImageJPG => ByteString::default().into(),
        DataTypeId::ImagePNG => ByteString::default().into(),

        _ => panic!(),
    }
}

/// Generates a randomized value of the appropriate type in a Variant
pub fn scalar_random_value(id: DataTypeId) -> Variant {
    let mut rng = rand::thread_rng();
    match id {
        DataTypeId::Boolean => rng.gen::<bool>().into(),
        DataTypeId::Byte => rng.gen::<u8>().into(),
        DataTypeId::SByte => rng.gen::<i8>().into(),
        DataTypeId::Int16 => rng.gen::<i16>().into(),
        DataTypeId::UInt16 => rng.gen::<u16>().into(),
        DataTypeId::Int32 => rng.gen::<i32>().into(),
        DataTypeId::UInt32 => rng.gen::<u32>().into(),
        DataTypeId::Int64 => rng.gen::<i64>().into(),
        DataTypeId::UInt64 => rng.gen::<u64>().into(),
        DataTypeId::Float => rng.gen::<f32>().into(),
        DataTypeId::Double => rng.gen::<f64>().into(),
        DataTypeId::String => {
            let s = (0..10)
                .map(|_| rng.sample(Alphanumeric))
                .collect::<String>();
            UAString::from(s).into()
        }
        DataTypeId::DateTime => {
            DateTime::from(rng.gen_range::<i64, i64, i64>(0, DateTime::endtimes_ticks())).into()
        }
        DataTypeId::Guid => Guid::new().into(),
        _ => scalar_default_value(id),
    }
}

/// Creates some sample variables, and some push / pull examples that update them
fn add_static_scalar_variables(server: &mut Server, ns: u16, static_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Scalar", "Scalar", &static_folder_id)
        .unwrap();

    for sn in SCALAR_TYPES.iter() {
        let name = scalar_name(*sn);
        let node_id = scalar_node_id(ns, *sn, false, false);
        VariableBuilder::new(&node_id, name, name)
            .data_type(sn)
            .value(scalar_default_value(*sn))
            .organized_by(&folder_id)
            .writable()
            .insert(&mut address_space);
    }
}

fn add_static_array_variables(server: &mut Server, ns: u16, static_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Array", "Array", &static_folder_id)
        .unwrap();

    SCALAR_TYPES.iter().for_each(|sn| {
        let node_id = scalar_node_id(ns, *sn, false, true);
        let name = scalar_name(*sn);
        let values = (0..100)
            .map(|_| scalar_default_value(*sn))
            .collect::<Vec<Variant>>();

        let value_type = values.get(0).unwrap().type_id();
        VariableBuilder::new(&node_id, name, name)
            .data_type(*sn)
            .value_rank(1)
            .value((value_type, values))
            .organized_by(&folder_id)
            .writable()
            .insert(&mut address_space);
    });
}

fn add_dynamic_scalar_variables(server: &mut Server, ns: u16, dynamic_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Scalar", "Scalar", &dynamic_folder_id)
        .unwrap();

    SCALAR_TYPES.iter().for_each(|sn| {
        let node_id = scalar_node_id(ns, *sn, true, false);
        let name = scalar_name(*sn);
        VariableBuilder::new(&node_id, name, name)
            .data_type(*sn)
            .value(scalar_default_value(*sn))
            .organized_by(&folder_id)
            .insert(&mut address_space);
    });
}

fn add_dynamic_array_variables(server: &mut Server, ns: u16, dynamic_folder_id: &NodeId) {
    // The address space is guarded so obtain a lock to change it
    let address_space = server.address_space();
    let mut address_space = address_space.write();

    // Create a folder under static folder
    let folder_id = address_space
        .add_folder("Array", "Array", &dynamic_folder_id)
        .unwrap();

    SCALAR_TYPES.iter().for_each(|sn| {
        let node_id = scalar_node_id(ns, *sn, true, true);
        let name = scalar_name(*sn);
        let values = (0..10)
            .map(|_| scalar_default_value(*sn))
            .collect::<Vec<Variant>>();
        let value_type = values.get(0).unwrap().type_id();
        VariableBuilder::new(&node_id, name, name)
            .data_type(*sn)
            .value_rank(1)
            .value((value_type, values))
            .organized_by(&folder_id)
            .insert(&mut address_space);
    });
}

fn set_dynamic_timers(server: &mut Server, ns: u16) {
    let address_space = server.address_space();

    // Standard change timers
    server.add_polling_action(250, move || {
        let mut address_space = address_space.write();
        // Scalar
        let now = DateTime::now();
        SCALAR_TYPES.iter().for_each(|sn| {
            let node_id = scalar_node_id(ns, *sn, true, false);
            let _ = address_space.set_variable_value_by_ref(
                &node_id,
                scalar_random_value(*sn),
                &now,
                &now,
            );

            let node_id = scalar_node_id(ns, *sn, true, true);
            let values = (0..10)
                .map(|_| scalar_random_value(*sn))
                .collect::<Vec<Variant>>();
            let value_type = values.get(0).unwrap().type_id();
            let _ =
                address_space.set_variable_value_by_ref(&node_id, (value_type, values), &now, &now);
        });
    });
}

pub fn add_stress_variables(server: &mut Server, ns: u16) {
    let node_ids = (0..1000)
        .map(|i| NodeId::new(ns, format!("v{:04}", i)))
        .collect::<Vec<NodeId>>();

    let address_space = server.address_space();
    let mut address_space = address_space.write();

    let folder_id = address_space
        .add_folder("Stress", "Stress", &NodeId::objects_folder_id())
        .unwrap();

    node_ids.iter().enumerate().for_each(|(i, node_id)| {
        let name = format!("v{:04}", i);
        VariableBuilder::new(&node_id, &name, &name)
            .data_type(DataTypeId::Int32)
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
        let mut address_space = address_space.write();
        let now = DateTime::now();
        node_ids.iter().for_each(|node_id| {
            let value: Variant = rng.gen::<i32>().into();
            let _ = address_space.set_variable_value_by_ref(node_id, value, &now, &now);
        });
    });
}
