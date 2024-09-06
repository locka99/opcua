// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! A sample method

use std::sync::Arc;

use opcua::{
    server::{
        address_space::{EventNotifier, MethodBuilder, ObjectBuilder},
        node_manager::memory::SimpleNodeManager,
    },
    types::{DataTypeId, NodeId, ObjectId, StatusCode, Variant},
};

pub fn add_methods(manager: Arc<SimpleNodeManager>, ns: u16) {
    let address_space = manager.address_space();
    let mut address_space = address_space.write();

    let object_id = NodeId::new(ns, "Functions");
    ObjectBuilder::new(&object_id, "Functions", "Functions")
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut address_space);

    // NoOp has 0 inputs and 0 outputs
    let fn_node_id = NodeId::new(ns, "NoOp");
    MethodBuilder::new(&fn_node_id, "NoOp", "NoOp")
        .component_of(object_id.clone())
        .executable(true)
        .user_executable(true)
        .insert(&mut address_space);
    manager.inner().add_method_callback(fn_node_id, |_| {
        debug!("NoOp method called");
        Ok(Vec::new())
    });

    // HelloWorld has 0 inputs and 1 output - returns "Hello World" in a result parameter
    let fn_node_id = NodeId::new(ns, "HelloWorld");
    MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
        .component_of(object_id.clone())
        .executable(true)
        .user_executable(true)
        .output_args(
            &mut address_space,
            &NodeId::new(ns, "HelloWorldOutput"),
            &[("Result", DataTypeId::String).into()],
        )
        .insert(&mut address_space);
    manager.inner().add_method_callback(fn_node_id, |_| {
        debug!("HelloWorld method called");
        Ok(vec![Variant::from("Hello World!".to_owned())])
    });

    // HelloX has 1 one input and 1 output - "Hello Foo" in a result parameter
    let fn_node_id = NodeId::new(ns, "HelloX");
    MethodBuilder::new(&fn_node_id, "HelloX", "HelloX")
        .component_of(object_id.clone())
        .executable(true)
        .user_executable(true)
        .input_args(
            &mut address_space,
            &NodeId::new(ns, "HelloXInput"),
            &[("YourName", DataTypeId::String).into()],
        )
        .output_args(
            &mut address_space,
            &NodeId::new(ns, "HelloXOutput"),
            &[("Result", DataTypeId::String).into()],
        )
        .insert(&mut address_space);
    manager.inner().add_method_callback(fn_node_id, |args| {
        // We don't actually need to do much validation here, since it should all have happened elsewhere,
        // but we don't want to panic if something goes wrong.
        let Some(Variant::String(s)) = args.get(0) else {
            return Err(StatusCode::BadTypeMismatch);
        };

        Ok(vec![Variant::String(
            format!("Hello {}!", s.as_ref()).into(),
        )])
    });

    // Boop has 1 one input and 0 output
    let fn_node_id = NodeId::new(ns, "Boop");
    MethodBuilder::new(&fn_node_id, "Boop", "Boop")
        .component_of(object_id.clone())
        .executable(true)
        .user_executable(true)
        .input_args(
            &mut address_space,
            &NodeId::new(ns, "BoopInput"),
            &[("Ping", DataTypeId::String).into()],
        )
        .insert(&mut address_space);

    manager.inner().add_method_callback(fn_node_id, |args| {
        let Some(Variant::String(_)) = args.get(0) else {
            return Err(StatusCode::BadInvalidArgument);
        };
        Ok(Vec::new())
    });
}
