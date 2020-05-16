// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2020 Adam Lock

//! A sample method

use opcua_server::{
    address_space::method::MethodBuilder,
    callbacks,
    prelude::*,
    session::Session,
};

pub fn add_methods(server: &mut Server, ns: u16) {
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    let object_id = NodeId::new(ns, "Functions");
    ObjectBuilder::new(&object_id, "Functions", "Functions")
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut address_space);

    let fn_node_id = NodeId::new(ns, "HelloWorld");
    MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
        .component_of(object_id.clone())
        .output_args(&mut address_space, &[
            ("Result", DataTypeId::String).into()
        ])
        .callback(Box::new(HelloWorld))
        .insert(&mut address_space);
}

pub struct HelloWorld;

impl callbacks::Method for HelloWorld {
    fn call(&mut self, _session: &mut Session, _request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![StatusCode::Good]),
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![Variant::from("Hello World!")]),
        })
    }
}
