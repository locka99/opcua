// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! A sample method

use opcua_server::{
    address_space::method::MethodBuilder, callbacks, prelude::*, session::Session,
};

pub fn add_methods(server: &mut Server, ns: u16) {
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    let object_id = NodeId::new(ns, "Functions");
    ObjectBuilder::new(&object_id, "Functions", "Functions")
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut address_space);

    // NoOp has 0 inputs and 0 outputs
    let fn_node_id = NodeId::new(ns, "NoOp");
    MethodBuilder::new(&fn_node_id, "NoOp", "NoOp")
        .component_of(object_id.clone())
        .callback(Box::new(NoOp))
        .insert(&mut address_space);

    // HelloWorld has 0 inputs and 1 output - returns "Hello World" in a result parameter
    let fn_node_id = NodeId::new(ns, "HelloWorld");
    MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
        .component_of(object_id.clone())
        .output_args(&mut address_space, &[("Result", DataTypeId::String).into()])
        .callback(Box::new(HelloWorld))
        .insert(&mut address_space);

    // HelloX has 1 one input and 1 output - "Hello Foo" in a result parameter
    let fn_node_id = NodeId::new(ns, "HelloX");
    MethodBuilder::new(&fn_node_id, "HelloX", "HelloX")
        .component_of(object_id.clone())
        .input_args(
            &mut address_space,
            &[("YourName", DataTypeId::String).into()],
        )
        .output_args(&mut address_space, &[("Result", DataTypeId::String).into()])
        .callback(Box::new(HelloX))
        .insert(&mut address_space);

    // Boop has 1 one input and 0 output
    let fn_node_id = NodeId::new(ns, "Boop");
    MethodBuilder::new(&fn_node_id, "Boop", "Boop")
        .component_of(object_id.clone())
        .input_args(&mut address_space, &[("Ping", DataTypeId::String).into()])
        .callback(Box::new(HelloX))
        .insert(&mut address_space);
}

struct NoOp;

impl callbacks::Method for NoOp {
    fn call(
        &mut self,
        _session: &mut Session,
        _request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: None,
            input_argument_diagnostic_infos: None,
            output_arguments: None,
        })
    }
}

struct Boop;

impl callbacks::Method for Boop {
    fn call(
        &mut self,
        _session: &mut Session,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        // Validate input to be a string
        let in1_result = if let Some(ref input_arguments) = request.input_arguments {
            if let Some(in1) = input_arguments.get(0) {
                if let Variant::String(_) = in1 {
                    StatusCode::Good
                } else {
                    StatusCode::BadInvalidArgument
                }
            } else if input_arguments.len() == 0 {
                StatusCode::BadArgumentsMissing
            } else {
                // Shouldn't get here because there is 1 argument
                StatusCode::BadTooManyArguments
            }
        } else {
            StatusCode::BadArgumentsMissing
        };
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![in1_result]),
            input_argument_diagnostic_infos: None,
            output_arguments: None,
        })
    }
}
struct HelloWorld;

impl callbacks::Method for HelloWorld {
    fn call(
        &mut self,
        _session: &mut Session,
        _request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        let message = format!("Hello World!");
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: None,
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![Variant::from(message)]),
        })
    }
}

struct HelloX;

impl callbacks::Method for HelloX {
    fn call(
        &mut self,
        _session: &mut Session,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        // Validate input to be a string
        let mut out1 = Variant::Empty;
        let in1_result = if let Some(ref input_arguments) = request.input_arguments {
            if let Some(in1) = input_arguments.get(0) {
                if let Variant::String(in1) = in1 {
                    out1 = Variant::from(format!("Hello {}!", &in1));
                    StatusCode::Good
                } else {
                    StatusCode::BadInvalidArgument
                }
            } else if input_arguments.len() == 0 {
                StatusCode::BadArgumentsMissing
            } else {
                // Shouldn't get here because there is 1 argument
                StatusCode::BadTooManyArguments
            }
        } else {
            StatusCode::BadArgumentsMissing
        };
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![in1_result]),
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![out1]),
        })
    }
}
