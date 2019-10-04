//! A sample method

use opcua_server::{
    prelude::*,
    session::Session,
    address_space::method::MethodBuilder,
    callbacks,
};

pub fn add_methods(server: &mut Server) {
    let address_space = server.address_space();
    let mut address_space = address_space.write().unwrap();

    let object_id = NodeId::new(2, "Functions");
    ObjectBuilder::new(&object_id, "Functions", "Functions")
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut address_space);

    let fn_node_id = NodeId::new(2, "HelloWorld");
    MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
        .organized_by(object_id.clone())
        .insert(&mut address_space);

    // TODO this should go on the builder
    // e.g. .method_handler(object_id, fn_node_id, HelloWorld)
    address_space.register_method_handler(object_id, fn_node_id, Box::new(HelloWorld));
}

pub struct HelloWorld;

impl callbacks::Method for HelloWorld {
    fn call(&mut self, session: &mut Session, _request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![StatusCode::Good]),
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![Variant::from("Hello World!")]),
        })
    }
}
