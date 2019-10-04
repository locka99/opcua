//! A sample method

use opcua_server::{
    address_space::method::MethodBuilder,
    callbacks,
    prelude::*,
    session::Session,
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
        .component_of(object_id.clone())
        .insert(&mut address_space);

    // Output arguments
    let output_args_id = NodeId::new(2, "OutputArguments");

    let output_args_value = vec![
        Variant::from(ExtensionObject::from_encodable(
            NodeId::new(0, 297), &Argument {
                name: UAString::from("Result"),
                data_type: DataTypeId::String.into(),
                value_rank: -1,
                array_dimensions: None,
                description: LocalizedText::new("", ""),
            })),
    ];

    VariableBuilder::new(&output_args_id, "OutputArguments", "OutputArguments")
        .property_of(fn_node_id.clone())
        .has_type_definition(VariableTypeId::PropertyType)
        .value(output_args_value)
        .insert(&mut address_space);

    // TODO this should go on the builder
    // e.g. .method_handler(object_id, fn_node_id, HelloWorld)
    address_space.register_method_handler(object_id, fn_node_id, Box::new(HelloWorld));
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
