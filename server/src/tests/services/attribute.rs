use super::*;
use services::attribute::AttributeService;
use address_space::constants::*;

fn read_value(node_id: &NodeId, attribute_id: AttributeId) -> ReadValueId {
    ReadValueId {
        node_id: node_id.clone(),
        attribute_id: attribute_id as UInt32,
        index_range: UAString::null(),
        data_encoding: QualifiedName::null()
    }
}

#[test]
fn read_test() {
    // Set up some nodes
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    // test an empty read nothing to do
    let parent_node_id = {
        let mut address_space = server_state.address_space.lock().unwrap();
        let parent_node_id = add_many_vars_to_address_space(&mut address_space, 10);

        // change variable access level so it cannot be read
        //let v3_node_id = NodeId::new_string(2, "v3");
        //let v3_node = address_space.find_node(&v3_node_id).unwrap();
        //v3_node.as_node().set_attribute(AttributeId::WriteMask, DataValue::new_byte(0));

        parent_node_id
    };

    let ats = AttributeService::new();

    // Read a non existent variable
    let nodes_to_read = vec![
        // a non existent variable
        read_value(&NodeId::new_string(2, "vxxx"), AttributeId::Value),
        // a variable
        read_value(&NodeId::new_string(2, "v1"), AttributeId::Value),
        // a node of some kind other than variable
        // another attribute
        read_value(&NodeId::new_string(2, "v2"), AttributeId::AccessLevel),
        // a variable without the required attribute
        read_value(&NodeId::new_string(2, "v2"), AttributeId::IsAbstract),
        // a variable with no read access
    ];
    let request = ReadRequest {
        request_header: make_request_header(),
        max_age: 0f64,
        timestamps_to_return: TimestampsToReturn::Both,
        nodes_to_read: Some(nodes_to_read),
    };

    let response = ats.read(&mut server_state, &mut session, request);
    assert!(response.is_ok());
    let response: ReadResponse = supported_message_as!(response.unwrap(), ReadResponse);

    // read index range

    // distinguish between read and user read
    // test max_age
    // test timestamps to return Server, Source, None, Both
}

fn write_value(node_id: &NodeId, attribute_id: AttributeId, value: DataValue) -> WriteValue {
    WriteValue {
        node_id: node_id.clone(),
        attribute_id: attribute_id as UInt32,
        index_range: UAString::null(),
        value,
    }
}

#[test]
fn write_test() {
    // Set up some nodes
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    // test an empty read nothing to do
    let parent_node_id = {
        let mut address_space = server_state.address_space.lock().unwrap();
        let parent_node_id = add_many_vars_to_address_space(&mut address_space, 10);

        // change variable access level so it cannot be written to
        //let v3_node_id = NodeId::new_string(2, "v3");
        //let v3_node = address_space.find_node(&v3_node_id).unwrap();
        //v3_node.as_node().set_attribute(AttributeId::WriteMask, DataValue::new_byte(0));

        parent_node_id
    };

    let ats = AttributeService::new();

    // test an empty write nothing to do

    let nodes_to_write = vec![
        // a non existent variable
        write_value(&NodeId::new_string(2, "vxxx"), AttributeId::Value, DataValue::new_i32(100)),
        // a variable
        write_value(&NodeId::new_string(2, "v1"), AttributeId::Value, DataValue::new_i32(100)),
        // a variable without the required attribute
        // a variable which has no write access
        // a node of some kind other than variable
    ];

    let request = WriteRequest {
        request_header: make_request_header(),
        nodes_to_write: Some(nodes_to_write),
    };

    // do a write with the following write
    let response = ats.write(&mut server_state, &mut session, request);
    assert!(response.is_ok());
    let response: WriteResponse = supported_message_as!(response.unwrap(), WriteResponse);

    // write index range

    // distinguish between write and user write
    // test max_age
}
