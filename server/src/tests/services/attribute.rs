use super::*;
use services::attribute::AttributeService;
use address_space::access_level;

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
    let node_ids = {
        let mut address_space = server_state.address_space.lock().unwrap();
        let (_, node_ids) = add_many_vars_to_address_space(&mut address_space, 10);
        // Remove read access to [3] for a test below
        let node = address_space.find_node_mut(&node_ids[3]).unwrap();
        node.as_mut_node().set_attribute(AttributeId::AccessLevel, DataValue::new_byte(0));
        node_ids
    };

    let ats = AttributeService::new();

    {
        // Read a non existent variable
        let nodes_to_read = vec![
            // 1. a variable
            read_value(&node_ids[0], AttributeId::Value),
            // 2. an attribute other than value
            read_value(&node_ids[1], AttributeId::AccessLevel),
            // 3. a variable without the required attribute
            read_value(&node_ids[2], AttributeId::IsAbstract),
            // 4. a variable with no read access
            read_value(&node_ids[3], AttributeId::Value),
            // 5. a non existent variable
            read_value(&NodeId::new_string(1, "vxxx"), AttributeId::Value),
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

        // Verify expected values
        let results = response.results.unwrap();

        // 1. a variable
        assert_eq!(results[0].status.as_ref().unwrap(), &GOOD);
        assert_eq!(results[0].value.as_ref().unwrap(), &Variant::Int32(0));

        // 2. an attribute other than value (access level)
        assert_eq!(results[1].status.as_ref().unwrap(), &GOOD);
        assert_eq!(results[1].value.as_ref().unwrap(), &Variant::Byte(1));

        // 3. a variable without the required attribute
        assert_eq!(results[2].status.as_ref().unwrap(), &BAD_ATTRIBUTE_ID_INVALID);

        // 4. a variable with no read access
        assert_eq!(results[3].status.as_ref().unwrap(), &BAD_NOT_READABLE);

        // 5. Non existent
        assert_eq!(results[4].status.as_ref().unwrap(), &BAD_NODE_ID_UNKNOWN);
    }

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
    let node_ids = {
        let mut address_space = server_state.address_space.lock().unwrap();
        let (_, node_ids) = add_many_vars_to_address_space(&mut address_space, 10);
        // change variable access level so it cannot be written to
        for (i, node_id) in node_ids.iter().enumerate() {
            let node = address_space.find_node_mut(node_id).unwrap();
            if i == 2 {
                // No write access
                node.as_mut_node().set_attribute(AttributeId::AccessLevel, DataValue::new_byte(0));
            }
            else {
                // Write access
                node.as_mut_node().set_attribute(AttributeId::AccessLevel, DataValue::new_byte(access_level::CURRENT_WRITE));
            }
        }

        // change node with write access removed for a certain action
        let node = address_space.find_node_mut(&ReferenceTypeId::HasChild.as_node_id()).unwrap();
        // node.as_mut_node().set_write_mask(), IsAbstract 0

        node_ids
    };

    let ats = AttributeService::new();

    // test an empty write nothing to do

    let nodes_to_write = vec![
        // 1. a variable
        write_value(&node_ids[0], AttributeId::Value, DataValue::new_i32(100)),
        // 2. a variable without the required attribute
        write_value(&node_ids[1], AttributeId::IsAbstract, DataValue::new_bool(true)),
        // 3. a variable which has no write access
        write_value(&node_ids[2], AttributeId::Value, DataValue::new_i32(200)),
        // 4. a node of some kind other than variable
        write_value(&ReferenceTypeId::HasEncoding.as_node_id(), AttributeId::Value, DataValue::new_i32(200)),
        // 5. a node with some kind other than variable with no write mask
        write_value(&ReferenceTypeId::HasChild.as_node_id(), AttributeId::IsAbstract, DataValue::new_bool(false)),
        // 6. a non existent variable
        write_value(&NodeId::new_string(2, "vxxx"), AttributeId::Value, DataValue::new_i32(100)),
    ];

    let request = WriteRequest {
        request_header: make_request_header(),
        nodes_to_write: Some(nodes_to_write),
    };

    // do a write with the following write
    let response = ats.write(&mut server_state, &mut session, request);
    assert!(response.is_ok());
    let response: WriteResponse = supported_message_as!(response.unwrap(), WriteResponse);
    let results = response.results.unwrap();

    // 1. a variable
    // assert_eq!(results[0], GOOD);
    // 2. a variable without the required attribute
    // assert_eq!(results[1], BAD_ATTRIBUTE_ID_INVALID);
    // 3. a variable which has no write access
    // 4. a node of some kind other than variable
    // 5. a node with some kind other than variable with no write mask
    // 6. a non existent variable
    assert_eq!(results[5], BAD_NODE_ID_UNKNOWN);

    // write index range

    // distinguish between write and user write
    // test max_age
}
