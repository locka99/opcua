use super::*;

use opcua_types::WriteMask;

use services::attribute::AttributeService;
use address_space::AccessLevel;

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

    // test an empty read nothing to do
    let node_ids = {
        let mut address_space = st.server.address_space.write().unwrap();
        let (_, node_ids) = add_many_vars_to_address_space(&mut address_space, 10);
        // Remove read access to [3] for a test below
        let node = address_space.find_node_mut(&node_ids[3]).unwrap();
        let r = node.as_mut_node().set_attribute(AttributeId::AccessLevel, DataValue::new(0 as Byte));
        assert!(r.is_ok());
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
            read_value(&NodeId::new(1, "vxxx"), AttributeId::Value),
        ];
        let request = ReadRequest {
            request_header: make_request_header(),
            max_age: 0f64,
            timestamps_to_return: TimestampsToReturn::Both,
            nodes_to_read: Some(nodes_to_read),
        };

        let address_space = st.server.address_space.read().unwrap();
        let response = ats.read(&address_space, request);
        assert!(response.is_ok());
        let response: ReadResponse = supported_message_as!(response.unwrap(), ReadResponse);

        // Verify expected values
        let results = response.results.unwrap();

        // 1. a variable
        assert_eq!(results[0].status.as_ref().unwrap(), &(Good as u32));
        assert_eq!(results[0].value.as_ref().unwrap(), &Variant::Int32(0));

        // 2. an attribute other than value (access level)
        assert_eq!(results[1].status.as_ref().unwrap(), &(Good as u32));
        assert_eq!(results[1].value.as_ref().unwrap(), &Variant::Byte(1));

        // 3. a variable without the required attribute
        assert_eq!(results[2].status.as_ref().unwrap(), &(BadAttributeIdInvalid as u32));

        // 4. a variable with no read access
        assert_eq!(results[3].status.as_ref().unwrap(), &(BadNotReadable as u32));

        // 5. Non existent
        assert_eq!(results[4].status.as_ref().unwrap(), &(BadNodeIdUnknown as u32));
    }


    // OTHER POTENTIAL TESTS

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

    // Create some variable nodes and modify permissions in the address space so we 
    // can see what happens when they are written to.
    let node_ids = {
        let mut address_space = st.server.address_space.write().unwrap();
        let (_, node_ids) = add_many_vars_to_address_space(&mut address_space, 10);
        // set up nodes for the tests to be performed to each
        for (i, node_id) in node_ids.iter().enumerate() {
            let node = address_space.find_node_mut(node_id).unwrap();
            match i {
                1 => {
                    // Add IsAbstract to WriteMask
                    node.as_mut_node().set_write_mask(WriteMask::IS_ABSTRACT);
                }
                2 => {
                    // No write access
                    let _ = node.as_mut_node().set_attribute(AttributeId::AccessLevel, DataValue::new(0u8)).unwrap();
                }
                6 => {
                    node.as_mut_node().set_write_mask(WriteMask::ACCESS_LEVEL);
                }
                _ => {
                    // Write access
                    let _ = node.as_mut_node().set_attribute(AttributeId::AccessLevel, DataValue::new(AccessLevel::CURRENT_WRITE.bits())).unwrap();
                }
            }
        }

        // change HasEncoding node with write access so response can be compared to HasChild which will be left alone
        let node = address_space.find_node_mut(&ReferenceTypeId::HasEncoding.into()).unwrap();
        node.as_mut_node().set_write_mask(WriteMask::IS_ABSTRACT);

        node_ids
    };

    let ats = AttributeService::new();

    // This is a cross section of variables and other kinds of nodes that we want to write to
    let nodes_to_write = vec![
        // 1. a variable value
        write_value(&node_ids[0], AttributeId::Value, DataValue::new(100 as Int32)),
        // 2. a variable with another attribute
        write_value(&node_ids[1], AttributeId::IsAbstract, DataValue::new(true)),
        // 3. a variable value which has no write access
        write_value(&node_ids[2], AttributeId::Value, DataValue::new(200 as Int32)),
        // 4. a node of some kind other than variable
        write_value(&ReferenceTypeId::HasEncoding.into(), AttributeId::IsAbstract, DataValue::new(false)),
        // 5. a node with some kind other than variable with no write mask
        write_value(&ReferenceTypeId::HasChild.into(), AttributeId::IsAbstract, DataValue::new(false)),
        // 6. a non existent variable
        write_value(&NodeId::new(2, "vxxx"), AttributeId::Value, DataValue::new(100 as Int32)),
        // 7. wrong type for attribute
        write_value(&node_ids[6], AttributeId::AccessLevel, DataValue::new(-1 as SByte)),
    ];

    let request = WriteRequest {
        request_header: make_request_header(),
        nodes_to_write: Some(nodes_to_write),
    };

    // do a write with the following write
    let mut address_space = st.server.address_space.write().unwrap();
    let response = ats.write(&mut address_space, request);
    assert!(response.is_ok());
    let response: WriteResponse = supported_message_as!(response.unwrap(), WriteResponse);
    let results = response.results.unwrap();

    // 1. a variable value
    assert_eq!(results[0], Good);
    // 2. a variable with another attribute
    assert_eq!(results[1], Good);
    // 3. a variable value which has no write access
    assert_eq!(results[2], BadNotWritable);
    // 4. a node of some kind other than variable
    assert_eq!(results[3], Good);
    // 5. a node with some kind other than variable with no write mask
    assert_eq!(results[4], BadNotWritable);
    // 6. a non existent variable
    assert_eq!(results[5], BadNodeIdUnknown);
    // 7. wrong type for attribute
    assert_eq!(results[6], BadTypeMismatch);

    // OTHER POTENTIAL TESTS

    // write index range
    // distinguish between write and user write
    // test max_age
}
