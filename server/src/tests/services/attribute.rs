use chrono::Duration;

use opcua_types::{Variant, WriteMask};

use crate::{
    address_space::AccessLevel,
    services::attribute::AttributeService,
};

use super::*;

fn read_value(node_id: &NodeId, attribute_id: AttributeId) -> ReadValueId {
    ReadValueId {
        node_id: node_id.clone(),
        attribute_id: attribute_id as u32,
        index_range: UAString::null(),
        data_encoding: QualifiedName::null(), // TODO
    }
}

fn do_attribute_service_test<F>(f: F)
    where F: FnOnce(Arc<RwLock<ServerState>>, Arc<RwLock<Session>>, Arc<RwLock<AddressSpace>>, &AttributeService)
{
    // Set up some nodes
    let st = ServiceTest::new();
    f(st.server_state.clone(), st.session.clone(), st.address_space.clone(), &AttributeService::new())
}

#[test]
fn read() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // set up some nodes
        let node_ids = {
            let (_, node_ids) = add_many_vars_to_address_space(address_space.clone(), 10);
            let mut address_space = trace_write_lock_unwrap!(address_space);
            // Remove read access to [3] for a test below
            let node = address_space.find_node_mut(&node_ids[3]).unwrap();
            let r = node.as_mut_node().set_attribute(AttributeId::UserAccessLevel, Variant::from(0u8));
            assert!(r.is_ok());
            node_ids
        };

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

            let response = ats.read(server_state, session, address_space, &request);
            let response: ReadResponse = supported_message_as!(response, ReadResponse);

            // Verify expected values
            let results = response.results.unwrap();

            // 1. a variable
            assert_eq!(results[0].status.as_ref().unwrap(), &StatusCode::Good);
            assert_eq!(results[0].value.as_ref().unwrap(), &Variant::Int32(0));

            // 2. an attribute other than value (access level)
            //assert_eq!(results[1].status.as_ref().unwrap(), &(StatusCode::Good.bits()));
            assert_eq!(results[1].value.as_ref().unwrap(), &Variant::Byte(1));

            // 3. a variable without the required attribute
            assert_eq!(results[2].status.as_ref().unwrap(), &StatusCode::BadAttributeIdInvalid);

            // 4. a variable with no read access
            assert_eq!(results[3].status.as_ref().unwrap(), &StatusCode::BadNotReadable);

            // 5. Non existent
            assert_eq!(results[4].status.as_ref().unwrap(), &StatusCode::BadNodeIdUnknown);
        }


        // OTHER POTENTIAL TESTS

        // read index range
        // distinguish between read and user read
        // test max_age
        // test timestamps to return Server, Source, None, Both
    });
}

fn write_value(node_id: &NodeId, attribute_id: AttributeId, value: DataValue) -> WriteValue {
    WriteValue {
        node_id: node_id.clone(),
        attribute_id: attribute_id as u32,
        index_range: UAString::null(),
        value,
    }
}

#[test]
fn write() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Set up some nodes
        // Create some variable nodes and modify permissions in the address space so we
        // can see what happens when they are written to.
        let node_ids = {
            let (_, node_ids) = add_many_vars_to_address_space(address_space.clone(), 10);
            let mut address_space = trace_write_lock_unwrap!(address_space);
            // set up nodes for the tests to be performed to each
            for (i, node_id) in node_ids.iter().enumerate() {
                let node = address_space.find_node_mut(node_id).unwrap();
                match i {
                    1 => {
                        // Add IsAbstract to WriteMask
                        node.as_mut_node().set_write_mask(WriteMask::IS_ABSTRACT);
                    }
                    2 => {
                        // Remove write access to the value by setting access level to 0
                        let _ = node.as_mut_node().set_attribute(AttributeId::UserAccessLevel, Variant::from(0u8)).unwrap();
                    }
                    6 => {
                        node.as_mut_node().set_write_mask(WriteMask::ACCESS_LEVEL);
                    }
                    _ => {
                        // Write access
                        let _ = node.as_mut_node().set_attribute(AttributeId::AccessLevel, Variant::from(AccessLevel::CURRENT_WRITE.bits())).unwrap();
                        let _ = node.as_mut_node().set_attribute(AttributeId::UserAccessLevel, Variant::from(UserAccessLevel::CURRENT_WRITE.bits())).unwrap();
                    }
                }
            }

            // change HasEncoding node with write access so response can be compared to HasChild which will be left alone
            let node = address_space.find_node_mut(&ReferenceTypeId::HasEncoding.into()).unwrap();
            node.as_mut_node().set_write_mask(WriteMask::IS_ABSTRACT);

            node_ids
        };

        // This is a cross section of variables and other kinds of nodes that we want to write to
        let nodes_to_write = vec![
            // 1. a variable value
            write_value(&node_ids[0], AttributeId::Value, DataValue::new(100 as i32)),
            // 2. a variable with a bad attribute (IsAbstract doesn't exist on a var)
            write_value(&node_ids[1], AttributeId::IsAbstract, DataValue::new(true)),
            // 3. a variable value which has no write access
            write_value(&node_ids[2], AttributeId::Value, DataValue::new(200 as i32)),
            // 4. a node of some kind other than variable
            write_value(&ReferenceTypeId::HasEncoding.into(), AttributeId::IsAbstract, DataValue::new(false)),
            // 5. a node with some kind other than variable with no write mask
            write_value(&ReferenceTypeId::HasChild.into(), AttributeId::IsAbstract, DataValue::new(false)),
            // 6. a non existent variable
            write_value(&NodeId::new(2, "vxxx"), AttributeId::Value, DataValue::new(100i32)),
            // 7. wrong type for attribute
            write_value(&node_ids[6], AttributeId::AccessLevel, DataValue::new(-1i8)),
        ];

        let request = WriteRequest {
            request_header: make_request_header(),
            nodes_to_write: Some(nodes_to_write),
        };

        // do a write with the following write
        let response = ats.write(server_state, session, address_space, &request);
        let response: WriteResponse = supported_message_as!(response, WriteResponse);
        let results = response.results.unwrap();

        // 1. a variable value
        assert_eq!(results[0], StatusCode::Good);
        // 2. a variable with invalid attribute
        assert_eq!(results[1], StatusCode::BadAttributeIdInvalid);
        // 3. a variable value which has no write access
        assert_eq!(results[2], StatusCode::BadNotWritable);
        // 4. a node of some kind other than variable
        assert_eq!(results[3], StatusCode::Good);
        // 5. a node with some kind other than variable with no write mask
        assert_eq!(results[4], StatusCode::BadNotWritable);
        // 6. a non existent variable
        assert_eq!(results[5], StatusCode::BadNodeIdUnknown);
        // 7. wrong type for attribute
        assert_eq!(results[6], StatusCode::BadTypeMismatch);

        // OTHER POTENTIAL TESTS

        // write index range
        // distinguish between write and user write
        // test max_age
    });
}

struct DataProvider;

impl HistoricalDataProvider for DataProvider {
    fn read_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, _request: ReadRawModifiedDetails, _timestamps_to_return: TimestampsToReturn, _release_continuation_points: bool, _nodes_to_read: &[HistoryReadValueId]) -> Result<Vec<HistoryReadResult>, StatusCode> {
        info!("DataProvider's read_raw_modified_details");
        Ok(DataProvider::historical_read_result())
    }

    fn delete_raw_modified_details(&self, _address_space: Arc<RwLock<AddressSpace>>, request: DeleteRawModifiedDetails) -> Result<Vec<StatusCode>, StatusCode> {
        info!("DataProvider's delete_raw_modified_details");
        Ok(vec![StatusCode::Good])
    }
}

impl DataProvider {
    pub fn historical_read_result() -> Vec<HistoryReadResult> {
        vec![
            HistoryReadResult {
                status_code: StatusCode::Good,
                continuation_point: ByteString::null(),
                history_data: ExtensionObject::null(),
            }]
    }
}

fn nodes_to_read() -> Vec<HistoryReadValueId> {
    vec![
        HistoryReadValueId {
            node_id: NodeId::new(2, "test"),
            index_range: UAString::null(),
            data_encoding: QualifiedName::null(), // TODO
            continuation_point: ByteString::null(),
        }
    ]
}

fn read_raw_modified_details() -> ReadRawModifiedDetails {
    // Register a history data provider
    let now = chrono::Utc::now();
    let start_time = (now - Duration::days(5)).into();
    let end_time = now.into();

    ReadRawModifiedDetails {
        is_read_modified: true,
        start_time,
        end_time,
        num_values_per_node: 100u32,
        return_bounds: true,
    }
}

#[test]
fn history_read_nothing_to_do_1() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Register a history data provider
        // Send a valid read details command but with no nodes to read
        let read_raw_modified_details = read_raw_modified_details();
        let history_read_details = ExtensionObject::from_encodable(ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary, &read_raw_modified_details);
        let request = HistoryReadRequest {
            request_header: make_request_header(),
            history_read_details,
            timestamps_to_return: TimestampsToReturn::Both,
            release_continuation_points: true,
            nodes_to_read: None,
        };
        let response: ServiceFault = supported_message_as!(ats.history_read(server_state, session, address_space.clone(), &request), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);
    });
}

#[test]
fn history_read_nothing_history_operation_invalid() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Send a command with an invalid extension object
        let request = HistoryReadRequest {
            request_header: make_request_header(),
            history_read_details: ExtensionObject::null(),
            timestamps_to_return: TimestampsToReturn::Both,
            release_continuation_points: true,
            nodes_to_read: Some(nodes_to_read()),
        };
        let response: ServiceFault = supported_message_as!(ats.history_read(server_state, session, address_space, &request), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadHistoryOperationInvalid);
    });
}

#[test]
fn history_read_nothing_data_provider() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        {
            let mut server_state = server_state.write().unwrap();
            let data_provider = DataProvider;
            server_state.set_historical_data_provider(Box::new(data_provider));
        }

        // Call ReadRawModifiedDetails on the registered callback and expect a call back
        let read_raw_modified_details = read_raw_modified_details();
        let history_read_details = ExtensionObject::from_encodable(ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary, &read_raw_modified_details);
        let request = HistoryReadRequest {
            request_header: make_request_header(),
            history_read_details,
            timestamps_to_return: TimestampsToReturn::Both,
            release_continuation_points: true,
            nodes_to_read: Some(nodes_to_read()),
        };
        let response: HistoryReadResponse = supported_message_as!(ats.history_read(server_state, session, address_space, &request), HistoryReadResponse);
        let expected_read_result = DataProvider::historical_read_result();
        assert_eq!(response.results, Some(expected_read_result));
    });
}

fn delete_raw_modified_details() -> DeleteRawModifiedDetails {
    let now = chrono::Utc::now();
    let start_time = (now - Duration::days(5)).into();
    let end_time = now.into();
    DeleteRawModifiedDetails {
        node_id: NodeId::new(2, 100),
        is_delete_modified: true,
        start_time,
        end_time,
    }
}

#[test]
fn history_update_nothing_to_do_1() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Nothing to do
        let request = HistoryUpdateRequest {
            request_header: make_request_header(),
            history_update_details: None,
        };
        let response: ServiceFault = supported_message_as!(ats.history_update(server_state, session, address_space, &request), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);
    });
}

#[test]
fn history_update_nothing_to_do_2() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Nothing to do /2
        let request = HistoryUpdateRequest {
            request_header: make_request_header(),
            history_update_details: Some(vec![]),
        };
        let response: ServiceFault = supported_message_as!(ats.history_update(server_state, session, address_space, &request), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);
    });
}

#[test]
fn history_update_history_operation_invalid() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Invalid extension object
        let request = HistoryUpdateRequest {
            request_header: make_request_header(),
            history_update_details: Some(vec![ExtensionObject::null()]),
        };
        let response: HistoryUpdateResponse = supported_message_as!(ats.history_update(server_state, session, address_space, &request), HistoryUpdateResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);

        let result1 = &results[0];
        assert_eq!(result1.status_code, StatusCode::BadHistoryOperationInvalid);
    });
}

#[test]
fn history_update_history_operation_unsupported() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Create an update action
        let delete_raw_modified_details = delete_raw_modified_details();

        // Unsupported operation (everything by default)
        let history_update_details = ExtensionObject::from_encodable(ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary, &delete_raw_modified_details);
        let request = HistoryUpdateRequest {
            request_header: make_request_header(),
            history_update_details: Some(vec![history_update_details]),
        };
        let response: HistoryUpdateResponse = supported_message_as!(ats.history_update(server_state, session, address_space, &request), HistoryUpdateResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);

        let result1 = &results[0];
        assert_eq!(result1.status_code, StatusCode::BadHistoryOperationUnsupported);
    });
}

#[test]
fn history_update_data_provider() {
    do_attribute_service_test(|server_state, session, address_space, ats| {
        // Register a data provider
        {
            let mut server_state = server_state.write().unwrap();
            let data_provider = DataProvider;
            server_state.set_historical_data_provider(Box::new(data_provider));
        }

        let delete_raw_modified_details = delete_raw_modified_details();

        // Supported operation
        let history_update_details = ExtensionObject::from_encodable(ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary, &delete_raw_modified_details);
        let request = HistoryUpdateRequest {
            request_header: make_request_header(),
            history_update_details: Some(vec![history_update_details]),
        };
        let response: HistoryUpdateResponse = supported_message_as!(ats.history_update(server_state, session, address_space, &request), HistoryUpdateResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);

        let result1 = &results[0];
        assert_eq!(result1.status_code, StatusCode::Good);
    });
}