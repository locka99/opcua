use chrono::TimeDelta;
use opcua::{
    async_server::address_space::{
        AccessLevel, DataTypeBuilder, EventNotifier, MethodBuilder, ObjectBuilder,
        ObjectTypeBuilder, ReferenceTypeBuilder, UserAccessLevel, VariableBuilder,
        VariableTypeBuilder, ViewBuilder,
    },
    client::HistoryReadAction,
    types::{
        AttributeId, DataTypeId, DataValue, DateTime, HistoryData, HistoryReadValueId, NodeClass,
        NodeId, ObjectId, ObjectTypeId, ReadRawModifiedDetails, ReferenceTypeId, StatusCode,
        TimestampsToReturn, VariableId, VariableTypeId, Variant, WriteMask,
    },
};
use utils::{read_value_id, read_value_ids, setup};

mod utils;

fn array_value(v: &DataValue) -> &Vec<Variant> {
    let v = match v.value.as_ref().unwrap() {
        Variant::Array(a) => a,
        _ => panic!("Expected array"),
    };
    &v.values
}

#[tokio::test]
async fn read() {
    let (tester, _nm, session) = setup().await;

    // Read the service level
    tester.handle.set_service_level(123);
    let r = session
        .read(
            &[read_value_id(
                AttributeId::Value,
                VariableId::Server_ServiceLevel,
            )],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(1, r.len());
    assert_eq!(&Variant::Byte(123), r[0].value.as_ref().unwrap())
}

#[tokio::test]
async fn read_variable() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .historizing(true)
            .array_dimensions(&[2])
            .value(vec![1, 2])
            .description("Description")
            .value_rank(1)
            .data_type(DataTypeId::Int32)
            .access_level(AccessLevel::CURRENT_READ)
            .user_access_level(UserAccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Value,
                    AttributeId::Historizing,
                    AttributeId::ArrayDimensions,
                    AttributeId::Description,
                    AttributeId::ValueRank,
                    AttributeId::DataType,
                    AttributeId::AccessLevel,
                    AttributeId::UserAccessLevel,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        array_value(&r[0]),
        &vec![Variant::Int32(1), Variant::Int32(2)]
    );
    assert_eq!(r[1].value, Some(Variant::Boolean(true)));
    assert_eq!(array_value(&r[2]), &vec![Variant::UInt32(2)]);
    assert_eq!(
        r[3].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(r[4].value, Some(Variant::Int32(1)));
    assert_eq!(
        r[5].value,
        Some(Variant::NodeId(Box::new(DataTypeId::Int32.into())))
    );
    assert_eq!(r[6].value, Some(Variant::Byte(1)));
    assert_eq!(r[7].value, Some(Variant::Byte(1)));
    assert_eq!(
        r[8].value,
        Some(Variant::LocalizedText(Box::new("TestVar1".into())))
    );
    assert_eq!(
        r[9].value,
        Some(Variant::QualifiedName(Box::new("TestVar1".into())))
    );
    assert_eq!(
        r[10].value,
        Some(Variant::Int32(NodeClass::Variable as i32))
    );
    assert_eq!(r[11].value, Some(Variant::NodeId(Box::new(id))));
}

#[tokio::test]
async fn read_object() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&id, "TestObj1", "TestObj1")
            .description("Description")
            .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::EventNotifier,
                    AttributeId::WriteMask,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new("TestObj1".into())))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new("TestObj1".into())))
    );
    assert_eq!(r[3].value, Some(Variant::Int32(NodeClass::Object as i32)));
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::Byte(EventNotifier::SUBSCRIBE_TO_EVENTS.bits()))
    );
    assert_eq!(
        r[6].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
}

#[tokio::test]
async fn read_view() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ViewBuilder::new(&id, "TestView1", "TestView1")
            .description("Description")
            .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
            .contains_no_loops(true)
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::EventNotifier,
                    AttributeId::WriteMask,
                    AttributeId::ContainsNoLoops,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new("TestView1".into())))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new("TestView1".into())))
    );
    assert_eq!(r[3].value, Some(Variant::Int32(NodeClass::View as i32)));
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::Byte(EventNotifier::SUBSCRIBE_TO_EVENTS.bits()))
    );
    assert_eq!(
        r[6].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
    assert_eq!(r[7].value, Some(Variant::Boolean(true)));
}

#[tokio::test]
async fn read_method() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        MethodBuilder::new(&id, "TestMethod1", "TestMethod1")
            .description("Description")
            .executable(true)
            .user_executable(false)
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::WriteMask,
                    AttributeId::Executable,
                    AttributeId::UserExecutable,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new("TestMethod1".into())))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new("TestMethod1".into())))
    );
    assert_eq!(r[3].value, Some(Variant::Int32(NodeClass::Method as i32)));
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
    assert_eq!(r[6].value, Some(Variant::Boolean(true)));
    assert_eq!(r[7].value, Some(Variant::Boolean(false)));
}

#[tokio::test]
async fn read_object_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectTypeBuilder::new(&id, "TestObjectType1", "TestObjectType1")
            .description("Description")
            .is_abstract(true)
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &ObjectTypeId::BaseObjectType.into(),
        &ReferenceTypeId::HasSubtype.into(),
        None,
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::WriteMask,
                    AttributeId::IsAbstract,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new("TestObjectType1".into())))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new("TestObjectType1".into())))
    );
    assert_eq!(
        r[3].value,
        Some(Variant::Int32(NodeClass::ObjectType as i32))
    );
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
    assert_eq!(r[6].value, Some(Variant::Boolean(true)));
}

#[tokio::test]
async fn read_variable_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableTypeBuilder::new(&id, "TestVariableType1", "TestVariableType1")
            .description("Description")
            .is_abstract(true)
            .data_type(DataTypeId::Int32)
            .array_dimensions(&[2])
            .value(vec![1, 2])
            .value_rank(1)
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &ObjectTypeId::BaseObjectType.into(),
        &ReferenceTypeId::HasSubtype.into(),
        None,
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::WriteMask,
                    AttributeId::IsAbstract,
                    AttributeId::DataType,
                    AttributeId::ArrayDimensions,
                    AttributeId::ValueRank,
                    AttributeId::Value,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new("TestVariableType1".into())))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new("TestVariableType1".into())))
    );
    assert_eq!(
        r[3].value,
        Some(Variant::Int32(NodeClass::VariableType as i32))
    );
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
    assert_eq!(r[6].value, Some(Variant::Boolean(true)));
    assert_eq!(
        r[7].value,
        Some(Variant::NodeId(Box::new(DataTypeId::Int32.into())))
    );
    assert_eq!(array_value(&r[8]), &vec![Variant::UInt32(2)]);
    assert_eq!(r[9].value, Some(Variant::Int32(1)));
    assert_eq!(
        array_value(&r[10]),
        &vec![Variant::Int32(1), Variant::Int32(2)]
    );
}

#[tokio::test]
async fn read_data_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        DataTypeBuilder::new(&id, "TestDataType1", "TestDataType1")
            .description("Description")
            .is_abstract(true)
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &DataTypeId::BaseDataType.into(),
        &ReferenceTypeId::HasSubtype.into(),
        None,
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::WriteMask,
                    AttributeId::IsAbstract,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new("TestDataType1".into())))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new("TestDataType1".into())))
    );
    assert_eq!(r[3].value, Some(Variant::Int32(NodeClass::DataType as i32)));
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
    assert_eq!(r[6].value, Some(Variant::Boolean(true)));
}

#[tokio::test]
async fn read_reference_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ReferenceTypeBuilder::new(&id, "TestReferenceType1", "TestReferenceType1")
            .description("Description")
            .is_abstract(true)
            .symmetric(true)
            .inverse_name("Inverse")
            .write_mask(WriteMask::DISPLAY_NAME)
            .build()
            .into(),
        &ReferenceTypeId::References.into(),
        &ReferenceTypeId::HasSubtype.into(),
        None,
        Vec::new(),
    );

    let r = session
        .read(
            &read_value_ids(
                &[
                    AttributeId::Description,
                    AttributeId::DisplayName,
                    AttributeId::BrowseName,
                    AttributeId::NodeClass,
                    AttributeId::NodeId,
                    AttributeId::WriteMask,
                    AttributeId::IsAbstract,
                    AttributeId::Symmetric,
                    AttributeId::InverseName,
                ],
                &id,
            ),
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("Description".into())))
    );
    assert_eq!(
        r[1].value,
        Some(Variant::LocalizedText(Box::new(
            "TestReferenceType1".into()
        )))
    );
    assert_eq!(
        r[2].value,
        Some(Variant::QualifiedName(Box::new(
            "TestReferenceType1".into()
        )))
    );
    assert_eq!(
        r[3].value,
        Some(Variant::Int32(NodeClass::ReferenceType as i32))
    );
    assert_eq!(r[4].value, Some(Variant::NodeId(Box::new(id))));
    assert_eq!(
        r[5].value,
        Some(Variant::UInt32(WriteMask::DISPLAY_NAME.bits()))
    );
    assert_eq!(r[6].value, Some(Variant::Boolean(true)));
    assert_eq!(r[7].value, Some(Variant::Boolean(true)));
    assert_eq!(
        r[8].value,
        Some(Variant::LocalizedText(Box::new("Inverse".into())))
    );
}

#[tokio::test]
async fn read_mixed() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .historizing(true)
            .value("value")
            .description("Description")
            .value_rank(1)
            .data_type(DataTypeId::String)
            .access_level(AccessLevel::CURRENT_READ)
            .user_access_level(UserAccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    // Read from various nodes in different node managers
    tester.handle.set_service_level(200);
    let r = session
        .read(
            &[
                read_value_id(AttributeId::DisplayName, &id),
                read_value_id(AttributeId::Value, &id),
                read_value_id(AttributeId::Value, VariableId::Server_ServiceLevel),
                read_value_id(AttributeId::DisplayName, ObjectId::Server),
                // Wrong attribute
                read_value_id(AttributeId::Value, ObjectId::Server),
                // Invalid node, valid namespace
                read_value_id(AttributeId::Value, nm.inner().next_node_id()),
                // Invalid namespace
                read_value_id(AttributeId::Value, NodeId::new(100, 1)),
            ],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(
        r[0].value,
        Some(Variant::LocalizedText(Box::new("TestVar1".into())))
    );
    assert_eq!(r[1].value, Some(Variant::String("value".into())));
    assert_eq!(r[2].value, Some(Variant::Byte(200)));
    assert_eq!(
        r[3].value,
        Some(Variant::LocalizedText(Box::new("Server".into())))
    );
    assert_eq!(r[4].status, Some(StatusCode::BadAttributeIdInvalid));
    assert_eq!(r[4].value, None);
    assert_eq!(r[5].status, Some(StatusCode::BadNodeIdUnknown));
    assert_eq!(r[5].value, None);
    assert_eq!(r[6].status, Some(StatusCode::BadNodeIdUnknown));
    assert_eq!(r[6].value, None);
}

#[tokio::test]
async fn read_limits() {
    let (tester, _nm, session) = setup().await;

    let read_limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_nodes_per_read;

    // Read zero
    let r = session
        .read(&[], TimestampsToReturn::Both, 0.0)
        .await
        .unwrap_err();
    assert_eq!(r, StatusCode::BadNothingToDo);

    // Invalid max age
    let r = session
        .read(
            &[read_value_id(AttributeId::DisplayName, ObjectId::Server)],
            TimestampsToReturn::Both,
            -15.0,
        )
        .await
        .unwrap_err();
    assert_eq!(r, StatusCode::BadMaxAgeInvalid);

    // Invalid timestamps to return
    let r = session
        .read(
            &[read_value_id(AttributeId::DisplayName, ObjectId::Server)],
            TimestampsToReturn::Invalid,
            0.0,
        )
        .await
        .unwrap_err();
    assert_eq!(r, StatusCode::BadTimestampsToReturnInvalid);

    // Too many operations
    let ops: Vec<_> = (0..(read_limit + 1))
        .map(|r| read_value_id(AttributeId::Value, NodeId::new(2, r as i32)))
        .collect();
    let r = session
        .read(&ops, TimestampsToReturn::Both, 0.0)
        .await
        .unwrap_err();
    assert_eq!(r, StatusCode::BadTooManyOperations);

    // Exact number of operations, should not fail, though the reads will probably fail, mostly.
    let ops: Vec<_> = (0..read_limit)
        .map(|r| read_value_id(AttributeId::Value, NodeId::new(2, r as i32)))
        .collect();
    session
        .read(&ops, TimestampsToReturn::Both, 0.0)
        .await
        .unwrap();
}

#[tokio::test]
async fn history_read_raw() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .historizing(true)
            .value(0)
            .description("Description")
            .data_type(DataTypeId::Int32)
            .access_level(AccessLevel::CURRENT_READ | AccessLevel::HISTORY_READ)
            .user_access_level(UserAccessLevel::CURRENT_READ | UserAccessLevel::HISTORY_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let start = DateTime::now() - TimeDelta::try_seconds(1000).unwrap();

    nm.inner().add_history(
        &id,
        (0..1000).map(|v| DataValue {
            value: Some((v as i32).into()),
            status: Some(StatusCode::Good),
            source_timestamp: Some(start + TimeDelta::try_seconds(v).unwrap()),
            server_timestamp: Some(start + TimeDelta::try_seconds(v).unwrap()),
            ..Default::default()
        }),
    );

    let action = HistoryReadAction::ReadRawModifiedDetails(ReadRawModifiedDetails {
        is_read_modified: false,
        start_time: start,
        end_time: start + TimeDelta::try_seconds(2000).unwrap(),
        num_values_per_node: 100,
        return_bounds: false,
    });

    // Read up to 100, should get the 100 first.
    let r = session
        .history_read(
            &action,
            TimestampsToReturn::Both,
            false,
            &[HistoryReadValueId {
                node_id: id.clone(),
                index_range: Default::default(),
                data_encoding: Default::default(),
                continuation_point: Default::default(),
            }],
        )
        .await
        .unwrap();

    assert_eq!(r.len(), 1);
    let v = &r[0];
    assert!(!v.continuation_point.is_null());
    assert_eq!(v.status_code, StatusCode::Good);
    let mut data = v
        .history_data
        .decode_inner::<HistoryData>(session.decoding_options())
        .unwrap()
        .data_values
        .unwrap();

    assert_eq!(data.len(), 100);

    let mut cp = v.continuation_point.clone();

    // Read the 100 next in a loop until we reach the end.
    for i in 0..9 {
        let r = session
            .history_read(
                &action,
                TimestampsToReturn::Both,
                false,
                &[HistoryReadValueId {
                    node_id: id.clone(),
                    index_range: Default::default(),
                    data_encoding: Default::default(),
                    continuation_point: cp,
                }],
            )
            .await
            .unwrap();

        assert_eq!(r.len(), 1);
        let v = &r[0];
        if i == 8 {
            assert!(v.continuation_point.is_null());
        } else {
            assert!(!v.continuation_point.is_null(), "Expected cp for i = {}", i);
        }
        assert_eq!(v.status_code, StatusCode::Good);
        let next_data = v
            .history_data
            .decode_inner::<HistoryData>(session.decoding_options())
            .unwrap()
            .data_values
            .unwrap();

        assert_eq!(next_data.len(), 100);
        data.extend(next_data);

        cp = v.continuation_point.clone();
    }

    // Data should be from 0 to 999, with the correct timestamps
    // This part is more a test of the test node manager,
    // but it's good to verify that continuation points work as expected.
    assert_eq!(1000, data.len());
    for (idx, it) in data.into_iter().enumerate() {
        let v = match it.value.as_ref().unwrap() {
            Variant::Int32(v) => *v,
            _ => panic!("Wrong value type: {:?}", it.value),
        };
        assert_eq!(idx as i32, v);
        assert_eq!(
            it.source_timestamp,
            Some(start + TimeDelta::try_seconds(idx as i64).unwrap())
        );
    }
}

#[tokio::test]
async fn history_read_release_continuation_points() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .historizing(true)
            .value(0)
            .description("Description")
            .data_type(DataTypeId::Int32)
            .access_level(AccessLevel::CURRENT_READ | AccessLevel::HISTORY_READ)
            .user_access_level(UserAccessLevel::CURRENT_READ | UserAccessLevel::HISTORY_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let start = DateTime::now() - TimeDelta::try_seconds(1000).unwrap();

    nm.inner().add_history(
        &id,
        (0..1000).map(|v| DataValue {
            value: Some((v as i32).into()),
            status: Some(StatusCode::Good),
            source_timestamp: Some(start + TimeDelta::try_seconds(v).unwrap()),
            server_timestamp: Some(start + TimeDelta::try_seconds(v).unwrap()),
            ..Default::default()
        }),
    );

    let action = HistoryReadAction::ReadRawModifiedDetails(ReadRawModifiedDetails {
        is_read_modified: false,
        start_time: start,
        end_time: start + TimeDelta::try_seconds(2000).unwrap(),
        num_values_per_node: 100,
        return_bounds: false,
    });

    let r = session
        .history_read(
            &action,
            TimestampsToReturn::Both,
            false,
            &[HistoryReadValueId {
                node_id: id.clone(),
                index_range: Default::default(),
                data_encoding: Default::default(),
                continuation_point: Default::default(),
            }],
        )
        .await
        .unwrap();

    assert_eq!(r.len(), 1);
    let v = &r[0];
    assert!(!v.continuation_point.is_null());
    assert_eq!(v.status_code, StatusCode::Good);
    let data = v
        .history_data
        .decode_inner::<HistoryData>(session.decoding_options())
        .unwrap()
        .data_values
        .unwrap();

    assert_eq!(data.len(), 100);

    let cp = v.continuation_point.clone();

    let r = session
        .history_read(
            &action,
            TimestampsToReturn::Both,
            true,
            &[HistoryReadValueId {
                node_id: id.clone(),
                index_range: Default::default(),
                data_encoding: Default::default(),
                continuation_point: cp,
            }],
        )
        .await
        .unwrap();

    assert_eq!(r.len(), 1);
    let v = &r[0];
    assert!(v.continuation_point.is_null());
    assert_eq!(v.status_code, StatusCode::Good);
    assert!(v.history_data.is_null());
}

#[tokio::test]
async fn history_read_fail() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .historizing(true)
            .value(0)
            .description("Description")
            .data_type(DataTypeId::Int32)
            .access_level(AccessLevel::CURRENT_READ)
            .user_access_level(UserAccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let start = DateTime::now() - TimeDelta::try_seconds(1000).unwrap();

    let action = HistoryReadAction::ReadRawModifiedDetails(ReadRawModifiedDetails {
        is_read_modified: false,
        start_time: start,
        end_time: start + TimeDelta::try_seconds(2000).unwrap(),
        num_values_per_node: 100,
        return_bounds: false,
    });

    // Read nothing
    let r = session
        .history_read(&action, TimestampsToReturn::Both, false, &[])
        .await
        .unwrap_err();
    assert_eq!(r, StatusCode::BadNothingToDo);

    let history_read_limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_nodes_per_history_read_data;

    // Read too many
    let r = session
        .history_read(
            &action,
            TimestampsToReturn::Both,
            false,
            &(0..(history_read_limit + 1))
                .map(|i| HistoryReadValueId {
                    node_id: NodeId::new(2, i as i32),
                    index_range: Default::default(),
                    data_encoding: Default::default(),
                    continuation_point: Default::default(),
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap_err();
    assert_eq!(r, StatusCode::BadTooManyOperations);

    // Read without access
    let r = session
        .history_read(
            &action,
            TimestampsToReturn::Both,
            false,
            &[HistoryReadValueId {
                node_id: id.clone(),
                index_range: Default::default(),
                data_encoding: Default::default(),
                continuation_point: Default::default(),
            }],
        )
        .await
        .unwrap();

    assert_eq!(r[0].status_code, StatusCode::BadUserAccessDenied);

    // Read node that doesn't exist
    let r = session
        .history_read(
            &action,
            TimestampsToReturn::Both,
            false,
            &[HistoryReadValueId {
                node_id: NodeId::new(2, 100),
                index_range: Default::default(),
                data_encoding: Default::default(),
                continuation_point: Default::default(),
            }],
        )
        .await
        .unwrap();

    assert_eq!(r[0].status_code, StatusCode::BadNodeIdUnknown);
}
