use opcua::{
    async_server::address_space::{
        AccessLevel, DataTypeBuilder, MethodBuilder, ObjectBuilder, ObjectTypeBuilder,
        ReferenceTypeBuilder, UserAccessLevel, VariableBuilder, VariableTypeBuilder, ViewBuilder,
    },
    client::Session,
    server::address_space::EventNotifier,
    types::{
        AttributeId, DataTypeId, DataValue, DateTime, LocalizedText, NodeId, ObjectId,
        ObjectTypeId, QualifiedName, ReferenceTypeId, StatusCode, TimestampsToReturn, UAString,
        VariableTypeId, Variant, WriteMask, WriteValue,
    },
};
// Write is not implemented in the core library itself, only in the test node manager,
// we still test here to test write functionality in the address space.
use utils::{read_value_id, setup};

mod utils;

fn write_value(
    attribute_id: AttributeId,
    value: impl Into<Variant>,
    node_id: impl Into<NodeId>,
) -> WriteValue {
    WriteValue {
        value: DataValue {
            value: Some(value.into()),
            status: Some(StatusCode::Good),
            source_timestamp: Some(DateTime::now()),
            ..Default::default()
        },
        node_id: node_id.into(),
        attribute_id: attribute_id as u32,
        index_range: UAString::null(),
    }
}

async fn write_then_read(session: &Session, values: &[WriteValue]) {
    let r = session.write(values).await.unwrap();
    assert_eq!(r.len(), values.len());
    for s in r {
        assert_eq!(s, StatusCode::Good);
    }

    let reads: Vec<_> = values
        .iter()
        .map(|r| read_value_id(AttributeId::from_u32(r.attribute_id).unwrap(), &r.node_id))
        .collect();

    let r = session
        .read(&reads, TimestampsToReturn::Both, 0.0)
        .await
        .unwrap();

    assert_eq!(r.len(), values.len());
    for (read, write) in r.into_iter().zip(values) {
        assert_eq!(read.value, write.value.value);
    }
}

#[tokio::test]
async fn write_variable() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::ARRAY_DIMENSIONS
                    | WriteMask::VALUE_RANK
                    | WriteMask::DATA_TYPE
                    | WriteMask::ACCESS_LEVEL
                    | WriteMask::USER_ACCESS_LEVEL
                    | WriteMask::HISTORIZING,
            )
            .data_type(DataTypeId::String)
            .value("value")
            .access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(AttributeId::DisplayName, LocalizedText::from("NewVar"), &id),
            write_value(AttributeId::BrowseName, QualifiedName::from("NewVar"), &id),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(AttributeId::ArrayDimensions, vec![2u32], &id),
            write_value(AttributeId::ValueRank, 1, &id),
            write_value(
                AttributeId::DataType,
                Variant::NodeId(Box::new(DataTypeId::Int32.into())),
                &id,
            ),
            write_value(
                AttributeId::AccessLevel,
                (AccessLevel::CURRENT_READ
                    | AccessLevel::CURRENT_WRITE
                    | AccessLevel::HISTORY_READ)
                    .bits(),
                &id,
            ),
            write_value(
                AttributeId::UserAccessLevel,
                (UserAccessLevel::CURRENT_READ
                    | UserAccessLevel::CURRENT_WRITE
                    | UserAccessLevel::HISTORY_READ)
                    .bits(),
                &id,
            ),
            write_value(AttributeId::Historizing, true, &id),
            write_value(AttributeId::Value, vec![1, 2], &id),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_object() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&id, "TestObj1", "TestObj1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::EVENT_NOTIFIER,
            )
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(AttributeId::DisplayName, LocalizedText::from("NewObj"), &id),
            write_value(AttributeId::BrowseName, QualifiedName::from("NewObj"), &id),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(
                AttributeId::EventNotifier,
                EventNotifier::SUBSCRIBE_TO_EVENTS.bits(),
                &id,
            ),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_view() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ViewBuilder::new(&id, "TestView1", "TestView1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::EVENT_NOTIFIER
                    | WriteMask::CONTAINS_NO_LOOPS,
            )
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(
                AttributeId::DisplayName,
                LocalizedText::from("NewView"),
                &id,
            ),
            write_value(AttributeId::BrowseName, QualifiedName::from("NewView"), &id),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(
                AttributeId::EventNotifier,
                EventNotifier::SUBSCRIBE_TO_EVENTS.bits(),
                &id,
            ),
            write_value(AttributeId::ContainsNoLoops, true, &id),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_method() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        MethodBuilder::new(&id, "TestMethod1", "TestMethod1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::EXECUTABLE
                    | WriteMask::USER_EXECUTABLE,
            )
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(
                AttributeId::DisplayName,
                LocalizedText::from("NewMethod"),
                &id,
            ),
            write_value(
                AttributeId::BrowseName,
                QualifiedName::from("NewMethod"),
                &id,
            ),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(AttributeId::Executable, true, &id),
            write_value(AttributeId::UserExecutable, true, &id),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_object_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectTypeBuilder::new(&id, "TestObjectType1", "TestObjectType1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::IS_ABSTRACT,
            )
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(
                AttributeId::DisplayName,
                LocalizedText::from("NewObjectType"),
                &id,
            ),
            write_value(
                AttributeId::BrowseName,
                QualifiedName::from("NewObjectType"),
                &id,
            ),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(AttributeId::IsAbstract, true, &id),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_variable_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableTypeBuilder::new(&id, "TestVariableType1", "TestVariableType1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::IS_ABSTRACT
                    | WriteMask::DATA_TYPE
                    | WriteMask::ARRAY_DIMENSIONS
                    | WriteMask::VALUE_FOR_VARIABLE_TYPE
                    | WriteMask::VALUE_RANK,
            )
            .data_type(DataTypeId::String)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(
                AttributeId::DisplayName,
                LocalizedText::from("NewVariableType"),
                &id,
            ),
            write_value(
                AttributeId::BrowseName,
                QualifiedName::from("NewVariableType"),
                &id,
            ),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(AttributeId::IsAbstract, true, &id),
            write_value(AttributeId::ArrayDimensions, vec![2u32], &id),
            write_value(AttributeId::ValueRank, 1, &id),
            write_value(
                AttributeId::DataType,
                Variant::NodeId(Box::new(DataTypeId::Int32.into())),
                &id,
            ),
            write_value(AttributeId::Value, vec![1, 2], &id),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_data_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        DataTypeBuilder::new(&id, "TestObjectType1", "TestObjectType1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::IS_ABSTRACT,
            )
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(
                AttributeId::DisplayName,
                LocalizedText::from("NewDataType"),
                &id,
            ),
            write_value(
                AttributeId::BrowseName,
                QualifiedName::from("NewDataType"),
                &id,
            ),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(AttributeId::IsAbstract, true, &id),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_reference_type() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ReferenceTypeBuilder::new(&id, "TestRefType1", "TestRefType1")
            .description("Description")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::IS_ABSTRACT
                    | WriteMask::SYMMETRIC
                    | WriteMask::INVERSE_NAME,
            )
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        None,
        Vec::new(),
    );

    write_then_read(
        &session,
        &[
            write_value(
                AttributeId::DisplayName,
                LocalizedText::from("NewRefType"),
                &id,
            ),
            write_value(
                AttributeId::BrowseName,
                QualifiedName::from("NewRefType"),
                &id,
            ),
            write_value(
                AttributeId::Description,
                LocalizedText::from("Description"),
                &id,
            ),
            write_value(AttributeId::IsAbstract, true, &id),
            write_value(AttributeId::Symmetric, true, &id),
            write_value(
                AttributeId::InverseName,
                LocalizedText::from("Inverse"),
                &id,
            ),
        ],
    )
    .await;
}

#[tokio::test]
async fn write_invalid() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .write_mask(
                WriteMask::DISPLAY_NAME
                    | WriteMask::BROWSE_NAME
                    | WriteMask::DESCRIPTION
                    | WriteMask::DATA_TYPE
                    | WriteMask::HISTORIZING,
            )
            .data_type(DataTypeId::String)
            .value("value")
            .access_level(AccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let r = session
        .write(&[
            // Wrong type
            write_value(AttributeId::DataType, LocalizedText::from("uhoh"), &id),
            // Not valid for variables.
            write_value(AttributeId::EventNotifier, 1, &id),
            // Not allowed
            write_value(
                AttributeId::AccessLevel,
                (AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE).bits(),
                &id,
            ),
            // Not allowed value
            write_value(AttributeId::Value, "foo", &id),
        ])
        .await
        .unwrap();

    assert_eq!(r[0], StatusCode::BadTypeMismatch);
    assert_eq!(r[1], StatusCode::BadNotWritable);
    assert_eq!(r[2], StatusCode::BadNotWritable);
    assert_eq!(r[3], StatusCode::BadUserAccessDenied);
}

#[tokio::test]
async fn write_limits() {
    let (tester, _nm, session) = setup().await;

    let write_limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_nodes_per_write;

    // Write zero. This doesn't actually reach the server, since we intercept it in the client.
    // we still protect against it on the server, but we don't have a way to bypass that check here.
    let r = session.write(&[]).await.unwrap_err();
    assert_eq!(r, StatusCode::BadNothingToDo);

    // Too many operations
    let ops: Vec<_> = (0..(write_limit + 1))
        .map(|r| write_value(AttributeId::Value, 123, NodeId::new(2, r as i32)))
        .collect();

    let r = session.write(&ops).await.unwrap_err();
    assert_eq!(r, StatusCode::BadTooManyOperations);

    // Exact number of operations
    let ops: Vec<_> = (0..write_limit)
        .map(|r| write_value(AttributeId::Value, 123, NodeId::new(2, r as i32)))
        .collect();

    session.write(&ops).await.unwrap();
}
