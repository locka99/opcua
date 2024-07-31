use opcua::{
    server::address_space::{EventNotifier, NodeBase, NodeType, ObjectBuilder},
    types::{
        AddNodeAttributes, AddNodesItem, AddReferencesItem, DeleteNodesItem, DeleteReferencesItem,
        ExpandedNodeId, NodeClass, NodeId, ObjectAttributes, ObjectId, ObjectTypeId,
        ReferenceTypeId, StatusCode,
    },
};
use utils::setup;

mod utils;

#[tokio::test]
async fn add_delete_node() {
    let (_tester, nm, session) = setup().await;

    let r = session
        .add_nodes(&[AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::HasComponent.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: "MyNode".into(),
            node_class: NodeClass::Object,
            node_attributes: AddNodeAttributes::Object(ObjectAttributes {
                specified_attributes: (1 << 5) | (1 << 6),
                display_name: "DisplayName".into(),
                description: "Description".into(),
                write_mask: Default::default(),
                user_write_mask: Default::default(),
                event_notifier: EventNotifier::all().bits(), // Should not be set
            })
            .as_extension_object(),
            type_definition: ExpandedNodeId::new(ObjectTypeId::FolderType),
        }])
        .await
        .unwrap();

    assert_eq!(1, r.len());
    let it = &r[0];
    assert_eq!(it.status_code, StatusCode::Good);
    assert!(!it.added_node_id.is_null());

    let id = it.added_node_id.clone();

    {
        let sp = nm.address_space().read();
        let Some(NodeType::Object(o)) = sp.find(&id) else {
            panic!("Missing");
        };
        assert_eq!(o.browse_name(), &"MyNode".into());
        assert_eq!(o.display_name(), &"DisplayName".into());
        assert_eq!(o.description(), Some(&"Description".into()));
        assert_eq!(0, o.event_notifier().bits());
    }

    println!("{id}");

    let r = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: id.clone(),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], StatusCode::Good);
}

#[tokio::test]
async fn add_delete_reference() {
    let (tester, nm, session) = setup().await;

    let id1 = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&id1, "TestObj1", "TestObj1")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );
    let id2 = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&id2, "TestObj2", "TestObj2")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );

    let r = session
        .add_references(&[AddReferencesItem {
            source_node_id: id1.clone(),
            reference_type_id: ReferenceTypeId::HasCondition.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: id2.clone().into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], StatusCode::Good);

    {
        let sp = nm.address_space().read();
        let type_tree = tester.handle.type_tree().read();
        sp.find_references(
            &id1,
            None::<(NodeId, bool)>,
            &type_tree,
            opcua::types::BrowseDirection::Forward,
        )
        .find(|r| {
            r.target_node == &id2 && r.reference_type == &ReferenceTypeId::HasCondition.into()
        })
        .unwrap();
    }

    let r = session
        .delete_references(&[DeleteReferencesItem {
            source_node_id: id1.clone(),
            reference_type_id: ReferenceTypeId::HasCondition.into(),
            is_forward: true,
            target_node_id: id2.clone().into(),
            delete_bidirectional: true,
        }])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], StatusCode::Good);
}

#[tokio::test]
async fn add_delete_node_limits() {
    let (tester, _nm, session) = setup().await;
    let limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_nodes_per_node_management;

    // Add zero
    let e = session.add_nodes(&[]).await.unwrap_err();
    assert_eq!(e, StatusCode::BadNothingToDo);

    // Add too many
    let e = session
        .add_nodes(
            &(0..(limit + 1))
                .map(|i| {
                    AddNodesItem {
                        parent_node_id: ObjectId::ObjectsFolder.into(),
                        reference_type_id: ReferenceTypeId::HasComponent.into(),
                        requested_new_node_id: ExpandedNodeId::null(),
                        browse_name: format!("MyNode{i}").into(),
                        node_class: NodeClass::Object,
                        node_attributes: AddNodeAttributes::Object(ObjectAttributes {
                            specified_attributes: (1 << 5) | (1 << 6),
                            display_name: "DisplayName".into(),
                            description: "Description".into(),
                            write_mask: Default::default(),
                            user_write_mask: Default::default(),
                            event_notifier: EventNotifier::all().bits(), // Should not be set
                        })
                        .as_extension_object(),
                        type_definition: ExpandedNodeId::new(ObjectTypeId::FolderType),
                    }
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap_err();
    assert_eq!(e, StatusCode::BadTooManyOperations);
}

#[tokio::test]
async fn add_delete_reference_limits() {
    let (tester, _nm, session) = setup().await;
    let limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_references_per_references_management;

    // Add zero
    let e = session.add_references(&[]).await.unwrap_err();
    assert_eq!(e, StatusCode::BadNothingToDo);

    // Add too many
    let e = session
        .add_references(
            &(0..(limit + 1))
                .map(|i| AddReferencesItem {
                    source_node_id: NodeId::new(2, i as i32),
                    reference_type_id: ReferenceTypeId::HasCause.into(),
                    is_forward: true,
                    target_server_uri: Default::default(),
                    target_node_id: NodeId::new(2, (i + 1) as i32).into(),
                    target_node_class: NodeClass::Object,
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap_err();
    assert_eq!(e, StatusCode::BadTooManyOperations);
}
