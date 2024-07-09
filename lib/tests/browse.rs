use opcua::{
    async_server::address_space::{ObjectBuilder, ReferenceDirection, VariableBuilder},
    types::{
        BrowseDescription, BrowseDirection, BrowseResultMask, DataTypeId, NodeClass, NodeClassMask,
        NodeId, ObjectId, ObjectTypeId, ReferenceTypeId, StatusCode, VariableTypeId,
    },
};
use utils::setup;

mod utils;

fn hierarchical_desc(node_id: NodeId) -> BrowseDescription {
    BrowseDescription {
        node_id,
        browse_direction: BrowseDirection::Forward,
        reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
        include_subtypes: true,
        node_class_mask: NodeClassMask::all().bits(),
        result_mask: BrowseResultMask::All as u32,
    }
}

#[tokio::test]
async fn browse() {
    let (tester, _nm, session) = setup().await;

    // Browse the server node and expect a few specific nodes.
    let r = session
        .browse(&[hierarchical_desc(ObjectId::Server.into())], 1000, None)
        .await
        .unwrap();

    assert_eq!(r.len(), 1);
    let it = &r[0];

    assert!(it.continuation_point.is_null());
    let refs = it.references.clone().unwrap_or_default();
    // Exact number may vary with new versions of the standard. This number may need to be changed
    // in the future. Keep the test as a sanity check.
    assert_eq!(refs.len(), 18);

    let server_cap_node = refs
        .iter()
        .find(|f| f.node_id.node_id == ObjectId::Server_ServerCapabilities.into())
        .unwrap();
    let type_tree = tester.handle.type_tree().read();
    for rf in &refs {
        assert!(rf.is_forward);
        assert!(type_tree.is_subtype_of(
            &rf.reference_type_id,
            &ReferenceTypeId::HierarchicalReferences.into()
        ));
    }

    assert_eq!(server_cap_node.browse_name, "ServerCapabilities".into());
    assert_eq!(server_cap_node.display_name, "ServerCapabilities".into());
    assert_eq!(server_cap_node.node_class, NodeClass::Object);
    assert!(server_cap_node.is_forward);
    assert_eq!(
        server_cap_node.type_definition.node_id,
        ObjectTypeId::ServerCapabilitiesType.into()
    );
}

#[tokio::test]
async fn browse_filter() {
    let (_tester, _nm, session) = setup().await;

    // Browse the server node and expect a few specific nodes.
    let mut desc = hierarchical_desc(ObjectId::Server.into());
    desc.node_class_mask = NodeClassMask::OBJECT.bits();
    let r = session.browse(&[desc], 1000, None).await.unwrap();
    assert_eq!(r.len(), 1);
    let it = &r[0];

    assert!(it.continuation_point.is_null());
    let refs = it.references.clone().unwrap_or_default();
    // Exact number may vary with new versions of the standard. This number may need to be changed
    // in the future. Keep the test as a sanity check.
    assert_eq!(refs.len(), 7);
    for rf in &refs {
        assert!(rf.is_forward);
        assert_eq!(rf.node_class, NodeClass::Object);
    }
}

#[tokio::test]
async fn browse_reverse() {
    let (_tester, _nm, session) = setup().await;

    // Browse the server node and expect a few specific nodes.
    let mut desc = hierarchical_desc(ObjectId::Server.into());
    desc.browse_direction = BrowseDirection::Inverse;
    let r = session.browse(&[desc], 1000, None).await.unwrap();
    assert_eq!(r.len(), 1);
    let it = &r[0];

    assert!(it.continuation_point.is_null());
    let refs = it.references.clone().unwrap_or_default();
    // Exact number may vary with new versions of the standard. This number may need to be changed
    // in the future. Keep the test as a sanity check.
    assert_eq!(refs.len(), 1);
    let rf = &refs[0];
    assert!(!rf.is_forward);
    assert_eq!(rf.reference_type_id, ReferenceTypeId::Organizes.into());
    assert_eq!(rf.browse_name, "Objects".into());
    assert_eq!(rf.display_name, "Objects".into());
}

#[tokio::test]
async fn browse_multiple() {
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
        &id1,
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );

    let r = session
        .browse(
            &[
                hierarchical_desc(ObjectId::Server_Namespaces.into()),
                hierarchical_desc(ObjectId::ObjectsFolder.into()),
                hierarchical_desc(id1.clone()),
                hierarchical_desc(id2.clone()),
            ],
            1000,
            None,
        )
        .await
        .unwrap();

    assert_eq!(4, r.len());
    let it = &r[0];
    let refs = it.references.clone().unwrap_or_default();
    // Should be 3 namespaces.
    assert_eq!(3, refs.len());

    let it = &r[1];
    let refs = it.references.clone().unwrap_or_default();
    // The objects folder has two references, our custom node and the server node.
    // Note that future versions of the standard has more nodes here.
    assert_eq!(2, refs.len());
    let rf = refs.iter().find(|r| r.node_id.node_id == id1).unwrap();
    assert_eq!(rf.display_name, "TestObj1".into());

    // The first custom object should reference the second
    let it = &r[2];
    let refs = it.references.clone().unwrap_or_default();
    // The objects folder has one reference, our custom node.
    assert_eq!(1, refs.len());
    assert_eq!(refs[0].display_name, "TestObj2".into());

    // The second custom object has no hierarchical references.
    let it = &r[3];
    let refs = it.references.clone().unwrap_or_default();
    // The objects folder has one reference, our custom node.
    assert!(refs.is_empty());
}

#[tokio::test]
async fn browse_cross_node_manager() {
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

    // Add a non-hierarchical reference pointing into the main node manager.
    nm.inner().add_references(
        nm.address_space(),
        &id1,
        vec![(
            &ObjectId::Server.into(),
            ReferenceTypeId::HasCondition.into(),
            ReferenceDirection::Forward,
        )],
    );

    // Browse the server in inverse, and our custom node forward.
    // This should result in an external reference from our custom node manager,
    // which should be resolved by calling into the core node manager.
    let mut desc1 = hierarchical_desc(id1.clone());
    desc1.reference_type_id = ReferenceTypeId::NonHierarchicalReferences.into();
    let mut desc2 = hierarchical_desc(ObjectId::Server.into());
    desc2.reference_type_id = ReferenceTypeId::NonHierarchicalReferences.into();
    desc2.browse_direction = BrowseDirection::Inverse;
    let r = session.browse(&[desc1, desc2], 1000, None).await.unwrap();

    assert_eq!(2, r.len());
    let it = &r[0];
    let refs = it.references.clone().unwrap_or_default();
    // Expect two non-hierarchical references here, one for the type definition.
    assert_eq!(2, refs.len());
    let type_def_ref = refs
        .iter()
        .find(|r| r.reference_type_id == ReferenceTypeId::HasTypeDefinition.into())
        .unwrap();
    assert_eq!(type_def_ref.display_name, "FolderType".into());
    let server_ref = refs
        .iter()
        .find(|r| r.node_id.node_id == ObjectId::Server.into())
        .unwrap();
    assert_eq!(server_ref.display_name, "Server".into());
    assert_eq!(server_ref.type_definition, ObjectTypeId::ServerType.into());
    assert_eq!(server_ref.browse_name, "Server".into());
    assert_eq!(
        server_ref.reference_type_id,
        ReferenceTypeId::HasCondition.into()
    );
    assert!(server_ref.is_forward);

    let it = &r[1];
    let refs = it.references.clone().unwrap_or_default();
    // Should only be one reference for now.
    assert_eq!(1, refs.len());
    let rf = &refs[0];
    assert_eq!(rf.display_name, "TestObj1".into());
}

#[tokio::test]
async fn browse_continuation_point() {
    let (tester, nm, session) = setup().await;
    let root_id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&root_id, "TestObj1", "TestObj1")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );
    for i in 0..1000 {
        let id = nm.inner().next_node_id();
        nm.inner().add_node(
            nm.address_space(),
            tester.handle.type_tree(),
            VariableBuilder::new(&id, &format!("Var{i}"), &format!("Var{i}"))
                .data_type(DataTypeId::Int32)
                .build()
                .into(),
            &root_id,
            &ReferenceTypeId::HasComponent.into(),
            Some(&VariableTypeId::BaseDataVariableType.into()),
            Vec::new(),
        );
    }

    let desc = hierarchical_desc(root_id);
    let r = session.browse(&[desc], 100, None).await.unwrap();
    assert_eq!(1, r.len());
    let it = &r[0];
    assert_eq!(StatusCode::Good, it.status_code);
    assert!(!it.continuation_point.is_null());

    let mut results = it.references.clone().unwrap();
    let mut cp = it.continuation_point.clone();
    assert_eq!(100, results.len());
    for i in 0..9 {
        let r = session.browse_next(false, &[cp.clone()]).await.unwrap();
        assert_eq!(1, r.len());
        let it = &r[0];
        assert_eq!(StatusCode::Good, it.status_code);
        if i == 8 {
            assert!(it.continuation_point.is_null());
        } else {
            assert!(!it.continuation_point.is_null());
        }
        cp = it.continuation_point.clone();
        results.extend(it.references.clone().into_iter().flatten());
    }

    assert_eq!(1000, results.len());
}

#[tokio::test]
async fn browse_release_continuation_point() {
    let (tester, nm, session) = setup().await;
    let root_id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&root_id, "TestObj1", "TestObj1")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );
    for i in 0..1000 {
        let id = nm.inner().next_node_id();
        nm.inner().add_node(
            nm.address_space(),
            tester.handle.type_tree(),
            VariableBuilder::new(&id, &format!("Var{i}"), &format!("Var{i}"))
                .data_type(DataTypeId::Int32)
                .build()
                .into(),
            &root_id,
            &ReferenceTypeId::HasComponent.into(),
            Some(&VariableTypeId::BaseDataVariableType.into()),
            Vec::new(),
        );
    }

    let desc = hierarchical_desc(root_id);
    let r = session.browse(&[desc], 100, None).await.unwrap();
    assert_eq!(1, r.len());
    let it = &r[0];
    assert!(!it.continuation_point.is_null());

    let cp = it.continuation_point.clone();
    let r = session.browse_next(true, &[cp.clone()]).await.unwrap();
    assert_eq!(1, r.len());
    let it = &r[0];
    assert_eq!(StatusCode::Good, it.status_code);
    let refs = it.references.clone().unwrap_or_default();
    assert!(refs.is_empty());
}
