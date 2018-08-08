use prelude::*;

use tests::*;

#[test]
fn address_space() {
    let address_space = AddressSpace::new();

    let root_folder = address_space.root_folder();
    assert_eq!(root_folder.node_class(), NodeClass::Object);
    let objects_folder = address_space.objects_folder();
    assert_eq!(objects_folder.node_class(), NodeClass::Object);
    let types_folder = address_space.types_folder();
    assert_eq!(types_folder.node_class(), NodeClass::Object);
    let views_folder = address_space.views_folder();
    assert_eq!(views_folder.node_class(), NodeClass::Object);
}

#[test]
fn find_root_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&NodeId::new(0, 84));
    assert!(node_type.is_some());

    let node = node_type.unwrap().as_node();
    assert_eq!(node.node_id(), NodeId::new(0, 84));
    assert_eq!(node.node_id(), ObjectId::RootFolder.into());
}

#[test]
fn find_objects_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::ObjectsFolder.into());
    assert!(node_type.is_some());
}

#[test]
fn find_types_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::TypesFolder.into());
    assert!(node_type.is_some());
}

#[test]
fn find_views_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::ViewsFolder.into());
    assert!(node_type.is_some());
}


#[test]
fn find_common_nodes() {
    let address_space = AddressSpace::new();
    let nodes: Vec<NodeId> = vec![
        AddressSpace::root_folder_id(),
        AddressSpace::objects_folder_id(),
        AddressSpace::types_folder_id(),
        AddressSpace::views_folder_id(),
        ObjectId::DataTypesFolder.into(),
        DataTypeId::BaseDataType.into(),
        // Types
        DataTypeId::Boolean.into(),
        DataTypeId::ByteString.into(),
        DataTypeId::DataValue.into(),
        DataTypeId::DateTime.into(),
        DataTypeId::DiagnosticInfo.into(),
        DataTypeId::Enumeration.into(),
        DataTypeId::ExpandedNodeId.into(),
        DataTypeId::Guid.into(),
        DataTypeId::LocalizedText.into(),
        DataTypeId::NodeId.into(),
        DataTypeId::Number.into(),
        DataTypeId::QualifiedName.into(),
        DataTypeId::StatusCode.into(),
        DataTypeId::String.into(),
        DataTypeId::Structure.into(),
        DataTypeId::XmlElement.into(),
        DataTypeId::Double.into(),
        DataTypeId::Float.into(),
        DataTypeId::Integer.into(),
        DataTypeId::SByte.into(),
        DataTypeId::Int16.into(),
        DataTypeId::Int32.into(),
        DataTypeId::Int64.into(),
        DataTypeId::Byte.into(),
        DataTypeId::UInt16.into(),
        DataTypeId::UInt32.into(),
        DataTypeId::UInt64.into(),
        ObjectId::OPCBinarySchema_TypeSystem.into(),
        ObjectTypeId::DataTypeSystemType.into(),
        // Refs
        ObjectId::ReferenceTypesFolder.into(),
        ReferenceTypeId::References.into(),
        ReferenceTypeId::HierarchicalReferences.into(),
        ReferenceTypeId::HasChild.into(),
        ReferenceTypeId::HasSubtype.into(),
        ReferenceTypeId::Organizes.into(),
        ReferenceTypeId::NonHierarchicalReferences.into(),
        ReferenceTypeId::HasTypeDefinition.into(),
    ];
    for n in nodes {
        assert!(address_space.find_node(&n).is_some());
    }
}

#[test]
fn object_attributes() {
    let on = NodeId::new(1, "o1");
    let o = Object::new(&on, "Browse01", "Display01", "xx");
    assert_eq!(o.node_class(), NodeClass::Object);
    assert_eq!(o.node_id(), on);
    assert_eq!(o.browse_name(), QualifiedName::new(0, "Browse01"));
    assert_eq!(o.display_name(), LocalizedText::new("", "Display01"));
}


#[test]
fn find_node_by_id() {
    let address_space = make_sample_address_space();

    assert!(!address_space.node_exists(&NodeId::null()));
    assert!(!address_space.node_exists(&NodeId::new(11, "v3")));

    assert!(address_space.node_exists(&NodeId::new(1, "v1")));
    assert!(address_space.node_exists(&NodeId::new(2, 300)));
    assert!(address_space.node_exists(&NodeId::new(1, "v3")));
}

#[test]
fn find_references_from() {
    let address_space = make_sample_address_space();

    let references = address_space.find_references_from(&AddressSpace::root_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_some());
    let references = references.as_ref().unwrap();
    for r in references {
        println!("Filtered type = {:?}, to = {:?}", r.reference_type_id, r.node_id);
    }
    assert_eq!(references.len(), 3);

    let references = address_space.find_references_from(&AddressSpace::root_folder_id(), None);
    assert!(references.is_some());
    let references = references.as_ref().unwrap();
    for r in references.iter() {
        println!("Refs from Root type = {:?}, to = {:?}", r.reference_type_id, r.node_id);
    }
    assert_eq!(references.len(), 4);

    let references = address_space.find_references_from(&AddressSpace::objects_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_some());
    let references = references.unwrap();
    for r in references.iter() {
        println!("Refs from Objects type = {:?}, to = {:?}", r.reference_type_id, r.node_id);
    }
    assert_eq!(references.len(), 2);

    let r1 = &references[0];
    assert_eq!(r1.reference_type_id, ReferenceTypeId::Organizes);
    let child_node_id = r1.node_id.clone();

    let child = address_space.find_node(&child_node_id);
    assert!(child.is_some());
}

#[test]
fn find_references_to() {
    let address_space = make_sample_address_space();

    //println!("{:#?}", address_space);
    let references = address_space.find_references_to(&AddressSpace::root_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_none());

    let references = address_space.find_references_to(&AddressSpace::objects_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_some());
    let references = references.unwrap();
    assert_eq!(references.len(), 1);
}