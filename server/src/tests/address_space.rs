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
    let node_type = address_space.find_node(&NodeId::new_numeric(0, 84));
    assert!(node_type.is_some());

    let node = node_type.unwrap().as_node();
    assert_eq!(node.node_id(), NodeId::new_numeric(0, 84));
    assert_eq!(node.node_id(), ObjectId::RootFolder.as_node_id());
}

#[test]
fn find_objects_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::ObjectsFolder.as_node_id());
    assert!(node_type.is_some());
}

#[test]
fn find_types_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::TypesFolder.as_node_id());
    assert!(node_type.is_some());
}

#[test]
fn find_views_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::ViewsFolder.as_node_id());
    assert!(node_type.is_some());
}


#[test]
fn find_common_nodes() {
    let address_space = AddressSpace::new();
    let nodes = vec![
        AddressSpace::root_folder_id(),
        AddressSpace::objects_folder_id(),
        AddressSpace::types_folder_id(),
        AddressSpace::views_folder_id(),
        ObjectId::DataTypesFolder.as_node_id(),
        DataTypeId::BaseDataType.as_node_id(),
        // Types
        DataTypeId::Boolean.as_node_id(),
        DataTypeId::ByteString.as_node_id(),
        DataTypeId::DataValue.as_node_id(),
        DataTypeId::DateTime.as_node_id(),
        DataTypeId::DiagnosticInfo.as_node_id(),
        DataTypeId::Enumeration.as_node_id(),
        DataTypeId::ExpandedNodeId.as_node_id(),
        DataTypeId::Guid.as_node_id(),
        DataTypeId::LocalizedText.as_node_id(),
        DataTypeId::NodeId.as_node_id(),
        DataTypeId::Number.as_node_id(),
        DataTypeId::QualifiedName.as_node_id(),
        DataTypeId::StatusCode.as_node_id(),
        DataTypeId::String.as_node_id(),
        DataTypeId::Structure.as_node_id(),
        DataTypeId::XmlElement.as_node_id(),
        DataTypeId::Double.as_node_id(),
        DataTypeId::Float.as_node_id(),
        DataTypeId::Integer.as_node_id(),
        DataTypeId::SByte.as_node_id(),
        DataTypeId::Int16.as_node_id(),
        DataTypeId::Int32.as_node_id(),
        DataTypeId::Int64.as_node_id(),
        DataTypeId::Byte.as_node_id(),
        DataTypeId::UInt16.as_node_id(),
        DataTypeId::UInt32.as_node_id(),
        DataTypeId::UInt64.as_node_id(),
        ObjectId::OPCBinarySchema_TypeSystem.as_node_id(),
        ObjectTypeId::DataTypeSystemType.as_node_id(),
        // Refs
        ObjectId::ReferenceTypesFolder.as_node_id(),
        ReferenceTypeId::References.as_node_id(),
        ReferenceTypeId::HierarchicalReferences.as_node_id(),
        ReferenceTypeId::HasChild.as_node_id(),
        ReferenceTypeId::HasSubtype.as_node_id(),
        ReferenceTypeId::Organizes.as_node_id(),
        ReferenceTypeId::NonHierarchicalReferences.as_node_id(),
        ReferenceTypeId::HasTypeDefinition.as_node_id(),
    ];
    for n in nodes {
        assert!(address_space.find_node(&n).is_some());
    }
}

#[test]
fn object_attributes() {
    let on = NodeId::new_string(1, "o1");
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
    assert!(!address_space.node_exists(&NodeId::new_string(11, "v3")));

    assert!(address_space.node_exists(&NodeId::new_string(1, "v1")));
    assert!(address_space.node_exists(&NodeId::new_numeric(2, 300)));
    assert!(address_space.node_exists(&NodeId::new_string(1, "v3")));
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