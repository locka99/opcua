use opcua_core::services::*;
use opcua_core::types::*;

use address_space::*;

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
    assert_eq!(node.node_id(), NodeId::from_object_id(ObjectId::RootFolder));
}

#[test]
fn find_objects_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&NodeId::from_object_id(ObjectId::ObjectsFolder));
    assert!(node_type.is_some());
}

#[test]
fn find_types_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&NodeId::from_object_id(ObjectId::TypesFolder));
    assert!(node_type.is_some());
}

#[test]
fn find_views_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&NodeId::from_object_id(ObjectId::ViewsFolder));
    assert!(node_type.is_some());
}

#[test]
fn object_attributes() {
    let on = NodeId::new_string(1, "o1");
    let o = Object::new(&on, "Browse01", "Display01");
    assert_eq!(o.node_class(), NodeClass::Object);
    assert_eq!(o.node_id(), on);
    assert_eq!(o.browse_name(), QualifiedName::new(0, "Browse01"));
    assert_eq!(o.display_name(), LocalizedText::new("", "Display01"));
}

fn make_sample_address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();

    // Create a sample folder under objects folder
    let sample_folder_id = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

    // Add some variables to our sample folder
    let vars = vec![
        Variable::new(&NodeId::new_string(1, "v1"), "v1", "v1", DataValue::new(Variant::Int32(30))),
        Variable::new(&NodeId::new_numeric(2, 300), "v2", "v2", DataValue::new(Variant::Boolean(true))),
        Variable::new(&NodeId::new_string(1, "v3"), "v3", "v3", DataValue::new(Variant::String(UAString::from_str("Hello world"))))
    ];
    let _ = address_space.add_variables(&vars, &sample_folder_id);
    address_space
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

    let references = address_space.find_references_from(&AddressSpace::root_folder_id(), &Some(ReferenceTypeId::Organizes));
    assert!(references.is_some());
    let references = references.unwrap();
    assert_eq!(references.len(), 3);

    let references = address_space.find_references_from(&AddressSpace::objects_folder_id(), &Some(ReferenceTypeId::Organizes));
    assert!(references.is_some());
    let references = references.unwrap();
    assert_eq!(references.len(), 1);

    let r1 = &references[0];
    assert_eq!(r1.reference_type_id, ReferenceTypeId::Organizes);
    let child_node_id = r1.node_id.clone();

    let child = address_space.find_node(&child_node_id);
    assert!(child.is_some());
}

#[test]
fn find_references_to() {
    let address_space = make_sample_address_space();

    let references = address_space.find_references_to(&AddressSpace::root_folder_id(), &Some(ReferenceTypeId::Organizes));
    assert!(references.is_some());
    let references = references.unwrap();
    assert_eq!(references.len(), 3);
}