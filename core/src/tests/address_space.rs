use address_space::*;
use services::*;
use types::*;

#[test]
fn address_space() {
    let address_space = AddressSpace::new_top_level();
    {
        let root_folder = address_space.root_folder();
        let objects_folder = address_space.objects_folder();
        let types_folder = address_space.types_folder();
        let views_folder = address_space.views_folder();
    }
}

#[test]
fn find_root_folder() {
    let address_space = AddressSpace::new_top_level();
    let node_type = address_space.find_node(&NodeId::new_numeric(0, 84));
    assert!(node_type.is_some());

    let node = node_type.unwrap().as_node();
    assert_eq!(node.node_id(), NodeId::new_numeric(0, 84));
    assert_eq!(node.node_id(), NodeId::from_object_id(ObjectId::RootFolder));
}

#[test]
fn find_objects_folder() {
    let address_space = AddressSpace::new_top_level();
    let node_type = address_space.find_node(&NodeId::from_object_id(ObjectId::ObjectsFolder));
    assert!(node_type.is_some());
}

#[test]
fn find_types_folder() {
    let address_space = AddressSpace::new_top_level();
    let node_type = address_space.find_node(&NodeId::from_object_id(ObjectId::TypesFolder));
    assert!(node_type.is_some());
}

#[test]
fn find_views_folder() {
    let address_space = AddressSpace::new_top_level();
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