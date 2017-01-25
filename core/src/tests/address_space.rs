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
fn object_attributes() {
    let on = NodeId::new_string(1, "o1");
    let o = Object::new(&on, "Browse01", "Display01");
    assert_eq!(o.node_class(), NodeClass::Object);
    assert_eq!(o.node_id(), on);
    assert_eq!(o.browse_name(), QualifiedName::new(0, "Browse01"));
    assert_eq!(o.display_name(), LocalizedText::new("", "Display01"));
}