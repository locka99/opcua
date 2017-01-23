use address_space::*;
use services::*;
use types::*;

#[test]
fn object_attributes() {
    let on= NodeId::new_string(1, "o1");
    let o = Object::new(&on, "Browse01", "Display01");
    assert_eq!(o.node_class(), NodeClass::Object);
    assert_eq!(o.node_id(), on);
    assert_eq!(o.browse_name(), QualifiedName::new(0, "Browse01"));
    assert_eq!(o.display_name(), LocalizedText::new("", "Display01"));
}