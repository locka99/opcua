mod address_space;

pub use self::address_space::*;


/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.

macro_rules! node_impl {
    ( $node_struct:ty ) => {
        impl Node for $node_struct {
            fn node_class(&self) -> NodeClass { self.base.node_class() }
            fn node_id(&self) -> NodeId { self.base.node_id() }
            fn browse_name(&self) -> QualifiedName { self.base.browse_name() }
            fn display_name(&self) -> LocalizedText { self.base.display_name() }
            fn description(&self) -> Option<LocalizedText> { self.base.description() }
            fn write_mask(&self) -> Option<UInt32> { self.base.write_mask() }
            fn user_write_mask(&self) -> Option<UInt32> { self.base.user_write_mask() }
            fn add_reference(&mut self, reference: Reference) { self.base.add_reference(reference); }
            fn references(&self) -> &Vec<Reference> { self.base.references() }
            fn find_attribute(&self, attribute_id: &AttributeId) -> Option<Attribute> { self.base.find_attribute(attribute_id) }
        }
    };
}

#[macro_export]
macro_rules! find_attribute_value_optional {
 ( $sel:expr, $attr: ident ) => {
        let attribute_id = AttributeId::$attr;
        let attribute = $sel.attributes[attribute_id as usize - 1].clone();
        if attribute.is_some() {
            if let Attribute::$attr(value) = attribute.unwrap() {
                return Some(value);
            }
            panic!("Cannot unwrap attribute {:?}", attribute_id);
        }
        return None;
    }
}

#[macro_export]
macro_rules! find_attribute_value_mandatory {
    ( $sel:expr, $attr: ident ) => {
        let attribute_id = AttributeId::$attr;
        let attribute = $sel.attributes[attribute_id as usize - 1].clone();
        if attribute.is_some() {
            if let Attribute::$attr(value) = attribute.unwrap() {
                return value;
            }
        }
        panic!("Mandatory attribute {:?} is missing", attribute_id);
    }
}

mod base;

pub use self::base::*;

mod object;

pub use self::object::*;

mod variable;

pub use self::variable::*;

mod method;

pub use self::method::*;

mod reference_type;

pub use self::reference_type::*;

mod object_type;

pub use self::object_type::*;

mod variable_type;

pub use self::variable_type::*;

mod data_type;

pub use self::data_type::*;

mod view;

pub use self::view::*;
