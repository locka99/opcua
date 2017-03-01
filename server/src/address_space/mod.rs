/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.

macro_rules! node_impl {
    ( $node_struct:ty ) => {
        use opcua_core::types::*;
        use opcua_core::services::*;

        impl Node for $node_struct {
            fn node_class(&self) -> NodeClass { self.base.node_class() }
            fn node_id(&self) -> NodeId { self.base.node_id() }
            fn browse_name(&self) -> QualifiedName { self.base.browse_name() }
            fn display_name(&self) -> LocalizedText { self.base.display_name() }
            fn description(&self) -> Option<LocalizedText> { self.base.description() }
            fn write_mask(&self) -> Option<UInt32> { self.base.write_mask() }
            fn user_write_mask(&self) -> Option<UInt32> { self.base.user_write_mask() }
            fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue> { self.base.find_attribute(attribute_id) }
        }
    };
}

#[macro_export]
macro_rules! find_attribute_value_mandatory {
    ( $sel:expr, $attr: ident, $t: ident ) => {
        {
            let result = find_attribute_value_optional!($sel, $attr, $t);
            if result.is_some() {
                result.unwrap()
            }
            else {
                panic!("Mandatory attribute {:?} is missing", AttributeId::$attr);
            }
        }
    }
}

#[macro_export]
macro_rules! find_attribute_value_optional {
    ( $sel:expr, $attr: ident, $ty: ident ) => {
        {
            let attribute_id = AttributeId::$attr;
            let ref attribute = $sel.attributes[attribute_id as usize - 1];

            let mut result = None;
            if attribute.is_some() {
                let attribute = attribute.as_ref().unwrap();
                if attribute.value.is_some() {
                    if let &Variant::$ty(ref value) = attribute.value.as_ref().unwrap() {
                        result = Some(value.clone());
                    }
                }
            }
            result
        }
    }
}

mod attribute;

pub use self::attribute::*;

mod address_space;

pub use self::address_space::*;

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
