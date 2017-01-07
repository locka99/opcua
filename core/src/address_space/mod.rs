mod address_space;

pub use self::address_space::*;

mod base_node;

pub use self::base_node::*;

/// This is a sanity saving macro that adds Node trait methods to all types that have a base_node
/// member. The BaseNode member implements Node trait and takes care of cloning values etc. so with
/// the exception of node_class(), this is just a pass-thru onto that impl.

macro_rules! node_impl {
    ( $node_struct:ty, $node_type: expr ) => {
        impl Node for $node_struct {
            fn node_class(&self) -> NodeClass {
                $node_type
            }
            fn node_id(&self) -> NodeId {
                self.base_node.node_id()
            }
            fn browse_name(&self) -> String {
                self.base_node.browse_name()
            }
            fn display_name(&self) -> String {
                self.base_node.display_name()
            }
            fn description(&self) -> String {
                self.base_node.description()
            }
        }
    };
}

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
