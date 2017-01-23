use address_space::*;
use types::*;
use services::*;

pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

// NodeClass::ObjectType