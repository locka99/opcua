use address_space::*;
use types::*;
use services::*;

pub struct Variable {
    pub base: Base,
}

node_impl!(Variable);

// NodeClass::Variable