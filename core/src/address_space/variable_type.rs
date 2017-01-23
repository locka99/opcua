use address_space::*;
use types::*;
use services::*;

pub struct VariableType {
    pub base: Base,
}

node_impl!(VariableType);

// NodeClass::VariableType