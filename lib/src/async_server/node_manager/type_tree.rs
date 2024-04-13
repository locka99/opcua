use crate::server::prelude::{NodeClass, NodeId};

/// Type managing the types in an OPC-UA server.
/// Types are usually known beforehand (though this is not guaranteed),
///
pub struct DefaultTypeTree {}

pub trait TypeTree {
    /// Return `true` if the node given by `child` is a hierarchical
    /// descendant of `ancestor`, or `child == ancestor`
    /// If either node does not exist, return `false`.
    fn is_child_of(&self, child: &NodeId, ancestor: &NodeId) -> bool;

    /// Return the node class of the given node, if it exists, otherwise return `None`
    fn get(&self, node: &NodeId) -> Option<NodeClass>;
}
