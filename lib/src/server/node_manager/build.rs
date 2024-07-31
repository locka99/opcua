use std::{collections::HashMap, sync::Arc};

use crate::server::address_space::AddressSpace;

use super::{DynNodeManager, NodeManager, ServerContext};

pub trait NodeManagerBuilder {
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager>;
}

impl<T, R: NodeManager + Send + Sync + 'static> NodeManagerBuilder for T
where
    T: FnOnce(ServerContext) -> R,
{
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager> {
        Arc::new(self(context))
    }
}

/// Utility for handling assignment of namespaces on server startup.
#[derive(Debug, Default)]
pub struct NamespaceMap {
    known_namespaces: HashMap<String, u16>,
}

impl NamespaceMap {
    pub fn new() -> Self {
        let mut known_namespaces = HashMap::new();
        known_namespaces.insert("http://opcfoundation.org/UA/".to_owned(), 0u16);

        Self { known_namespaces }
    }

    pub fn add_namespace(&mut self, namespace: &str) -> u16 {
        if let Some(ns) = self.known_namespaces.get(namespace) {
            return *ns;
        }
        let max = self
            .known_namespaces
            .iter()
            .map(|kv| *kv.1)
            .max()
            .unwrap_or_default();
        self.known_namespaces.insert(namespace.to_owned(), max + 1);

        max + 1
    }

    pub fn known_namespaces(&self) -> &HashMap<String, u16> {
        &self.known_namespaces
    }

    pub fn get_index(&self, ns: &str) -> Option<u16> {
        self.known_namespaces.get(ns).copied()
    }
}

pub fn add_namespaces(
    context: &ServerContext,
    address_space: &mut AddressSpace,
    namespaces: &[&str],
) -> Vec<u16> {
    let mut type_tree = context.type_tree.write();
    let mut res = Vec::new();
    for ns in namespaces {
        let idx = type_tree.namespaces_mut().add_namespace(ns);
        address_space.add_namespace(ns, idx);
        res.push(idx);
    }
    res
}
