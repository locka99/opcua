use crate::{
    server::MonitoredItemHandle,
    types::{AttributeId, MonitoredItemModifyResult, NodeId, StatusCode},
};

#[derive(Debug, Clone)]
/// Reference to a monitored item in the server subscription cache.
pub struct MonitoredItemRef {
    handle: MonitoredItemHandle,
    node_id: NodeId,
    attribute: AttributeId,
}

impl<'a> MonitoredItemRef {
    pub(crate) fn new(
        handle: MonitoredItemHandle,
        node_id: NodeId,
        attribute: AttributeId,
    ) -> Self {
        Self {
            handle,
            node_id,
            attribute,
        }
    }

    /// Monitored item handle, uniquely identifies a monitored item.
    pub fn handle(&self) -> MonitoredItemHandle {
        self.handle
    }

    /// Node ID of the monitored item.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Attribute ID of the monitored item.
    pub fn attribute(&self) -> AttributeId {
        self.attribute
    }
}

#[derive(Debug, Clone)]
/// Reference to a monitored item with information from an update operation.
pub struct MonitoredItemUpdateRef {
    handle: MonitoredItemHandle,
    node_id: NodeId,
    attribute: AttributeId,
    update: MonitoredItemModifyResult,
}

impl<'a> MonitoredItemUpdateRef {
    pub(crate) fn new(
        handle: MonitoredItemHandle,
        node_id: NodeId,
        attribute: AttributeId,
        update: MonitoredItemModifyResult,
    ) -> Self {
        Self {
            handle,
            node_id,
            attribute,
            update,
        }
    }

    /// Monitored item handle, uniquely identifies a monitored item.
    pub fn handle(&self) -> MonitoredItemHandle {
        self.handle
    }

    /// Node ID of the monitored item.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Attribute ID of the monitored item.
    pub fn attribute(&self) -> AttributeId {
        self.attribute
    }

    /// Result of the monitored item update.
    pub fn update(&self) -> &MonitoredItemModifyResult {
        &self.update
    }

    /// Status code of the update.
    pub fn status_code(&self) -> StatusCode {
        self.update.status_code
    }

    pub(crate) fn into_result(self) -> MonitoredItemModifyResult {
        self.update
    }
}
