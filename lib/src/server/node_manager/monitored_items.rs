use crate::{
    server::MonitoredItemHandle,
    types::{AttributeId, MonitoredItemModifyResult, NodeId, StatusCode},
};

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

    pub fn handle(&self) -> MonitoredItemHandle {
        self.handle
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn attribute(&self) -> AttributeId {
        self.attribute
    }
}

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

    pub fn handle(&self) -> MonitoredItemHandle {
        self.handle
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn attribute(&self) -> AttributeId {
        self.attribute
    }

    pub fn update(&self) -> &MonitoredItemModifyResult {
        &self.update
    }

    pub fn status_code(&self) -> StatusCode {
        self.update.status_code
    }

    pub fn into_result(self) -> MonitoredItemModifyResult {
        self.update
    }
}
