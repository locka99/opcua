//! Contains functions for generating events and adding them to the address space of the server.
use opcua_types::{
    UAString, NodeId, DateTime, Guid, ByteString, LocalizedText, QualifiedName, Variant,
    ExtensionObject, ObjectId, ObjectTypeId,
    service_types::TimeZoneDataType,
};

use crate::address_space::{
    AddressSpace,
    object::ObjectBuilder,
    variable::VariableBuilder,
};

/// Events can implement this to populate themselves into the address space
pub trait Event {
    /// Populates into the event into the address space
    fn insert<R, S, N>(self, node_id: &NodeId, browse_name: R, description: S, parent_node: N, address_space: &mut AddressSpace)
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              N: Into<NodeId>;
}

/// This correspondes to BaseEventType definition in OPC UA Part 5
pub struct BaseEventType {
    /// A unique identifier for an event, e.g. a GUID in a byte string
    pub event_id: ByteString,
    /// Event type describes the type of event
    pub event_type: NodeId,
    /// Source node identifies the node that the event originated from
    /// or null.
    pub source_node: NodeId,
    /// Source name provides the description of the source of the event,
    /// e.g. the display of the event source
    pub source_name: UAString,
    /// Time provides the time the event occurred. As close
    /// to the event generator as possible.
    pub time: DateTime,
    /// Receive time provides the time the OPC UA server received
    /// the event from the underlying device of another server.
    pub receive_time: DateTime,
    /// Local time (optional) is a structure containing
    /// the offset and daylightsaving flag.
    pub local_time: Option<TimeZoneDataType>,
    /// Message provides a human readable localizable text description
    /// of the event.
    pub message: LocalizedText,
    /// Severity is an indication of the urgency of the event. Values from 1 to 1000, with 1 as the lowest
    /// severity and 1000 being the highest. A value of 1000 would indicate an event of catastrophic nature.
    pub severity: u16,
}

impl Default for BaseEventType {
    fn default() -> Self {
        let now = DateTime::now();
        Self {
            event_id: Guid::new().into(),
            event_type: ObjectTypeId::BaseEventType.into(),
            source_node: NodeId::null(),
            source_name: UAString::null(),
            time: now.clone(),
            receive_time: now,
            local_time: None,
            message: LocalizedText::from(""),
            severity: 1,
        }
    }
}

fn insert_component<R, V>(event_id: &NodeId, namespace: u16, browse_name: R, value: V, address_space: &mut AddressSpace)
    where R: Into<QualifiedName>,
          V: Into<Variant>
{
    let id = NodeId::next_numeric(namespace);
    VariableBuilder::new(&id, browse_name, "")
        .component_of(event_id.clone())
        .value(value)
        .insert(address_space);
}

impl Event for BaseEventType {
    fn insert<R, S, N>(self, node_id: &NodeId, browse_name: R, description: S, parent_node: N, address_space: &mut AddressSpace)
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              N: Into<NodeId>
    {
        // create an event object in a folder with the
        let namespace = node_id.namespace;

        ObjectBuilder::new(node_id, browse_name, description)
            .organized_by(parent_node)
            .has_type_definition(self.event_type.clone())
            .insert(address_space);

        insert_component(node_id, namespace, "EventId", self.event_id.clone(), address_space);
        insert_component(node_id, namespace, "EventType", self.event_type, address_space);
        insert_component(node_id, namespace, "SourceNode", self.source_node, address_space);
        insert_component(node_id, namespace, "SourceName", self.source_name, address_space);
        insert_component(node_id, namespace, "Time", self.time, address_space);
        insert_component(node_id, namespace, "ReceiveTime", self.receive_time, address_space);
        insert_component(node_id, namespace, "Message", self.message, address_space);
        insert_component(node_id, namespace, "Severity", self.severity, address_space);

        // LocalTime is optional
        if let Some(ref local_time) = self.local_time {
            // Serialise to extension object
            let local_time = ExtensionObject::from_encodable(ObjectId::TimeZoneDataType_Encoding_DefaultBinary, local_time);
            insert_component(node_id, namespace, "LocalTime", local_time, address_space);
        }
    }
}
