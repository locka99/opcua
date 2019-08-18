//! Contains functions for generating events and adding them to the address space of the server.
use opcua_types::{
    ByteString, DateTime, DateTimeUtc, ExtensionObject, Guid, LocalizedText, NodeId, ObjectId, ObjectTypeId,
    QualifiedName, service_types::TimeZoneDataType, UAString, VariableId, VariableTypeId,
    Variant,
};

use crate::address_space::{
    AddressSpace,
    object::ObjectBuilder,
    variable::VariableBuilder,
};

/// Events can implement this to populate themselves into the address space
pub trait Event {
    type Err;

    /// Returns the event type id
    fn event_type_id() -> NodeId;

    /// Tests if the event is valid
    fn is_valid(&self) -> bool;

    /// Raises the event, i.e. adds the object into the address space. The event must be valid to be inserted.
    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err>;

    /// Helper function inserts a property for the event
    fn add_property<T, R, S, V>(event_id: &NodeId, property_id: T, browse_name: R, display_name: S, value: V, address_space: &mut AddressSpace)
        where T: Into<NodeId>,
              R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              V: Into<Variant>
    {
        VariableBuilder::new(&property_id.into(), browse_name, display_name)
            .property_of(event_id.clone())
            .has_type_definition(VariableTypeId::PropertyType)
            .value(value)
            .insert(address_space);
    }
}

/// This corresponds to BaseEventType definition in OPC UA Part 5
pub struct BaseEventType {
    /// Object builder for the event
    pub object_builder: ObjectBuilder,
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
    ///
    /// Guidance:
    ///
    /// * 801-1000 - High
    /// * 601-800 - Medium High
    /// * 401-600 - Medium
    /// * 201-400 - Medium Low
    /// * 1-200 - Low
    pub severity: u16,
}

impl Event for BaseEventType {
    type Err = ();

    fn event_type_id() -> NodeId {
        ObjectTypeId::BaseEventType.into()
    }

    fn is_valid(&self) -> bool {
        !self.event_id.is_null_or_empty() &&
            !self.event_type.is_null() &&
            self.severity >= 1 && self.severity <= 1000
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err>
    {
        if self.is_valid() {
            // create an event object in a folder with the
            let node_id = self.node_id();
            let ns = node_id.namespace;

            self.object_builder.insert(address_space);

            // Mandatory properties
            Self::add_property(&node_id, NodeId::next_numeric(ns), "EventId", "EventId", self.event_id.clone(), address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "EventType", "EventType", self.event_type, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "SourceNode", "SourceNode", self.source_node, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "SourceName", "SourceName", self.source_name, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "Time", "Time", self.time, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "ReceiveTime", "ReceiveTime", self.receive_time, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "Message", "Message", self.message, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "Severity", "Severity", self.severity, address_space);

            // LocalTime is optional
            if let Some(ref local_time) = self.local_time {
                // Serialise to extension object
                let local_time = ExtensionObject::from_encodable(ObjectId::TimeZoneDataType_Encoding_DefaultBinary, local_time);
                Self::add_property(&node_id, NodeId::next_numeric(ns), "LocalTime", "LocalTime", local_time, address_space);
            }

            Ok(node_id)
        } else {
            error!("Event is invalid and will not be inserted");
            Err(())
        }
    }
}

impl BaseEventType {
    pub fn new<R, S, T, U, V>(node_id: R, browse_name: S, display_name: T, parent_node: U, source_node: V) -> BaseEventType
        where R: Into<NodeId>,
              S: Into<QualifiedName>,
              T: Into<LocalizedText>,
              U: Into<NodeId>,
              V: Into<NodeId>
    {

        // create an event object in a folder with the
        let node_id = node_id.into();
        let source_node = source_node.into();

        let object_builder = ObjectBuilder::new(&node_id, browse_name, display_name)
            .organized_by(parent_node)
            .has_type_definition(Self::event_type_id())
            .has_event_source(source_node.clone());

        let now = DateTime::now();
        Self {
            object_builder,
            event_id: Guid::new().into(),
            event_type: Self::event_type_id(),
            source_node,
            source_name: UAString::null(),
            time: now.clone(),
            receive_time: now,
            local_time: None,
            message: LocalizedText::from(""),
            severity: 1,
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.object_builder.get_node_id()
    }
}

pub fn purge_events(event_type_id: &NodeId, source_node: &NodeId, before: DateTimeUtc) {}