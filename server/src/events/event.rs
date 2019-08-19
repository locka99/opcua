//! Contains functions for generating events and adding them to the address space of the server.
use opcua_types::{
    AttributeId, ByteString, DateTime, DateTimeUtc, ExtensionObject, Guid, LocalizedText, NodeId,
    ObjectId, ObjectTypeId, QualifiedName, service_types::TimeZoneDataType, UAString, VariableTypeId,
    Variant,
};

use crate::address_space::{
    AddressSpace,
    object::ObjectBuilder,
    relative_path::*,
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
    pub fn new<R, S, T, U, V>(node_id: R, browse_name: S, display_name: T, parent_node: U, source_node: V, time: DateTime) -> BaseEventType
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

        Self {
            object_builder,
            event_id: Guid::new().into(),
            event_type: Self::event_type_id(),
            source_node,
            source_name: UAString::null(),
            time: time.clone(),
            receive_time: time,
            local_time: None,
            message: LocalizedText::from(""),
            severity: 1,
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.object_builder.get_node_id()
    }
}


fn event_source_node(event_id: &NodeId, address_space: &AddressSpace) -> Option<NodeId> {
    if let Ok(event_time_node) = find_node_from_browse_path(address_space, event_id, &["SourceNode".into()]) {
        if let Some(value) = event_time_node.as_node().get_attribute(AttributeId::Value) {
            if let Some(value) = value.value {
                match value {
                    Variant::NodeId(node_id) => Some(*node_id),
                    _ => None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn event_time(event_id: &NodeId, address_space: &AddressSpace) -> Option<DateTime> {
    if let Ok(event_time_node) = find_node_from_browse_path(address_space, event_id, &["Time".into()]) {
        if let Some(value) = event_time_node.as_node().get_attribute(AttributeId::Value) {
            if let Some(value) = value.value {
                match value {
                    Variant::DateTime(date_time) => Some(*date_time),
                    _ => None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub fn filter_events<T, R, F>(source_object_id: T, event_type_id: R, address_space: &AddressSpace, time_predicate: F) -> Option<Vec<NodeId>>
    where T: Into<NodeId>,
          R: Into<NodeId>,
          F: Fn(&DateTimeUtc) -> bool
{
    let event_type_id = event_type_id.into();
    let source_object_id = source_object_id.into();
    // Find events of type event_type_id
    if let Some(events) = address_space.find_objects_by_type(event_type_id) {
        let event_ids = events.iter()
            .filter(move |event_id| {
                let mut filter = false;
                // Browse the relative path for the "Time" variable
                if let Some(event_time) = event_time(event_id, address_space) {
                    // Filter on those happened since the time
                    if time_predicate(&event_time.as_chrono()) {
                        if let Some(source_node) = event_source_node(event_id, address_space) {
                            // Whose source node is source_object_id
                            filter = source_node == source_object_id
                        }
                    }
                }
                filter
            })
            .cloned()
            .collect();
        Some(event_ids)
    } else {
        None
    }
}

pub fn purge_events<T, R>(source_object_id: T, event_type_id: R, address_space: &mut AddressSpace, happened_before: &DateTimeUtc) -> usize
    where T: Into<NodeId>,
          R: Into<NodeId>
{
    if let Some(events) = filter_events(source_object_id, event_type_id, address_space, move |event_time| event_time < happened_before) {
        // Delete these events from the address space
        let len = events.len();
        events.into_iter().for_each(|node_id| {
            address_space.delete(&node_id, true);
        });
        len
    } else {
        0
    }
}

/// Searches for events of the specified event type which reference the source object
pub fn events_for_object<T, R>(source_object_id: T, event_type_id: R, address_space: &AddressSpace, happened_since: &DateTimeUtc) -> Option<Vec<NodeId>>
    where T: Into<NodeId>,
          R: Into<NodeId>
{
    filter_events(source_object_id, event_type_id, address_space, move |event_time| event_time >= happened_since)
}

#[test]
fn test_event_source_node() {
    let mut address_space = AddressSpace::new();
    // Raise an event
    let event_id = NodeId::next_numeric(2);
    let event = BaseEventType::new(&event_id, "Event1", "", NodeId::objects_folder_id(), ObjectId::Server_ServerCapabilities, DateTime::now());
    assert!(event.raise(&mut address_space).is_ok());
    // Check that the helper fn returns the expected source node
    assert_eq!(event_source_node(&event_id, &address_space).unwrap(), ObjectId::Server_ServerCapabilities.into());
}

#[test]
fn test_event_time() {
    let mut address_space = AddressSpace::new();
    // Raise an event
    let event_id = NodeId::next_numeric(2);
    let event = BaseEventType::new(&event_id, "Event1", "", NodeId::objects_folder_id(), ObjectId::Server_ServerCapabilities, DateTime::now());
    let expected_time = event.time.clone();
    assert!(event.raise(&mut address_space).is_ok());
    // Check that the helper fn returns the expected source node
    assert_eq!(event_time(&event_id, &address_space).unwrap(), expected_time);
}


#[test]
fn test_events_for_object() {
    let mut address_space = AddressSpace::new();

    // Raise an event
    let happened_since = chrono::Utc::now();
    let event_id = NodeId::next_numeric(2);
    let event = BaseEventType::new(&event_id, "Event1", "", NodeId::objects_folder_id(), ObjectId::Server_ServerCapabilities, DateTime::now());
    assert!(event.raise(&mut address_space).is_ok());

    // Check that event can be found
    let mut events = events_for_object(ObjectId::Server_ServerCapabilities, ObjectTypeId::BaseEventType, &address_space, &happened_since).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events.pop().unwrap(), event_id);
}

#[test]
fn test_purge_events() {
    use opcua_console_logging;
    use opcua_types::Identifier;

    opcua_console_logging::init();

    let mut address_space = AddressSpace::new();

    // We're going to create a fake node to get the numeric value out of it
    let first_node_id = match NodeId::next_numeric(100).identifier {
        Identifier::Numeric(i) => i + 1,
        _ => panic!()
    };

    // Get the next numeric value
    let mut last_node_id = 0;

    // Raise a bunch of events
    let start_time = DateTime::now().as_chrono();
    let mut time = start_time.clone();


    (0..10).for_each(|i| {
        let event_id = NodeId::new(100, format!("Event{}", i));
        let event_name = format!("Event {}", i);
        let event = BaseEventType::new(&event_id, event_name, "", NodeId::objects_folder_id(), ObjectId::Server_ServerCapabilities, DateTime::from(time));
        assert!(event.raise(&mut address_space).is_ok());

        if i == 4 {
            last_node_id = match NodeId::next_numeric(100).identifier {
                Identifier::Numeric(i) => i,
                _ => panic!()
            };
        }

        time = time + chrono::Duration::minutes(5);
    });

    // Expect all events
    let events = events_for_object(ObjectId::Server_ServerCapabilities, ObjectTypeId::BaseEventType, &address_space, &start_time).unwrap();
    assert_eq!(events.len(), 10);

    // Purge all events before halfway
    let happened_before = start_time + chrono::Duration::minutes(25);
    assert_eq!(purge_events(ObjectId::Server_ServerCapabilities, ObjectTypeId::BaseEventType, &mut address_space, &happened_before), 5);
    let events = events_for_object(ObjectId::Server_ServerCapabilities, ObjectTypeId::BaseEventType, &address_space, &start_time).unwrap();
    assert_eq!(events.len(), 5);

    // There should be NO reference left to any of the events we purged in the address space
    let references = address_space.references();
    (0..5).for_each(|i| {
        let event_id = NodeId::new(100, format!("Event{}", i));
        assert!(!references.reference_to_node_exists(&event_id));
    });
    (5..10).for_each(|i| {
        let event_id = NodeId::new(100, format!("Event{}", i));
        assert!(references.reference_to_node_exists(&event_id));
    });

    // Now we know any properties that were created fall between first and last node
    // None of the properties should exist either - just scan over a bunch of node_idsfor a bunch
    (first_node_id..last_node_id).for_each(|i| {
        // Event properties were numerically assigned from the NS
        let node_id = NodeId::new(100, i);
        assert!(address_space.find(&node_id).is_none());
        assert!(!references.reference_to_node_exists(&node_id));
    });
}