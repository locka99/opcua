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
    if let Some(events) = address_space.find_objects_by_type(event_type_id, true) {
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
            .collect::<Vec<NodeId>>();
        if event_ids.is_empty() { None } else { Some(event_ids) }
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
        info!("Deleting some events from the address space");
        let len = events.len();
        events.into_iter().for_each(|node_id| {
            debug!("Deleting event {}", node_id);
            address_space.delete(&node_id, true);
        });
        len
    } else {
        0
    }
}

/// Searches for events of the specified event type which reference the source object
pub fn events_for_object<T>(source_object_id: T, address_space: &AddressSpace, happened_since: &DateTimeUtc) -> Option<Vec<NodeId>>
    where T: Into<NodeId>
{
    filter_events(source_object_id, ObjectTypeId::BaseEventType, address_space, move |event_time| event_time >= happened_since)
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
    let mut events = events_for_object(ObjectId::Server_ServerCapabilities, &address_space, &happened_since).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events.pop().unwrap(), event_id);
}

#[test]
#[ignore]
fn test_purge_events() {
    use opcua_console_logging;
    use opcua_types::Identifier;

    opcua_console_logging::init();

    let mut address_space = AddressSpace::new();

    // Nodes will be created in this namespace
    let ns = 100;

    // This test is going to raise a bunch of events and then purge some of them. The purged
    // events should be the ones expected to be purged and there should be no trace of them
    // in the address space after they are removed.

    // Raising events will create bunch of numeric node ids for their properties. This
    // call will find out the node id that the first node is most likely to have (note that if
    // tests are run concurrently that use next_numeric() then they are not going to belong to this
    // test but that does not matter.
    let first_node_id = match NodeId::next_numeric(ns).identifier {
        Identifier::Numeric(i) => i + 1,
        _ => panic!()
    };

    let source_node = ObjectId::Server_ServerCapabilities;

    // Raise a bunch of events
    let start_time = DateTime::now().as_chrono();
    let mut time = start_time.clone();
    let mut last_purged_node_id = 0;

    (0..10).for_each(|i| {
        let event_id = NodeId::new(ns, format!("Event{}", i));
        let event_name = format!("Event {}", i);
        let event = BaseEventType::new(&event_id, event_name, "", NodeId::objects_folder_id(), source_node, DateTime::from(time));
        assert!(event.raise(&mut address_space).is_ok());

        // The first 5 events will be purged, so note the last node id here because none of the
        // ids between start and end should survive when tested.
        if i == 4 {
            last_purged_node_id = match NodeId::next_numeric(ns).identifier {
                Identifier::Numeric(i) => i,
                _ => panic!()
            };
        }

        time = time + chrono::Duration::minutes(5);
    });

    // Expect all events
    let events = events_for_object(source_node, &address_space, &start_time).unwrap();
    assert_eq!(events.len(), 10);

    // Purge all events up to halfway
    let happened_before = start_time + chrono::Duration::minutes(25);
    assert_eq!(purge_events(source_node, ObjectTypeId::BaseEventType, &mut address_space, &happened_before), 5);

    // Should have only 5 events left
    let events = events_for_object(source_node, &address_space, &start_time).unwrap();
    assert_eq!(events.len(), 5);

    // There should be NO reference left to any of the events we purged in the address space
    let references = address_space.references();
    (0..5).for_each(|i| {
        let event_id = NodeId::new(ns, format!("Event{}", i));
        assert!(!references.reference_to_node_exists(&event_id));
    });
    (5..10).for_each(|i| {
        let event_id = NodeId::new(ns, format!("Event{}", i));
        assert!(references.reference_to_node_exists(&event_id));
    });

    // The node that generated the events should not be purged
    // This was a bug during development
    let source_node: NodeId = source_node.into();
    debug!("Expecting to still find source node {}", source_node);
    assert!(address_space.find_node(&source_node).is_some());

    // All of properties that were created for purged nodes fall between first and last node id.
    // None of the properties should exist now either - just scan over the range of numbers these
    // nodes reside in.
    (first_node_id..last_purged_node_id).for_each(|i| {
        // Event properties were numerically assigned from the NS
        let node_id = NodeId::new(ns, i);
        assert!(address_space.find_node(&node_id).is_none());
        assert!(!references.reference_to_node_exists(&node_id));
    });
}
