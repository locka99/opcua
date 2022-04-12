// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains functions for generating events and adding them to the address space of the server.
use crate::types::{
    service_types::TimeZoneDataType, AttributeId, ByteString, DataTypeId, DateTime, DateTimeUtc,
    ExtensionObject, Guid, LocalizedText, NodeId, NumericRange, ObjectId, ObjectTypeId,
    QualifiedName, TimestampsToReturn, UAString, VariableTypeId, Variant,
};

use crate::server::address_space::{
    object::ObjectBuilder, relative_path::*, variable::VariableBuilder, AddressSpace,
};

/// Events can implement this to populate themselves into the address space
pub trait Event {
    type Err;

    /// Tests if the event is valid
    fn is_valid(&self) -> bool;

    /// Raises the event, i.e. adds the object into the address space. The event must be valid to be inserted.
    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err>;
}

/// This corresponds to BaseEventType definition in OPC UA Part 5
pub struct BaseEventType {
    /// Node id
    node_id: NodeId,
    /// Parent node
    parent_node: NodeId,
    /// Browse name
    browse_name: QualifiedName,
    /// Display name
    display_name: LocalizedText,
    /// A unique identifier for an event, e.g. a GUID in a byte string
    event_id: ByteString,
    /// Event type describes the type of event
    event_type: NodeId,
    /// Source node identifies the node that the event originated from
    /// or null.
    source_node: NodeId,
    /// Source name provides the description of the source of the event,
    /// e.g. the display of the event source
    source_name: UAString,
    /// Time provides the time the event occurred. As close
    /// to the event generator as possible.
    time: DateTime,
    /// Receive time provides the time the OPC UA server received
    /// the event from the underlying device of another server.
    receive_time: DateTime,
    /// Local time (optional) is a structure containing
    /// the offset and daylightsaving flag.
    local_time: Option<TimeZoneDataType>,
    /// Message provides a human readable localizable text description
    /// of the event.
    message: LocalizedText,
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
    severity: u16,
    /// Properties as string/values in the order they were added
    properties: Vec<(LocalizedText, Variant)>,
}

impl Event for BaseEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        !self.node_id.is_null()
            && !self.event_id.is_null_or_empty()
            && !self.event_type.is_null()
            && self.severity >= 1
            && self.severity <= 1000
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        if self.is_valid() {
            // create an event object in a folder with the
            let ns = self.node_id.namespace;
            let node_id = self.node_id.clone();

            let object_builder = ObjectBuilder::new(
                &self.node_id,
                self.browse_name.clone(),
                self.display_name.clone(),
            )
            .organized_by(self.parent_node.clone())
            .has_type_definition(self.event_type.clone());

            let object_builder = if !self.source_node.is_null() {
                object_builder.has_event_source(self.source_node.clone())
            } else {
                object_builder
            };
            object_builder.insert(address_space);

            // Mandatory properties
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "EventId",
                "EventId",
                DataTypeId::ByteString,
                self.event_id.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "EventType",
                "EventType",
                DataTypeId::NodeId,
                self.event_type.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "SourceNode",
                "SourceNode",
                DataTypeId::NodeId,
                self.source_node.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "SourceName",
                "SourceName",
                DataTypeId::String,
                self.source_name.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "Time",
                "Time",
                DataTypeId::UtcTime,
                self.time,
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "ReceiveTime",
                "ReceiveTime",
                DataTypeId::UtcTime,
                self.receive_time,
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "Message",
                "Message",
                DataTypeId::LocalizedText,
                self.message.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "Severity",
                "Severity",
                DataTypeId::UInt16,
                self.severity,
                address_space,
            );

            // LocalTime is optional
            if let Some(ref local_time) = self.local_time {
                // Serialise to extension object
                let local_time = ExtensionObject::from_encodable(
                    ObjectId::TimeZoneDataType_Encoding_DefaultBinary,
                    local_time,
                );
                self.add_property(
                    &node_id,
                    NodeId::next_numeric(ns),
                    "LocalTime",
                    "LocalTime",
                    DataTypeId::TimeZoneDataType,
                    local_time,
                    address_space,
                );
            }

            Ok(node_id)
        } else {
            error!("Event is invalid and will not be inserted");
            Err(())
        }
    }
}

impl BaseEventType {
    pub fn new_now<R, E, S, T, U>(
        node_id: R,
        event_type_id: E,
        browse_name: S,
        display_name: T,
        parent_node: U,
    ) -> Self
    where
        R: Into<NodeId>,
        E: Into<NodeId>,
        S: Into<QualifiedName>,
        T: Into<LocalizedText>,
        U: Into<NodeId>,
    {
        let now = DateTime::now();
        Self::new(
            node_id,
            event_type_id,
            browse_name,
            display_name,
            parent_node,
            now,
        )
    }

    pub fn new<R, E, S, T, U>(
        node_id: R,
        event_type_id: E,
        browse_name: S,
        display_name: T,
        parent_node: U,
        time: DateTime,
    ) -> Self
    where
        R: Into<NodeId>,
        E: Into<NodeId>,
        S: Into<QualifiedName>,
        T: Into<LocalizedText>,
        U: Into<NodeId>,
    {
        Self {
            node_id: node_id.into(),
            browse_name: browse_name.into(),
            display_name: display_name.into(),
            parent_node: parent_node.into(),
            event_id: Guid::new().into(),
            event_type: event_type_id.into(),
            source_node: NodeId::null(),
            source_name: UAString::null(),
            time,
            receive_time: time,
            local_time: None,
            message: LocalizedText::null(),
            severity: 1,
            properties: Vec::with_capacity(20),
        }
    }

    /// Add a property to the event object
    pub fn add_property<T, R, S, U, V>(
        &mut self,
        event_id: &NodeId,
        property_id: T,
        browse_name: R,
        display_name: S,
        data_type: U,
        value: V,
        address_space: &mut AddressSpace,
    ) where
        T: Into<NodeId>,
        R: Into<QualifiedName>,
        S: Into<LocalizedText>,
        U: Into<NodeId>,
        V: Into<Variant>,
    {
        let display_name = display_name.into();
        let value = value.into();
        self.properties.push((display_name.clone(), value.clone()));

        Self::do_add_property(
            event_id,
            property_id,
            browse_name,
            display_name,
            data_type,
            value,
            address_space,
        )
    }

    /// Helper function inserts a property for the event
    fn do_add_property<T, R, S, U, V>(
        event_id: &NodeId,
        property_id: T,
        browse_name: R,
        display_name: S,
        data_type: U,
        value: V,
        address_space: &mut AddressSpace,
    ) where
        T: Into<NodeId>,
        R: Into<QualifiedName>,
        S: Into<LocalizedText>,
        U: Into<NodeId>,
        V: Into<Variant>,
    {
        VariableBuilder::new(&property_id.into(), browse_name, display_name)
            .property_of(event_id.clone())
            .has_type_definition(VariableTypeId::PropertyType)
            .data_type(data_type)
            .value(value)
            .insert(address_space);
    }

    pub fn message<T>(mut self, message: T) -> Self
    where
        T: Into<LocalizedText>,
    {
        self.message = message.into();
        self
    }

    pub fn source_node<T>(mut self, source_node: T) -> Self
    where
        T: Into<NodeId>,
    {
        self.source_node = source_node.into();
        self
    }

    pub fn source_name<T>(mut self, source_name: T) -> Self
    where
        T: Into<UAString>,
    {
        self.source_name = source_name.into();
        self
    }

    pub fn local_time(mut self, local_time: Option<TimeZoneDataType>) -> Self {
        self.local_time = local_time;
        self
    }

    pub fn severity(mut self, severity: u16) -> Self {
        self.severity = severity;
        self
    }

    pub fn receive_time(mut self, receive_time: DateTime) -> Self {
        self.receive_time = receive_time;
        self
    }

    pub fn properties(&self) -> &Vec<(LocalizedText, Variant)> {
        &self.properties
    }
}

/// This is a macro for types that aggregate from BaseEventType and want to expose the
/// builder functions.
macro_rules! base_event_impl {
    ( $event:ident, $base:ident ) => {
        impl $event {
            pub fn add_property<T, R, S, U, V>(
                &mut self,
                event_id: &NodeId,
                property_id: T,
                browse_name: R,
                display_name: S,
                data_type: U,
                value: V,
                address_space: &mut AddressSpace,
            ) where
                T: Into<NodeId>,
                R: Into<QualifiedName>,
                S: Into<LocalizedText>,
                U: Into<NodeId>,
                V: Into<Variant>,
            {
                self.$base.add_property(
                    event_id,
                    property_id,
                    browse_name,
                    display_name,
                    data_type,
                    value,
                    address_space,
                );
            }

            pub fn message<T>(mut self, message: T) -> $event
            where
                T: Into<LocalizedText>,
            {
                self.$base = self.$base.message(message);
                self
            }

            pub fn source_node<T>(mut self, source_node: T) -> $event
            where
                T: Into<NodeId>,
            {
                self.$base = self.$base.source_node(source_node);
                self
            }

            pub fn source_name<T>(mut self, source_name: T) -> $event
            where
                T: Into<UAString>,
            {
                self.$base = self.$base.source_name(source_name);
                self
            }

            pub fn local_time(mut self, local_time: Option<TimeZoneDataType>) -> $event {
                self.$base = self.$base.local_time(local_time);
                self
            }

            pub fn severity(mut self, severity: u16) -> $event {
                self.$base = self.$base.severity(severity);
                self
            }

            pub fn receive_time(mut self, receive_time: DateTime) -> $event {
                self.$base = self.$base.receive_time(receive_time);
                self
            }
        }
    };
}

fn event_source_node(event_id: &NodeId, address_space: &AddressSpace) -> Option<NodeId> {
    if let Ok(event_time_node) =
        find_node_from_browse_path(address_space, event_id, &["SourceNode".into()])
    {
        if let Some(value) = event_time_node.as_node().get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            NumericRange::None,
            &QualifiedName::null(),
        ) {
            if let Some(value) = value.value {
                match value {
                    Variant::NodeId(node_id) => Some(*node_id),
                    _ => None,
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
    // Find the Time variable under the event to return a timestamp.
    if let Ok(event_time_node) =
        find_node_from_browse_path(address_space, event_id, &["Time".into()])
    {
        if let Some(value) = event_time_node.as_node().get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            NumericRange::None,
            &QualifiedName::null(),
        ) {
            if let Some(value) = value.value {
                match value {
                    Variant::DateTime(date_time) => Some(*date_time),
                    _ => None,
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

/// Attempts to find events that were emitted by the source object based upon a time predicate
pub fn filter_events<T, R, F>(
    source_object_id: T,
    event_type_id: R,
    address_space: &AddressSpace,
    time_predicate: F,
) -> Option<Vec<NodeId>>
where
    T: Into<NodeId>,
    R: Into<NodeId>,
    F: Fn(&DateTimeUtc) -> bool,
{
    let event_type_id = event_type_id.into();
    let source_object_id = source_object_id.into();
    // Find events of type event_type_id
    if let Some(events) = address_space.find_objects_by_type(event_type_id, true) {
        let event_ids = events
            .iter()
            .filter(move |event_id| {
                let mut filter = false;
                if let Some(source_node) = event_source_node(event_id, address_space) {
                    // Browse the relative path for the "Time" variable
                    if let Some(event_time) = event_time(event_id, address_space) {
                        // Filter on those happened since the time
                        if time_predicate(&event_time.as_chrono()) {
                            // Whose source node is source_object_id
                            filter = source_node == source_object_id
                        }
                    }
                }
                filter
            })
            .cloned()
            .collect::<Vec<NodeId>>();
        if event_ids.is_empty() {
            None
        } else {
            Some(event_ids)
        }
    } else {
        None
    }
}

pub fn purge_events<T, R>(
    source_object_id: T,
    event_type_id: R,
    address_space: &mut AddressSpace,
    happened_before: &DateTimeUtc,
) -> usize
where
    T: Into<NodeId>,
    R: Into<NodeId>,
{
    if let Some(events) = filter_events(
        source_object_id,
        event_type_id,
        address_space,
        move |event_time| event_time < happened_before,
    ) {
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
pub fn events_for_object<T>(
    source_object_id: T,
    address_space: &AddressSpace,
    happened_since: &DateTimeUtc,
) -> Option<Vec<NodeId>>
where
    T: Into<NodeId>,
{
    filter_events(
        source_object_id,
        ObjectTypeId::BaseEventType,
        address_space,
        move |event_time| event_time >= happened_since,
    )
}

#[test]
fn test_event_source_node() {
    let mut address_space = AddressSpace::new();
    let ns = address_space.register_namespace("urn:test").unwrap();
    // Raise an event
    let event_id = NodeId::next_numeric(ns);
    let event_type_id = ObjectTypeId::BaseEventType;
    let mut event = BaseEventType::new(
        &event_id,
        event_type_id,
        "Event1",
        "",
        NodeId::objects_folder_id(),
        DateTime::now(),
    )
    .source_node(ObjectId::Server_ServerCapabilities);
    assert!(event.raise(&mut address_space).is_ok());
    // Check that the helper fn returns the expected source node
    assert_eq!(
        event_source_node(&event_id, &address_space).unwrap(),
        ObjectId::Server_ServerCapabilities.into()
    );
}

#[test]
fn test_event_time() {
    let mut address_space = AddressSpace::new();
    let ns = address_space.register_namespace("urn:test").unwrap();
    // Raise an event
    let event_id = NodeId::next_numeric(ns);
    let event_type_id = ObjectTypeId::BaseEventType;
    let mut event = BaseEventType::new(
        &event_id,
        event_type_id,
        "Event1",
        "",
        NodeId::objects_folder_id(),
        DateTime::now(),
    )
    .source_node(ObjectId::Server_ServerCapabilities);
    let expected_time = event.time.clone();
    assert!(event.raise(&mut address_space).is_ok());
    // Check that the helper fn returns the expected source node
    assert_eq!(
        event_time(&event_id, &address_space).unwrap(),
        expected_time
    );
}

#[test]
fn test_events_for_object() {
    let mut address_space = AddressSpace::new();
    let ns = address_space.register_namespace("urn:test").unwrap();

    // Raise an event
    let happened_since = chrono::Utc::now();
    let event_id = NodeId::next_numeric(ns);
    let event_type_id = ObjectTypeId::BaseEventType;
    let mut event = BaseEventType::new(
        &event_id,
        event_type_id,
        "Event1",
        "",
        NodeId::objects_folder_id(),
        DateTime::now(),
    )
    .source_node(ObjectId::Server_ServerCapabilities);
    assert!(event.raise(&mut address_space).is_ok());

    // Check that event can be found
    let mut events = events_for_object(
        ObjectId::Server_ServerCapabilities,
        &address_space,
        &happened_since,
    )
    .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events.pop().unwrap(), event_id);
}

#[test]
fn test_purge_events() {
    use crate::types::Identifier;

    crate::console_logging::init();

    let mut address_space = AddressSpace::new();

    // Nodes will be created in this namespace
    let ns = address_space.register_namespace("urn:mynamespace").unwrap();

    // This test is going to raise a bunch of events and then purge some of them. The purged
    // events should be the ones expected to be purged and there should be no trace of them
    // in the address space after they are removed.

    // Raising events will create bunch of numeric node ids for their properties. This
    // call will find out the node id that the first node is most likely to have (note that if
    // tests are run concurrently that use next_numeric() then they are not going to belong to this
    // test but that does not matter.
    let first_node_id = match NodeId::next_numeric(ns).identifier {
        Identifier::Numeric(i) => i + 1,
        _ => panic!(),
    };

    let source_node = ObjectId::Server_ServerCapabilities;

    // Raise a bunch of events
    let start_time = DateTime::now().as_chrono();
    let mut time = start_time.clone();
    let mut last_purged_node_id = 0;

    let event_type_id = ObjectTypeId::BaseEventType;

    (0..10).for_each(|i| {
        let event_id = NodeId::new(ns, format!("Event{}", i));
        let event_name = format!("Event {}", i);
        let mut event = BaseEventType::new(
            &event_id,
            event_type_id,
            event_name,
            "",
            NodeId::objects_folder_id(),
            DateTime::from(time),
        )
        .source_node(source_node);
        assert!(event.raise(&mut address_space).is_ok());

        // The first 5 events will be purged, so note the last node id here because none of the
        // ids between start and end should survive when tested.
        if i == 4 {
            last_purged_node_id = match NodeId::next_numeric(ns).identifier {
                Identifier::Numeric(i) => i,
                _ => panic!(),
            };
        }

        time = time + chrono::Duration::minutes(5);
    });

    // Expect all events
    let events = events_for_object(source_node, &address_space, &start_time).unwrap();
    assert_eq!(events.len(), 10);

    // Purge all events up to halfway
    let happened_before = start_time + chrono::Duration::minutes(25);
    assert_eq!(
        purge_events(
            source_node,
            ObjectTypeId::BaseEventType,
            &mut address_space,
            &happened_before
        ),
        5
    );

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
