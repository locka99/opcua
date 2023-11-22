// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::{
    atomic::{AtomicU16, AtomicU32, Ordering},
    Arc,
};

use chrono;
use rand;

use opcua::server::{events::event::*, prelude::*};

pub fn add_machinery(server: &mut Server, ns: u16, raise_event: bool) {
    let address_space = server.address_space();
    let machine1_counter = Arc::new(AtomicU16::new(0));
    let machine2_counter = Arc::new(AtomicU16::new(50));

    let (machine1_id, machine2_id) = {
        let mut address_space = address_space.write();
        add_machinery_model(&mut address_space, ns);

        // Create a folder under static folder
        let devices_folder_id = address_space
            .add_folder("Devices", "Devices", &NodeId::objects_folder_id())
            .unwrap();

        // Create the machine events folder
        let _ = address_space.add_folder_with_id(
            &machine_events_folder_id(ns),
            "Events",
            "Events",
            &devices_folder_id,
        );

        // Create an object representing a machine that cycles from 0 to 100. Each time it cycles it will create an event
        let machine1_id = add_machine(
            &mut address_space,
            ns,
            devices_folder_id.clone(),
            "Machine 1",
            machine1_counter.clone(),
        );
        let machine2_id = add_machine(
            &mut address_space,
            ns,
            devices_folder_id,
            "Machine 2",
            machine2_counter.clone(),
        );
        (machine1_id, machine2_id)
    };

    // Increment counters
    server.add_polling_action(300, move || {
        let mut address_space = address_space.write();
        increment_counter(
            &mut address_space,
            ns,
            machine1_counter.clone(),
            &machine1_id,
            raise_event,
        );
        increment_counter(
            &mut address_space,
            ns,
            machine2_counter.clone(),
            &machine2_id,
            raise_event,
        );
    });
}

fn machine_type_id(ns: u16) -> NodeId {
    NodeId::new(ns, "MachineTypeId")
}

fn machine_events_folder_id(ns: u16) -> NodeId {
    NodeId::new(ns, "MachineEvents")
}

fn add_machinery_model(address_space: &mut AddressSpace, ns: u16) {
    // Create a machine counter type derived from BaseObjectType
    let machine_type_id = machine_type_id(ns);
    ObjectTypeBuilder::new(&machine_type_id, "MachineCounterType", "MachineCounterType")
        .is_abstract(false)
        .subtype_of(ObjectTypeId::BaseObjectType)
        .generates_event(MachineCycledEventType::event_type_id(ns))
        .insert(address_space);

    // Add some variables to the type
    let counter_id = NodeId::next_numeric(ns);
    VariableBuilder::new(&counter_id, "Counter", "Counter")
        .data_type(DataTypeId::UInt16)
        .property_of(machine_type_id.clone())
        .has_type_definition(VariableTypeId::PropertyType)
        .has_modelling_rule(ObjectId::ModellingRule_Mandatory)
        .insert(address_space);

    // Create a counter cycled event type
    let machine_cycled_event_type_id = MachineCycledEventType::event_type_id(ns);
    ObjectTypeBuilder::new(
        &machine_cycled_event_type_id,
        "MachineCycledEventType",
        "MachineCycledEventType",
    )
    .is_abstract(false)
    .subtype_of(ObjectTypeId::BaseEventType)
    .insert(address_space);
}

fn add_machine(
    address_space: &mut AddressSpace,
    ns: u16,
    folder_id: NodeId,
    name: &str,
    counter: Arc<AtomicU16>,
) -> NodeId {
    let machine_id = NodeId::new(ns, UAString::from(name));
    // Create a machine. Since machines generate events, the event notifier says that it does.
    ObjectBuilder::new(&machine_id, name, name)
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(folder_id)
        .has_type_definition(machine_type_id(ns))
        .insert(address_space);

    let counter_id = NodeId::new(ns, format!("{} Counter", name));
    VariableBuilder::new(&counter_id, "Counter", "Counter")
        .property_of(machine_id.clone())
        .data_type(DataTypeId::UInt16)
        .has_type_definition(VariableTypeId::PropertyType)
        .value_getter(AttrFnGetter::new_boxed(
            move |_, _, _, _, _, _| -> Result<Option<DataValue>, StatusCode> {
                let value = counter.load(Ordering::Relaxed);
                Ok(Some(DataValue::new_now(value)))
            },
        ))
        .insert(address_space);

    machine_id
}

pub struct MachineCycledEventType {
    base: BaseEventType,
}

impl Event for MachineCycledEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

impl MachineCycledEventType {
    pub fn event_type_id(ns: u16) -> NodeId {
        NodeId::new(ns, "MachineCycledEventId")
    }
}

lazy_static! {
    static ref MACHINE_CYCLED_EVENT_ID: AtomicU32 = AtomicU32::new(1);
}

impl MachineCycledEventType {
    fn new<R, S, T, U, V>(
        machine_name: &str,
        ns: u16,
        node_id: R,
        browse_name: S,
        display_name: T,
        parent_node: U,
        source_node: V,
        time: DateTime,
    ) -> Self
    where
        R: Into<NodeId>,
        S: Into<QualifiedName>,
        T: Into<LocalizedText>,
        U: Into<NodeId>,
        V: Into<NodeId>,
    {
        let event_type_id = MachineCycledEventType::event_type_id(ns);
        let source_node: NodeId = source_node.into();
        MachineCycledEventType {
            base: BaseEventType::new(
                node_id,
                event_type_id,
                browse_name,
                display_name,
                parent_node,
                time,
            )
            .source_node(source_node.clone())
            .source_name(UAString::from(machine_name))
            .message(LocalizedText::from(format!(
                "A machine cycled event from machine {}",
                source_node
            )))
            .severity(rand::random::<u16>() % 999u16 + 1u16),
        }
    }
}

fn raise_machine_cycled_event(
    address_space: &mut AddressSpace,
    ns: u16,
    source_machine_id: &NodeId,
) {
    // Remove old events
    let now = chrono::Utc::now();
    let happened_before = now - chrono::Duration::minutes(5);
    purge_events(
        source_machine_id,
        MachineCycledEventType::event_type_id(ns),
        address_space,
        &happened_before,
    );

    let machine_name = if let Some(node) = address_space.find_node(source_machine_id) {
        format!("{}", node.as_node().display_name().text)
    } else {
        "Machine ???".to_string()
    };

    // New event
    let event_node_id = NodeId::next_numeric(ns);
    let event_id = MACHINE_CYCLED_EVENT_ID.fetch_add(1, Ordering::Relaxed);
    let event_name = format!("Event{}", event_id);
    let now = DateTime::now();
    let mut event = MachineCycledEventType::new(
        &machine_name,
        ns,
        &event_node_id,
        event_name.clone(),
        event_name,
        machine_events_folder_id(ns),
        source_machine_id,
        now,
    );

    // create an event object in a folder with the
    let _ = event.raise(address_space);
}

fn increment_counter(
    address_space: &mut AddressSpace,
    ns: u16,
    machine_counter: Arc<AtomicU16>,
    machine_id: &NodeId,
    raise_event: bool,
) {
    let c = machine_counter.load(Ordering::Relaxed);
    let c = if c < 99 {
        c + 1
    } else {
        if raise_event {
            // Raise new event
            raise_machine_cycled_event(address_space, ns, machine_id);
        }
        0
    };
    machine_counter.store(c, Ordering::Relaxed);
}
