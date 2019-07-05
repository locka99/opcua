use std::sync::{Arc, atomic::{AtomicU16, AtomicU32, Ordering}};

use opcua_server::{
    prelude::*,
    events::event::*,
};

pub fn add_machinery(server: &mut Server) {
    let address_space = server.address_space();
    let machine1_counter = Arc::new(AtomicU16::new(0));
    let machine2_counter = Arc::new(AtomicU16::new(50));

    let (machine1_id, machine2_id) = {
        let mut address_space = address_space.write().unwrap();
        add_machinery_model(&mut address_space);

        // Create a folder under static folder
        let devices_folder_id = address_space
            .add_folder("Devices", "Devices", &AddressSpace::objects_folder_id())
            .unwrap();

        // Create the machine events folder
        let _ = address_space
            .add_folder_with_id(&machine_events_folder_id(), "Events", "Events", &devices_folder_id);

        // Create an object representing a machine that cycles from 0 to 100. Each time it cycles it will create an event
        let machine1_id = add_machine(&mut address_space, devices_folder_id.clone(), "Machine 1", machine1_counter.clone());
        let machine2_id = add_machine(&mut address_space, devices_folder_id, "Machine 2", machine2_counter.clone());
        (machine1_id, machine2_id)
    };

    // Increment counters
    server.add_polling_action(1000, move || {
        let mut address_space = address_space.write().unwrap();
        increment_counter(&mut address_space, machine1_counter.clone(), &machine1_id);
        increment_counter(&mut address_space, machine2_counter.clone(), &machine2_id);
    });
}

fn machine_type_id() -> NodeId { NodeId::new(1, "MachineTypeId") }

fn machine_cycled_event_type_id() -> NodeId { NodeId::new(1, "MachineCycledEventId") }

fn machine_events_folder_id() -> NodeId { NodeId::new(1, "MachineEvents") }

fn add_machinery_model(address_space: &mut AddressSpace) {
    // Create a machine counter type derived from BaseObjectType
    let machine_type_id = machine_type_id();
    ObjectTypeBuilder::new(&machine_type_id, "MachineCounterType", "MachineCounterType")
        .is_abstract(false)
        .subtype_of(ObjectTypeId::BaseObjectType)
        .insert(address_space);

    // Add some variables to the type
    let counter_id = NodeId::next_numeric(1);
    VariableBuilder::new(&counter_id, "Counter", "Counter")
        .property_of(machine_type_id.clone())
        .has_type_definition(VariableTypeId::PropertyType)
        .has_modelling_rule(ObjectId::ModellingRule_Mandatory)
        .insert(address_space);

    // Create a counter cycled event type
    let machine_cycled_event_type_id = machine_cycled_event_type_id();
    ObjectTypeBuilder::new(&machine_cycled_event_type_id, "MachineCycledEventType", "MachineCycledEventType")
        .is_abstract(false)
        .subtype_of(ObjectTypeId::BaseEventType)
        .insert(address_space);
}

fn add_machine(address_space: &mut AddressSpace, folder_id: NodeId, name: &str, counter: Arc<AtomicU16>) -> NodeId {
    let namespace = 1;
    let machine_id = NodeId::next_numeric(namespace);

    // Create an object instance
    ObjectBuilder::new(&machine_id, name, name)
        .event_notifier(EventNotifier::empty())
        .organized_by(folder_id)
        .has_type_definition(machine_type_id())
        .insert(address_space);

    let counter_id = NodeId::next_numeric(namespace);
    VariableBuilder::new(&counter_id, "Counter", "Counter")
        .property_of(machine_id.clone())
        .has_type_definition(VariableTypeId::PropertyType)
        .value_getter(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
            let value = counter.load(Ordering::Relaxed);
            Ok(Some(DataValue::new(value)))
        })
        .insert(address_space);

    machine_id
}

/// This correspondes to BaseEventType definition in OPC UA Part 5
pub struct MachineCycledEventType {
    base: BaseEventType
}

impl Event for MachineCycledEventType {
    fn insert<R, S, N>(self, node_id: &NodeId, browse_name: R, description: S, parent_node: N, address_space: &mut AddressSpace)
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              N: Into<NodeId> {
        self.base.insert(node_id, browse_name, description, parent_node, address_space);
    }
}

lazy_static! {
    static ref MACHINE_CYCLED_EVENT_ID: AtomicU32 = AtomicU32::new(1);
}

fn create_machine_cycled_event(address_space: &mut AddressSpace, source_machine_id: &NodeId) {
    let mut event = MachineCycledEventType {
        base: Default::default()
    };
    event.base.event_type = machine_cycled_event_type_id();
    event.base.source_node = source_machine_id.clone();

    // create an event object in a folder with the
    let event_node_id = NodeId::next_numeric(1);
    let event_id = MACHINE_CYCLED_EVENT_ID.fetch_add(1, Ordering::Relaxed);
    let event_name = format!("Event{}", event_id);
    event.insert(&event_node_id, event_name.clone(), event_name, machine_events_folder_id(), address_space);
}

fn increment_counter(address_space: &mut AddressSpace, machine_counter: Arc<AtomicU16>, machine_id: &NodeId) {
    let c = machine_counter.load(Ordering::Relaxed);
    let c = if c < 99 {
        c + 1
    } else {
        create_machine_cycled_event(address_space, machine_id);
        0
    };
    machine_counter.store(c, Ordering::Relaxed);
}
