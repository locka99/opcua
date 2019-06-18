//! Contains functions for generating events and adding them to the address space of the server.
use opcua_types::{UAString, NodeId};

use crate::address_space::AddressSpace;

pub trait Event {
    /// The event type that the event is of
    fn event_type(&self) -> NodeId;
    /// Populates into the event into the address space
    fn populate(&self, event_id: UAString, address_space: &mut AddressSpace);
}

/// Raises an event in the address space, returning
pub fn raise_event<E>(event: E, address_space: &mut AddressSpace) -> UAString
    where E: Event
{
    let event_id = UAString::from("TODO");
    // Populate
    event.populate(event_id.clone(), address_space);
    event_id
}
