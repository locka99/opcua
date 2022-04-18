// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use opcua::server::prelude::*;

pub fn add_control_switches(server: &mut Server, ns: u16) {
    // The address space is guarded so obtain a lock to change it
    let abort_node_id = NodeId::new(ns, "abort");

    let address_space = server.address_space();
    let server_state = server.server_state();

    {
        let mut address_space = address_space.write();
        let folder_id = address_space
            .add_folder("Control", "Control", &NodeId::objects_folder_id())
            .unwrap();

        VariableBuilder::new(&abort_node_id, "Abort", "Abort")
            .data_type(DataTypeId::Boolean)
            .value(false)
            .writable()
            .organized_by(&folder_id)
            .insert(&mut address_space);
    }

    server.add_polling_action(1000, move || {
        let address_space = address_space.read();
        // Test for abort flag
        let abort = if let Ok(v) = address_space.get_variable_value(abort_node_id.clone()) {
            match v.value {
                Some(Variant::Boolean(v)) => v,
                _ => {
                    panic!("Abort value should be true or false");
                }
            }
        } else {
            panic!("Abort value should be in address space");
        };
        // Check if abort has been set to true, in which case abort
        if abort {
            let mut server_state = server_state.write();
            server_state.abort();
        }
    });
}
