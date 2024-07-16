// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::sync::Arc;

use opcua::{
    server::{
        address_space::VariableBuilder, node_manager::memory::SimpleNodeManager, SubscriptionCache,
    },
    types::{DataTypeId, NodeId, StatusCode, Variant},
};
use tokio_util::sync::CancellationToken;

pub fn add_control_switches(
    ns: u16,
    manager: Arc<SimpleNodeManager>,
    subscriptions: Arc<SubscriptionCache>,
    token: CancellationToken,
) {
    // The address space is guarded so obtain a lock to change it
    let abort_node_id = NodeId::new(ns, "abort");
    let control_folder_id = NodeId::new(ns, "control");

    {
        let mut address_space = manager.address_space().write();
        address_space.add_folder(
            &control_folder_id,
            "Control",
            "Control",
            &NodeId::objects_folder_id(),
        );

        VariableBuilder::new(&abort_node_id, "Abort", "Abort")
            .data_type(DataTypeId::Boolean)
            .value(false)
            .writable()
            .organized_by(&control_folder_id)
            .insert(&mut address_space);
    }

    let mgr_ref = manager.clone();
    manager
        .inner()
        .add_write_callback(abort_node_id.clone(), move |v, _| {
            if let Some(Variant::Boolean(val)) = v.value {
                if val {
                    token.cancel();
                }
                mgr_ref
                    .set_value(&subscriptions, &abort_node_id, None, v)
                    .unwrap();
                StatusCode::Good
            } else {
                StatusCode::BadTypeMismatch
            }
        });
}
