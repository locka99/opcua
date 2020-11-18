// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.NodeSet2.Part9.xml by tools/schema/gen_address_space.js
// DO NOT EDIT THIS FILE

#[allow(unused_imports)]
use std::{convert::TryFrom, str::FromStr};

#[allow(unused_imports)]
use crate::{
    address_space::{types::*, EventNotifier},
    prelude::{
        service_types::Argument, DataTypeId, ExtensionObject, LocalizedText, NodeId,
        ReferenceTypeId, UAString, Variant,
    },
};

#[allow(unused_variables)]
pub fn populate_address_space(address_space: &mut AddressSpace) {
    add_variable_1(address_space);
    add_variable_2(address_space);
    add_variable_3(address_space);
    add_variabletype_4(address_space);
    add_variabletype_5(address_space);
    add_variabletype_6(address_space);
    add_method_7(address_space);
    add_method_8(address_space);
    add_method_9(address_space);
    add_method_10(address_space);
    add_method_11(address_space);
    add_method_12(address_space);
    add_method_13(address_space);
    add_method_14(address_space);
    add_method_15(address_space);
    add_method_16(address_space);
    add_method_17(address_space);
    add_method_18(address_space);
    add_method_19(address_space);
    add_method_20(address_space);
    add_method_21(address_space);
    add_method_22(address_space);
    add_method_23(address_space);
    add_method_24(address_space);
    add_method_25(address_space);
    add_method_26(address_space);
    add_method_27(address_space);
    add_method_28(address_space);
    add_method_29(address_space);
    add_method_30(address_space);
    add_method_31(address_space);
}

fn add_variable_1(address_space: &mut AddressSpace) {
    // Variable
    let name = "AverageAlarmRate";
    let value = Variant::Empty;
    let node_id = NodeId::new(0, 17288);
    let node =
        Variable::new_data_value(&node_id, name, name, NodeId::new(0, 11), None, None, value);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 17289),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 17277),
                &ReferenceTypeId::HasTypeDefinition,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 17279),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_variable_2(address_space: &mut AddressSpace) {
    // Variable
    let name = "Rate";
    let value = Variant::Empty;
    let node_id = NodeId::new(0, 17289);
    let node = Variable::new_data_value(&node_id, name, name, NodeId::new(0, 5), None, None, value);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 68),
                &ReferenceTypeId::HasTypeDefinition,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 17288),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_variable_3(address_space: &mut AddressSpace) {
    // Variable
    let name = "Rate";
    let value = Variant::Empty;
    let node_id = NodeId::new(0, 17278);
    let node = Variable::new_data_value(&node_id, name, name, NodeId::new(0, 5), None, None, value);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 68),
                &ReferenceTypeId::HasTypeDefinition,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 17277),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_variabletype_4(address_space: &mut AddressSpace) {
    // VariableType
    let name = "TwoStateVariableType";
    let node_id = NodeId::new(0, 8995);
    let node = VariableType::new(&node_id, name, name, NodeId::new(0, 21), false, -1);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 8996),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 9000),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 9001),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 11110),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 11111),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2755),
                &ReferenceTypeId::HasSubtype,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_variabletype_5(address_space: &mut AddressSpace) {
    // VariableType
    let name = "ConditionVariableType";
    let node_id = NodeId::new(0, 9002);
    let node = VariableType::new(&node_id, name, name, NodeId::null(), false, -2);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 9003),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 63),
                &ReferenceTypeId::HasSubtype,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_variabletype_6(address_space: &mut AddressSpace) {
    // VariableType
    let name = "AlarmRateVariableType";
    let node_id = NodeId::new(0, 17277);
    let node = VariableType::new(&node_id, name, name, NodeId::new(0, 11), false, -1);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 17278),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 63),
                &ReferenceTypeId::HasSubtype,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_7(address_space: &mut AddressSpace) {
    // Method
    let name = "Disable";
    let node_id = NodeId::new(0, 9028);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2782),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_8(address_space: &mut AddressSpace) {
    // Method
    let name = "Enable";
    let node_id = NodeId::new(0, 9027);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2782),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_9(address_space: &mut AddressSpace) {
    // Method
    let name = "AddComment";
    let node_id = NodeId::new(0, 9029);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 9030),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2782),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_10(address_space: &mut AddressSpace) {
    // Method
    let name = "ConditionRefresh";
    let node_id = NodeId::new(0, 3875);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 3876),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2782),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_11(address_space: &mut AddressSpace) {
    // Method
    let name = "ConditionRefresh2";
    let node_id = NodeId::new(0, 12912);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 12913),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2782),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_12(address_space: &mut AddressSpace) {
    // Method
    let name = "Respond";
    let node_id = NodeId::new(0, 9069);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 9070),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2830),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_13(address_space: &mut AddressSpace) {
    // Method
    let name = "Acknowledge";
    let node_id = NodeId::new(0, 9111);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 9112),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2881),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_14(address_space: &mut AddressSpace) {
    // Method
    let name = "Confirm";
    let node_id = NodeId::new(0, 9113);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 9114),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2881),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_15(address_space: &mut AddressSpace) {
    // Method
    let name = "TimedShelve";
    let node_id = NodeId::new(0, 9213);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 9214),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 9178),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_16(address_space: &mut AddressSpace) {
    // Method
    let name = "Unshelve";
    let node_id = NodeId::new(0, 9211);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 9178),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_17(address_space: &mut AddressSpace) {
    // Method
    let name = "OneShotShelve";
    let node_id = NodeId::new(0, 9212);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 9178),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_18(address_space: &mut AddressSpace) {
    // Method
    let name = "Silence";
    let node_id = NodeId::new(0, 16402);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2915),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_19(address_space: &mut AddressSpace) {
    // Method
    let name = "Suppress";
    let node_id = NodeId::new(0, 16403);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2915),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_20(address_space: &mut AddressSpace) {
    // Method
    let name = "Unsuppress";
    let node_id = NodeId::new(0, 17868);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2915),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_21(address_space: &mut AddressSpace) {
    // Method
    let name = "RemoveFromService";
    let node_id = NodeId::new(0, 17869);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2915),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_22(address_space: &mut AddressSpace) {
    // Method
    let name = "PlaceInService";
    let node_id = NodeId::new(0, 17870);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2915),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_23(address_space: &mut AddressSpace) {
    // Method
    let name = "Reset";
    let node_id = NodeId::new(0, 18199);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 80),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2915),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_24(address_space: &mut AddressSpace) {
    // Method
    let name = "Disable";
    let node_id = NodeId::new(0, 16439);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 16406),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_25(address_space: &mut AddressSpace) {
    // Method
    let name = "Enable";
    let node_id = NodeId::new(0, 16440);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 16406),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_26(address_space: &mut AddressSpace) {
    // Method
    let name = "AddComment";
    let node_id = NodeId::new(0, 16441);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 16442),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 16406),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_27(address_space: &mut AddressSpace) {
    // Method
    let name = "Acknowledge";
    let node_id = NodeId::new(0, 16461);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 16462),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 16406),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_28(address_space: &mut AddressSpace) {
    // Method
    let name = "TimedShelve";
    let node_id = NodeId::new(0, 2949);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 2991),
                &ReferenceTypeId::HasProperty,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2929),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_29(address_space: &mut AddressSpace) {
    // Method
    let name = "Unshelve";
    let node_id = NodeId::new(0, 2947);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2929),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_30(address_space: &mut AddressSpace) {
    // Method
    let name = "OneShotShelve";
    let node_id = NodeId::new(0, 2948);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 2929),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}

fn add_method_31(address_space: &mut AddressSpace) {
    // Method
    let name = "Reset";
    let node_id = NodeId::new(0, 18666);
    let node = Method::new(&node_id, name, name, true, true);
    let _ = address_space.insert(
        node,
        Some(&[
            (
                &NodeId::new(0, 78),
                &ReferenceTypeId::HasModellingRule,
                ReferenceDirection::Forward,
            ),
            (
                &NodeId::new(0, 17279),
                &ReferenceTypeId::HasComponent,
                ReferenceDirection::Inverse,
            ),
        ]),
    );
}
