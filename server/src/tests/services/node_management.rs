use std::ops::Add;
use std::collections::HashSet;

use chrono::{self, Utc};

use opcua_types::node_ids::{ObjectId, ObjectTypeId};

use crate::{
    services::node_management::NodeManagementService,
};

use super::*;

/// A helper that sets up a subscription service test
fn do_node_management_service_test<T>(f: T)
    where T: FnOnce(&mut ServerState, &mut Session, &mut AddressSpace, NodeManagementService)
{
    let st = ServiceTest::new();
    let mut server_state = trace_write_lock_unwrap!(st.server_state);
    let mut session = trace_write_lock_unwrap!(st.session);

    {
        let mut address_space = trace_write_lock_unwrap!(st.address_space);
        add_many_vars_to_address_space(&mut address_space, 100);
    }

    let mut address_space = trace_write_lock_unwrap!(st.address_space);
    f(&mut server_state, &mut session, &mut address_space, NodeManagementService::new());
}

fn add_nodes_request(nodes_to_add: Vec<AddNodesItem>) -> AddNodesRequest {
    AddNodesRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        nodes_to_add: Some(nodes_to_add),
    }
}

fn object_attributes() -> ExtensionObject {
    let specified_attributes = AttributesMask::DISPLAY_NAME |
        AttributesMask::DESCRIPTION |
        AttributesMask::WRITE_MASK |
        AttributesMask::USER_WRITE_MASK |
        AttributesMask::EVENT_NOTIFIER;

    ExtensionObject::from_encodable(ObjectId::ObjectAttributes_Encoding_DefaultBinary, &ObjectAttributes {
        specified_attributes: specified_attributes.bits(),
        display_name: LocalizedText::new("", "displayName"),
        description: LocalizedText::new("", "description"),
        write_mask: 0,
        user_write_mask: 0,
        event_notifier: 0,
    })
}

#[test]
fn add_nodes_empty() {
    // Empty request
    do_node_management_service_test(|_, _, address_space, nms: NodeManagementService| {
        let response = nms.add_nodes(address_space, &AddNodesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            nodes_to_add: None,
        });
        let response: ServiceFault = supported_message_as!(response.unwrap(), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);

        let response = nms.add_nodes(address_space, &AddNodesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            nodes_to_add: Some(vec![]),
        });
        let response: ServiceFault = supported_message_as!(response.unwrap(), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);
    });
}

#[test]
fn add_nodes_null_node_id() {
    // Add a node with a null requested node id
    do_node_management_service_test(|_, _, address_space, nms| {
        let response = nms.add_nodes(address_space, &add_nodes_request(vec![
            AddNodesItem {
                parent_node_id: AddressSpace::root_folder_id().into(),
                reference_type_id: NodeId::null(),
                requested_new_node_id: ExpandedNodeId::null(),
                browse_name: QualifiedName::from(""),
                node_class: NodeClass::Object,
                node_attributes: object_attributes(),
                type_definition: ObjectTypeId::BaseObjectType.into(),
            }
        ]));
        let response: AddNodesResponse = supported_message_as!(response.unwrap(), AddNodesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_code, StatusCode::BadReferenceTypeIdInvalid);
        assert_eq!(results[0].added_node_id, NodeId::null());
    });
}

#[test]
fn add_nodes_invalid_class() {
    // Invalid class
    do_node_management_service_test(|_, _, address_space, nms| {
        let response = nms.add_nodes(address_space, &add_nodes_request(vec![
            AddNodesItem {
                parent_node_id: ExpandedNodeId::null(),
                reference_type_id: NodeId::null(),
                requested_new_node_id: ExpandedNodeId::null(),
                browse_name: QualifiedName::from(""),
                node_class: NodeClass::Object,
                node_attributes: ExtensionObject::null(),
                type_definition: ExpandedNodeId::null(),
            }
        ]));
        let response: AddNodesResponse = supported_message_as!(response.unwrap(), AddNodesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_code, StatusCode::BadReferenceTypeIdInvalid);
        assert_eq!(results[0].added_node_id, NodeId::null());
    });
}

fn add_nodes_invalid_parent_id() {
    // Add a node with an invalid parent id
    do_node_management_service_test(|_, _, address_space, nms| {
        let response = nms.add_nodes(address_space, &add_nodes_request(vec![
            AddNodesItem {
                parent_node_id: NodeId::new(100, "blahblah").into(),
                reference_type_id: NodeId::null(),
                requested_new_node_id: ExpandedNodeId::null(),
                browse_name: QualifiedName::from(""),
                node_class: NodeClass::Object,
                node_attributes: ExtensionObject::null(),
                type_definition: ExpandedNodeId::null(),
            }
        ]));
        let response: AddNodesResponse = supported_message_as!(response.unwrap(), AddNodesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_code, StatusCode::BadParentNodeIdInvalid);
        assert_eq!(results[0].added_node_id, NodeId::null());
    });
}

fn add_nodes_missing_type() {
    // Add a node with a missing type
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

fn add_nodes_invalid_type_not_required() {
    // Add a node with a type when a type is not required
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

fn add_nodes_invalid_unrecognized_type() {
    // Add a node with an unrecognized type
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

fn add_nodes_invalid_node_id_exists() {
    // Add a node where node id already exists
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

fn add_nodes_valid() {
    // Add a node which is valid
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

fn add_nodes_invalid_no_permission() {
    // Add a node which is valid without permission
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

#[test]
fn add_references_test1() {
    // TODO
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

#[test]
fn delete_nodes_test1() {
    // TODO

    // delete a node by node id
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });

    // delete a node by node id when it does not exist
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });

    // delete a node by node id without permission
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}

#[test]
fn delete_references_test1() {
    // TODO
    do_node_management_service_test(|_, _, address_space, nms| {
        // TODO
    });
}
