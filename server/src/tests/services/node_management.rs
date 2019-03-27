use opcua_types::node_ids::{ObjectId, ObjectTypeId, ReferenceTypeId, DataTypeId, MethodId};

use crate::{
    services::node_management::NodeManagementService,
};

use super::*;

/// A helper that sets up a subscription service test
fn do_node_management_service_test<T>(f: T)
    where T: FnOnce(&mut ServerState, &mut Session, &mut AddressSpace, NodeManagementService)
{
    opcua_console_logging::init();

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

// A helper that adds one node and tests that the result matches the expected status code
fn do_add_node_test_with_expected_error(item: AddNodesItem, expected_status_code: StatusCode) {
    do_node_management_service_test(|_, session, address_space, nms| {
        let response = nms.add_nodes(session, address_space, &AddNodesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            nodes_to_add: Some(vec![item]),
        });
        let response: AddNodesResponse = supported_message_as!(response.unwrap(), AddNodesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_code, expected_status_code);
        if expected_status_code.is_good() {
            assert_ne!(results[0].added_node_id, NodeId::null());
            assert!(address_space.find_node(&results[0].added_node_id).is_some());
        } else {
            assert_eq!(results[0].added_node_id, NodeId::null());
        }
    });
}

fn do_add_references_test(item: AddReferencesItem, expected_status_code: StatusCode) {
    do_node_management_service_test(|_, session, address_space, nms| {
        let response = nms.add_references(session, address_space, &AddReferencesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            references_to_add: Some(vec![item]),
        });
        let response: AddReferencesResponse = supported_message_as!(response.unwrap(), AddReferencesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], expected_status_code);
        if expected_status_code.is_good() {
            // TODO expect the reference to exist
        }
    });
}

fn do_delete_nodes_test(item: DeleteNodesItem, expected_status_code: StatusCode) {
    do_node_management_service_test(|_, session, address_space, nms| {
        let response = nms.delete_nodes(session, address_space, &DeleteNodesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            nodes_to_delete: Some(vec![item]),
        });
        let response: DeleteNodesResponse = supported_message_as!(response.unwrap(), DeleteNodesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], expected_status_code);
    });
}

fn do_delete_references_test(item: DeleteReferencesItem, expected_status_code: StatusCode) {
    do_node_management_service_test(|_, session, address_space, nms| {
        let response = nms.delete_references(session, address_space, &DeleteReferencesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            references_to_delete: Some(vec![item]),
        });
        let response: DeleteReferencesResponse = supported_message_as!(response.unwrap(), DeleteReferencesResponse);
        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], expected_status_code);
    });
}

fn object_attributes<T>(display_name: T) -> ExtensionObject where T: Into<LocalizedText> {
    let specified_attributes = AttributesMask::DISPLAY_NAME |
        AttributesMask::DESCRIPTION |
        AttributesMask::WRITE_MASK |
        AttributesMask::USER_WRITE_MASK |
        AttributesMask::EVENT_NOTIFIER;

    ExtensionObject::from_encodable(ObjectId::ObjectAttributes_Encoding_DefaultBinary, &ObjectAttributes {
        specified_attributes: specified_attributes.bits(),
        display_name: display_name.into(),
        description: LocalizedText::new("", "description"),
        write_mask: 0,
        user_write_mask: 0,
        event_notifier: 0,
    })
}

fn variable_attributes<T>(display_name: T) -> ExtensionObject where T: Into<LocalizedText> {
    let specified_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::ACCESS_LEVEL | AttributesMask::USER_ACCESS_LEVEL |
        AttributesMask::DATA_TYPE | AttributesMask::HISTORIZING | AttributesMask::VALUE | AttributesMask::VALUE_RANK;

    ExtensionObject::from_encodable(ObjectId::VariableAttributes_Encoding_DefaultBinary, &VariableAttributes {
        specified_attributes: specified_attributes.bits(),
        display_name: display_name.into(),
        description: LocalizedText::null(),
        write_mask: 0,
        user_write_mask: 0,
        value: Variant::from(true),
        data_type: DataTypeId::Boolean.into(),
        value_rank: 1,
        array_dimensions: None,
        access_level: 1,
        user_access_level: 2,
        minimum_sampling_interval: 0.0,
        historizing: false,
    })
}

fn method_attributes<T>(display_name: T) -> ExtensionObject where T: Into<LocalizedText> {
    let specified_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::EXECUTABLE | AttributesMask::USER_EXECUTABLE;
    ExtensionObject::from_encodable(ObjectId::MethodAttributes_Encoding_DefaultBinary, &MethodAttributes {
        specified_attributes: specified_attributes.bits(),
        display_name: display_name.into(),
        description: LocalizedText::null(),
        write_mask: 0,
        user_write_mask: 0,
        executable: true,
        user_executable: true,
    })
}

#[test]
fn add_nodes_nothing_to_do() {
    // Empty request
    do_node_management_service_test(|_, session, address_space, nms: NodeManagementService| {
        let response = nms.add_nodes(session, address_space, &AddNodesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            nodes_to_add: None,
        });
        let response: ServiceFault = supported_message_as!(response.unwrap(), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);

        let response = nms.add_nodes(session, address_space, &AddNodesRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            nodes_to_add: Some(vec![]),
        });
        let response: ServiceFault = supported_message_as!(response.unwrap(), ServiceFault);
        assert_eq!(response.response_header.service_result, StatusCode::BadNothingToDo);
    });
}

#[test]
fn add_nodes_reference_type_id_invalid() {
    // Add a node with a null requested node id
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: AddressSpace::root_folder_id().into(),
            reference_type_id: NodeId::null(), // !!!
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Object,
            node_attributes: object_attributes("foo"),
            type_definition: ObjectTypeId::BaseObjectType.into(),
        }, StatusCode::BadReferenceTypeIdInvalid);
}

#[test]
fn add_nodes_node_class_invalid() {
    // Invalid class
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Unspecified, // !!!
            node_attributes: object_attributes("foo"),
            type_definition: ObjectTypeId::BaseObjectType.into(),
        }, StatusCode::BadNodeClassInvalid);
}

#[test]
fn add_nodes_parent_node_id_invalid() {
    // Add a node with an invalid parent id
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: NodeId::new(100, "blahblah").into(), // !!!
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Object,
            node_attributes: object_attributes("foo"),
            type_definition: ObjectTypeId::BaseObjectType.into(),
        }, StatusCode::BadParentNodeIdInvalid);
}

#[test]
fn add_nodes_type_definition_invalid() {
    // Add a node with a missing type definition, when one is required
    // Object
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Object,
            node_attributes: object_attributes("foo"),
            type_definition: ExpandedNodeId::null(), // !!!
        }, StatusCode::BadTypeDefinitionInvalid);

    // Add a node with a missing type definition, when one is required
    // Variable
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Variable,
            node_attributes: variable_attributes("foo"),
            type_definition: ExpandedNodeId::null(), // !!!
        }, StatusCode::BadTypeDefinitionInvalid);

    // Add a node with a type definition when one is not required, e.g.. for Method
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Method,
            node_attributes: method_attributes("foo"),
            type_definition: ObjectTypeId::AddressSpaceFileType.into(), // !!!
        }, StatusCode::BadTypeDefinitionInvalid);

    // Add a node with an unrecognized type, something that is not a type at all
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Variable,
            node_attributes: variable_attributes("foo"),
            type_definition: MethodId::ProgramStateMachineType_Start.into(), // !!!
        }, StatusCode::BadTypeDefinitionInvalid);
}

#[test]
fn add_nodes_node_id_exists() {
    // Add a node where node id already exists
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::RootFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ObjectId::ObjectsFolder.into(), // !!!
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Variable,
            node_attributes: variable_attributes("foo"),
            type_definition: ExpandedNodeId::null(),
        }, StatusCode::BadNodeIdExists);
}

#[test]
fn add_nodes_mismatching_class_and_attributes_exists() {
    // Add a node where node class does not match the supplied node attributes
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Object,
            node_attributes: variable_attributes("foo"), // !!!
            type_definition: ObjectTypeId::AddressSpaceFileType.into(),
        }, StatusCode::BadNodeAttributesInvalid);
}

#[test]
fn add_nodes_browse_name_duplicated() {
    // Add a node which is valid
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: AddressSpace::root_folder_id().into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("Objects"), // !!!
            node_class: NodeClass::Object,
            node_attributes: object_attributes("foo"),
            type_definition: ObjectTypeId::BaseObjectType.into(),
        }, StatusCode::BadBrowseNameDuplicated);
}

#[test]
fn add_nodes_valid() {
    // Add a node which is valid
    do_add_node_test_with_expected_error(
        AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: QualifiedName::from("boo"),
            node_class: NodeClass::Object,
            node_attributes: object_attributes("foo"),
            type_definition: ObjectTypeId::BaseObjectType.into(),
        }, StatusCode::Good);
}


// TODO a test which tries adding nodes with no permission to do so

#[test]
fn add_references_source_node_id_invalid() {
    // Add a reference where the node id is invalid
    do_add_references_test(AddReferencesItem {
        source_node_id: NodeId::null(), // !!!
        reference_type_id: ReferenceTypeId::HasChild.into(),
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ObjectId::ServerConfiguration.into(),
        target_node_class: NodeClass::Object,
    }, StatusCode::BadSourceNodeIdInvalid);
}

#[test]
fn add_references_target_node_id_invalid() {
    // Add a reference where the node id is invalid
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: ReferenceTypeId::HasChild.into(),
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ExpandedNodeId::null(), // !!!
        target_node_class: NodeClass::Object,
    }, StatusCode::BadTargetNodeIdInvalid);
}

#[test]
fn add_references_server_uri_invalid() {
    // Add a reference where the server uri is invalid
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: ReferenceTypeId::HasChild.into(),
        is_forward: true,
        target_server_uri: UAString::from("urn:foo"), // !!!
        target_node_id: ObjectId::ServerConfiguration.into(),
        target_node_class: NodeClass::Object,
    }, StatusCode::BadServerUriInvalid);
}

#[test]
fn add_references_reference_type_id_invalid() {
    // Add a reference where the reference type id is invalid

    // Null node
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: NodeId::null(), // !!!
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ObjectId::ObjectsFolder.into(),
        target_node_class: NodeClass::Object,
    }, StatusCode::BadReferenceTypeIdInvalid);

    // Not a reference type id node
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: MethodId::AddressSpaceFileType_Write.into(), // !!!
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ObjectId::ObjectsFolder.into(),
        target_node_class: NodeClass::Object,
    }, StatusCode::BadReferenceTypeIdInvalid);
}

#[test]
fn add_references_reference_local_only() {
    // Add a reference where the reference is remote
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: ReferenceTypeId::HasChild.into(),
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ExpandedNodeId { server_index: 1, namespace_uri: UAString::null(), node_id: ObjectId::ServerConfiguration.into() }, // !!!
        target_node_class: NodeClass::Object,
    }, StatusCode::BadReferenceLocalOnly);
}

#[test]
fn add_references_duplicate_reference_not_allowed() {
    // Add a reference that is a duplicate
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: ReferenceTypeId::Organizes.into(),
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ObjectId::ObjectsFolder.into(),
        target_node_class: NodeClass::Object,
    }, StatusCode::BadDuplicateReferenceNotAllowed);
}

#[test]
fn add_references_node_class_invalid() {
    // Add a reference where the node class is invalid
    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: ReferenceTypeId::Organizes.into(),
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ObjectId::ObjectsFolder.into(),
        target_node_class: NodeClass::Unspecified, // !!!
    }, StatusCode::BadNodeClassInvalid);

    do_add_references_test(AddReferencesItem {
        source_node_id: ObjectId::RootFolder.into(),
        reference_type_id: ReferenceTypeId::Organizes.into(),
        is_forward: true,
        target_server_uri: UAString::null(),
        target_node_id: ObjectId::ObjectsFolder.into(),
        target_node_class: NodeClass::Variable, // !!!
    }, StatusCode::BadNodeClassInvalid);
}

#[test]
fn delete_nodes_test1() {
    // TODO

    // delete a node by node id

    // delete a node by node id when it does not exist

    // delete a node by node id without permission
}

#[test]
fn delete_references_test1() {
    // TODO
}
