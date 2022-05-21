use std::sync::Weak;

use crate::server::services::view::ViewService;
use crate::supported_message_as;
use crate::sync::*;

use super::*;

// View service tests

fn make_browse_request<T>(
    nodes: &[NodeId],
    node_class_mask: NodeClassMask,
    max_references_per_node: usize,
    browse_direction: BrowseDirection,
    reference_type: T,
) -> BrowseRequest
where
    T: Into<NodeId> + Clone,
{
    let request_header = make_request_header();
    let nodes_to_browse = nodes
        .iter()
        .map(|n| BrowseDescription {
            node_id: n.clone(),
            browse_direction,
            reference_type_id: reference_type.clone().into(),
            include_subtypes: true,
            node_class_mask: node_class_mask.bits(),
            result_mask: BrowseDescriptionResultMask::all().bits() as u32,
        })
        .collect();
    BrowseRequest {
        request_header,
        view: ViewDescription {
            view_id: NodeId::null(),
            timestamp: DateTime::null(),
            view_version: 0,
        },
        requested_max_references_per_node: max_references_per_node as u32,
        nodes_to_browse: Some(nodes_to_browse),
    }
}

fn make_browse_next_request(
    continuation_point: &ByteString,
    release_continuation_points: bool,
) -> BrowseNextRequest {
    let request_header = make_request_header();
    BrowseNextRequest {
        request_header,
        release_continuation_points,
        continuation_points: if continuation_point.is_null() {
            None
        } else {
            Some(vec![continuation_point.clone()])
        },
    }
}

fn verify_references_to_many_vars(
    references: &[ReferenceDescription],
    expected_size: usize,
    start_idx: usize,
) {
    // Verify that the reference descriptions point at sequential vars
    assert_eq!(references.len(), expected_size);
    for (i, r) in references.iter().enumerate() {
        assert_eq!(r.node_id.node_id, var_node_id(i + start_idx));
    }
}

fn do_view_service_test<F>(f: F)
where
    F: FnOnce(
        Arc<RwLock<ServerState>>,
        Arc<RwLock<Session>>,
        Arc<RwLock<AddressSpace>>,
        &ViewService,
    ),
{
    crate::console_logging::init();
    let st = ServiceTest::new();
    f(
        st.server_state.clone(),
        st.session.clone(),
        st.address_space.clone(),
        &ViewService::new(),
    );
}

fn do_browse(
    vs: &ViewService,
    server_state: Arc<RwLock<ServerState>>,
    session: Arc<RwLock<Session>>,
    address_space: Arc<RwLock<AddressSpace>>,
    nodes: &[NodeId],
    max_references_per_node: usize,
    browse_direction: BrowseDirection,
) -> BrowseResponse {
    let request = make_browse_request(
        nodes,
        NodeClassMask::empty(),
        max_references_per_node,
        browse_direction,
        ReferenceTypeId::Organizes,
    );
    let response = vs.browse(server_state, session, address_space, &request);
    supported_message_as!(response, BrowseResponse)
}

fn do_browse_next(
    vs: &ViewService,
    session: Arc<RwLock<Session>>,
    address_space: Arc<RwLock<AddressSpace>>,
    continuation_point: &ByteString,
    release_continuation_points: bool,
) -> BrowseNextResponse {
    let request = make_browse_next_request(continuation_point, release_continuation_points);
    let response = vs.browse_next(session, address_space, &request);
    supported_message_as!(response, BrowseNextResponse)
}

#[test]
fn browse() {
    do_view_service_test(|server_state, session, address_space, vs| {
        add_sample_vars_to_address_space(address_space.clone());

        let nodes: Vec<NodeId> = vec![ObjectId::RootFolder.into()];
        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            1000,
            BrowseDirection::Forward,
        );
        assert!(response.results.is_some());

        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);

        assert!(results[0].references.is_some());
        let references = results[0].references.as_ref().unwrap();
        assert_eq!(references.len(), 3);

        // Expect to see refs to
        // Objects/
        // Types/
        // Views/

        let r1 = &references[0];
        assert_eq!(r1.browse_name, QualifiedName::new(0, "Objects"));
        let r2 = &references[1];
        assert_eq!(r2.browse_name, QualifiedName::new(0, "Types"));
        let r3 = &references[2];
        assert_eq!(r3.browse_name, QualifiedName::new(0, "Views"));
    });
}

// Test the response of supplying an unsupported view to the browse request
#[test]
fn browse_non_null_view() {
    do_view_service_test(|server_state, session, address_space, vs| {
        let nodes: Vec<NodeId> = vec![ObjectId::RootFolder.into()];

        // Expect a non-null view to be rejected
        let mut request = make_browse_request(
            &nodes,
            NodeClassMask::empty(),
            1000,
            BrowseDirection::Forward,
            ReferenceTypeId::Organizes,
        );
        request.view.view_id = NodeId::new(1, "FakeView");
        let response = vs.browse(
            server_state.clone(),
            session.clone(),
            address_space.clone(),
            &request,
        );
        let response = supported_message_as!(response, ServiceFault);
        assert_eq!(
            response.response_header.service_result,
            StatusCode::BadViewIdUnknown
        );

        // Expect a non-0 timestamp to be rejected
        request.view.view_id = NodeId::null();
        request.view.timestamp = DateTime::now();
        let response = vs.browse(server_state, session, address_space, &request);
        let response = supported_message_as!(response, ServiceFault);
        assert_eq!(
            response.response_header.service_result,
            StatusCode::BadViewIdUnknown
        );
    });
}

// This test applies a class mask to the browse so only nodes of types in the mask should come back
#[test]
fn browse_node_class_mask() {
    do_view_service_test(|server_state, session, address_space, vs| {
        add_sample_vars_to_address_space(address_space.clone());

        let nodes: Vec<NodeId> = vec![ObjectId::Server.into()];
        let request = make_browse_request(
            &nodes,
            NodeClassMask::OBJECT,
            1000,
            BrowseDirection::Forward,
            ReferenceTypeId::HasComponent,
        );

        let response = vs.browse(server_state, session, address_space, &request);
        let response = supported_message_as!(response, BrowseResponse);
        assert!(response.results.is_some());

        let results = response.results.unwrap();
        let references = results[0].references.as_ref().unwrap();

        // There are 12 HasComponent values under Server altogether but only 7 are of Object type
        assert_eq!(references.len(), 7);
        references.iter().for_each(|r| {
            assert_eq!(r.node_class, NodeClass::Object);
        });
    });
}

fn verify_references(
    expected: &[(ReferenceTypeId, NodeId, bool)],
    references: &[ReferenceDescription],
) {
    if expected.len() != references.len() {
        debug!("Check expected references to this actual list:");
        expected.iter().for_each(|r| {
            let reference_type_id: NodeId = r.0.into();
            let node_id: NodeId = r.1.clone();
            let is_forward = r.2;
            let found = references.iter().any(|r| {
                r.reference_type_id == reference_type_id
                    && r.node_id.node_id == node_id
                    && r.is_forward == is_forward
            });
            if !found {
                debug!(
                    "  Missing expected ({:?}, {:?}, {:?}),",
                    r.0, node_id, is_forward
                );
            }
        });
        references.iter().for_each(|r| {
            let found = expected.iter().any(|e| {
                let reference_type_id: NodeId = e.0.into();
                let node_id: NodeId = e.1.clone();
                let is_forward = e.2;
                r.reference_type_id == reference_type_id
                    && r.node_id.node_id == node_id
                    && r.is_forward == is_forward
            });
            if !found {
                debug!(
                    "  Surplus ({:?}, {:?}, {:?}),",
                    r.reference_type_id, r.node_id.node_id, r.is_forward
                );
            }
        });
    }

    assert_eq!(expected.len(), references.len());
    expected.into_iter().for_each(|e| {
        let reference_type_id: NodeId = e.0.into();
        let node_id: NodeId = e.1.clone();
        let is_forward = e.2;
        let reference = references.iter().find(|r| {
            r.reference_type_id == reference_type_id
                && r.node_id.node_id == node_id
                && r.is_forward == is_forward
        });
        assert!(reference.is_some());
    });
}

#[test]
fn browse_inverse() {
    crate::console_logging::init();
    do_view_service_test(|server_state, session, address_space, vs| {
        // Ask for Inverse refs only

        let node_id: NodeId = ObjectTypeId::FolderType.into();
        let nodes = vec![node_id.clone()];

        let request = make_browse_request(
            &nodes,
            NodeClassMask::empty(),
            1000,
            BrowseDirection::Inverse,
            NodeId::null(),
        );

        let response = vs.browse(server_state, session, address_space, &request);
        let response = supported_message_as!(response, BrowseResponse);

        assert!(response.results.is_some());

        let results = response.results.unwrap();
        let references = results.get(0).unwrap().references.as_ref().unwrap();

        // We do NOT expect to find the node in the list of results
        assert!(references
            .iter()
            .find(|r| r.node_id.node_id == node_id)
            .is_none());

        // We expect this many results
        assert_eq!(references.len(), 21);

        let expected: Vec<(ReferenceTypeId, NodeId, bool)> = vec![
            // (ref_type, node_id, is_forward)
            // Inverse refs
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::HistoryServerCapabilitiesType_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ObjectTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::DataTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerType_ServerCapabilities_ModellingRules.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::HistoryServerCapabilities_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::BaseObjectType.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerCapabilitiesType_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::Server_ServerCapabilities_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::TypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerCapabilitiesType_ModellingRules.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ObjectsFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::VariableTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::RootFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerType_ServerCapabilities_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ViewsFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::EventTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::Server_ServerCapabilities_ModellingRules.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ReferenceTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::HistoricalDataConfigurationType_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::InterfaceTypes.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::AuthorizationServices.into(),
                false,
            ),
        ];
        verify_references(&expected, references);
    });
}

#[test]
fn browse_both() {
    crate::console_logging::init();
    do_view_service_test(|server_state, session, address_space, vs| {
        // Ask for both forward and inverse refs

        let node_id: NodeId = ObjectTypeId::FolderType.into();
        let nodes = vec![node_id.clone()];

        let request = make_browse_request(
            &nodes,
            NodeClassMask::empty(),
            1000,
            BrowseDirection::Both,
            NodeId::null(),
        );

        let response = vs.browse(server_state, session, address_space, &request);
        let response = supported_message_as!(response, BrowseResponse);

        assert!(response.results.is_some());

        let results = response.results.unwrap();
        let references = results.get(0).unwrap().references.as_ref().unwrap();

        // We do NOT expect to find the node in the list of results
        assert!(references
            .iter()
            .find(|r| r.node_id.node_id == node_id)
            .is_none());

        // We expect this many results
        assert_eq!(references.len(), 29);

        let expected: Vec<(ReferenceTypeId, NodeId, bool)> = vec![
            // (ref_type, node_id, is_forward)
            // Forward refs
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::OperationLimitsType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::FileDirectoryType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::CertificateGroupFolderType.into(),
                true,
            ),
            // Inverse refs
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::HistoryServerCapabilitiesType_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ObjectTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::DataTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerType_ServerCapabilities_ModellingRules.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::HistoryServerCapabilities_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::BaseObjectType.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerCapabilitiesType_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::Server_ServerCapabilities_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::TypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerCapabilitiesType_ModellingRules.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ObjectsFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::VariableTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::RootFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ServerType_ServerCapabilities_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ViewsFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::EventTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::Server_ServerCapabilities_ModellingRules.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::ReferenceTypesFolder.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::HistoricalDataConfigurationType_AggregateFunctions.into(),
                false,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::DictionaryFolderType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::AlarmGroupType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::KeyCredentialConfigurationFolderType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::SecurityGroupFolderType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasSubtype,
                ObjectTypeId::DataSetFolderType.into(),
                true,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::InterfaceTypes.into(),
                false,
            ),
            (
                ReferenceTypeId::HasTypeDefinition,
                ObjectId::AuthorizationServices.into(),
                false,
            ),
        ];
        verify_references(&expected, references);
    });
}

#[test]
fn browse_next_no_cp1() {
    do_view_service_test(|server_state, session, address_space, vs| {
        let parent_node_id = add_many_vars_to_address_space(address_space.clone(), 100).0;
        let nodes = vec![parent_node_id.clone()];
        // Browse with requested_max_references_per_node = 101, expect 100 results, no continuation point
        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            101,
            BrowseDirection::Forward,
        );
        assert!(response.results.is_some());
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 100, 0);
    });
}

#[test]
fn browse_next_no_cp2() {
    do_view_service_test(|server_state, session, address_space, vs| {
        let parent_node_id = add_many_vars_to_address_space(address_space.clone(), 100).0;
        let nodes = vec![parent_node_id.clone()];
        // Browse with requested_max_references_per_node = 100, expect 100 results, no continuation point
        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            100,
            BrowseDirection::Forward,
        );
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 100, 0);
    });
}

#[test]
fn browse_next_cp() {
    // Browse with requested_max_references_per_node = 99 expect 99 results and a continuation point
    // Browse next with continuation point, expect 1 result leaving off from last continuation point
    do_view_service_test(|server_state, session, address_space, vs| {
        let parent_node_id = add_many_vars_to_address_space(address_space.clone(), 100).0;
        let nodes = vec![parent_node_id.clone()];
        // Get first 99
        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            99,
            BrowseDirection::Forward,
        );
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(!r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 99, 0);

        // Expect continuation point and browse next to return last var and no more continuation point
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r1.continuation_point,
            false,
        );
        let r2 = &response.results.unwrap()[0];
        assert!(r2.continuation_point.is_null());
        let references = r2.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 1, 99);

        // Browse next again with same continuation point, expect failure
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r1.continuation_point,
            false,
        );
        let r2 = &response.results.unwrap()[0];
        assert!(r2.continuation_point.is_null());
        assert_eq!(r2.status_code, StatusCode::BadContinuationPointInvalid);
    });
}

#[test]
fn browse_next_release_cp() {
    // Browse and get a continuation point and then release that continuation point, expecting it to be deleted
    do_view_service_test(|server_state, session, address_space, vs| {
        let parent_node_id = add_many_vars_to_address_space(address_space.clone(), 100).0;
        let nodes = vec![parent_node_id.clone()];
        // Get first 99
        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            99,
            BrowseDirection::Forward,
        );
        let r1 = &response.results.unwrap()[0];
        let _references = r1.references.as_ref().unwrap();
        assert!(!r1.continuation_point.is_null());

        // Browse next and release the previous continuation points, expect Null result
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r1.continuation_point,
            true,
        );
        assert!(response.results.is_none());

        // Browse next again with same continuation point, expect BadContinuationPointInvalid
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r1.continuation_point,
            false,
        );
        let r1 = &response.results.unwrap()[0];
        assert_eq!(r1.status_code, StatusCode::BadContinuationPointInvalid);
    });
}

#[test]
fn browse_next_multiple_cps() {
    // Browse multiple times with multiple continuation points
    do_view_service_test(|server_state, session, address_space, vs| {
        let parent_node_id = add_many_vars_to_address_space(address_space.clone(), 100).0;
        let nodes = vec![parent_node_id.clone()];
        // Browse with 35 expect continuation point cp1
        // Browse next with cp1 with 35 expect cp2
        // Browse next with cp2 expect 30 results
        // Get first 35
        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            35,
            BrowseDirection::Forward,
        );
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(!r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 35, 0);

        // Expect continuation point and browse next to return last var and no more continuation point
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r1.continuation_point,
            false,
        );
        let r2 = &response.results.unwrap()[0];
        assert!(!r2.continuation_point.is_null());
        let references = r2.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 35, 35);

        // Expect continuation point and browse next to return last var and no more continuation point
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r2.continuation_point,
            false,
        );
        let r3 = &response.results.unwrap()[0];
        assert!(r3.continuation_point.is_null());
        let references = r3.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 30, 70);
    });
}

#[test]
fn browse_next_modify_address_space() {
    // Modify the address space after a browse so continuation point becomes invalid
    do_view_service_test(|server_state, session, address_space, vs| {
        let parent_node_id = add_many_vars_to_address_space(address_space.clone(), 100).0;
        let nodes = vec![parent_node_id.clone()];
        // Modify address space so existing continuation point is invalid
        // Browse next with continuation point, expect BadContinuationPointInvalid
        use std::thread;
        use std::time::Duration;

        let response = do_browse(
            &vs,
            server_state,
            session.clone(),
            address_space.clone(),
            &nodes,
            99,
            BrowseDirection::Forward,
        );
        let r1 = &response.results.unwrap()[0];
        let _references = r1.references.as_ref().unwrap();
        assert!(!r1.continuation_point.is_null());

        // Sleep a bit, modify the address space so the old continuation point is out of date
        thread::sleep(Duration::from_millis(50));
        {
            let var_name = "xxxx";
            let mut address_space = trace_write_lock!(address_space);
            VariableBuilder::new(&NodeId::new(1, var_name), var_name, var_name)
                .data_type(DataTypeId::Int32)
                .value(200i32)
                .organized_by(&parent_node_id)
                .insert(&mut address_space);
        }

        // Browsing with the old continuation point should fail
        let response = do_browse_next(
            &vs,
            session.clone(),
            address_space.clone(),
            &r1.continuation_point,
            false,
        );
        let r1 = &response.results.unwrap()[0];
        assert_eq!(r1.status_code, StatusCode::BadContinuationPointInvalid);
    });
}

#[test]
fn translate_browse_paths_to_node_ids() {
    do_view_service_test(|server_state, _session, address_space, vs| {
        // This is a very basic test of this service. It wants to find the relative path from root to the
        // Objects folder and ensure that it comes back in the result

        let browse_paths = vec![BrowsePath {
            starting_node: ObjectId::RootFolder.into(),
            relative_path: RelativePath {
                elements: Some(vec![RelativePathElement {
                    reference_type_id: ReferenceTypeId::Organizes.into(),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(0, "Objects"),
                }]),
            },
        }];

        let request = TranslateBrowsePathsToNodeIdsRequest {
            request_header: make_request_header(),
            browse_paths: Some(browse_paths),
        };

        let response = vs.translate_browse_paths_to_node_ids(server_state, address_space, &request);
        let response: TranslateBrowsePathsToNodeIdsResponse =
            supported_message_as!(response, TranslateBrowsePathsToNodeIdsResponse);

        debug!("result = {:#?}", response);

        let results = response.results.unwrap();
        assert_eq!(results.len(), 1);
        let r1 = &results[0];
        let targets = r1.targets.as_ref().unwrap();
        assert_eq!(targets.len(), 1);
        let t1 = &targets[0];
        assert_eq!(&t1.target_id.node_id, &NodeId::objects_folder_id());
    });
}

#[test]
fn translate_browse_paths_to_node_ids2() {
    do_view_service_test(|server_state, _session, address_space, vs| {
        // Inputs and outputs taken from this testcase in Node OPCUA
        //
        // https://github.com/node-opcua/node-opcua/blob/68b1b57dec23a45148468fbea89ab71a39f9042f/test/end_to_end/u_test_e2e_translateBrowsePath.js

        let starting_node: NodeId = ObjectId::RootFolder.into();

        let browse_paths = [
            "/Objects/Server",
            "/Objects/Server.ServerStatus",
            "/Objects/Server.ServerStatus.BuildInfo",
            "/Objects/Server.ServerStatus.BuildInfo.ProductName",
            "/Objects/Server.ServerStatus.BuildInfo.",
            "/Objects.Server",
            "/Objects/2:MatrikonOPC Simulation Server (DA)",
        ]
        .iter()
        .map(|path| BrowsePath {
            starting_node: starting_node.clone(),
            relative_path: RelativePath::from_str(
                path,
                &RelativePathElement::default_node_resolver,
            )
            .unwrap(),
        })
        .collect::<Vec<_>>();

        let request = TranslateBrowsePathsToNodeIdsRequest {
            request_header: make_request_header(),
            browse_paths: Some(browse_paths),
        };

        let browse_paths_len = request.browse_paths.as_ref().unwrap().len();

        let response = vs.translate_browse_paths_to_node_ids(server_state, address_space, &request);
        let response: TranslateBrowsePathsToNodeIdsResponse =
            supported_message_as!(response, TranslateBrowsePathsToNodeIdsResponse);

        let results = response.results.unwrap();
        assert_eq!(results.len(), browse_paths_len);

        let mut idx = 0;

        // results[0]
        {
            let r = &results[idx];
            assert!(r.status_code.is_good());
            let targets = r.targets.as_ref().unwrap();
            trace!("targets for {} = {:#?}", idx, targets);
            assert_eq!(targets.len(), 1);
            assert_eq!(&targets[0].target_id, &ObjectId::Server.into());
            idx += 1;
        }

        // results[1]
        {
            let r = &results[idx];
            assert!(r.status_code.is_good());
            let targets = r.targets.as_ref().unwrap();
            trace!("targets for {} = {:#?}", idx, targets);
            assert_eq!(targets.len(), 1);
            assert_eq!(
                &targets[0].target_id,
                &VariableId::Server_ServerStatus.into()
            );
            idx += 1;
        }

        // results[2]
        {
            let r = &results[idx];
            assert!(r.status_code.is_good());
            let targets = r.targets.as_ref().unwrap();
            trace!("targets for {} = {:#?}", idx, targets);
            assert_eq!(targets.len(), 1);
            assert_eq!(
                &targets[0].target_id,
                &VariableId::Server_ServerStatus_BuildInfo.into()
            );
            idx += 1;
        }

        // results[3]
        {
            let r = &results[idx];
            assert!(r.status_code.is_good());
            let targets = r.targets.as_ref().unwrap();
            trace!("targets for {} = {:#?}", idx, targets);
            assert_eq!(
                &targets[0].target_id,
                &VariableId::Server_ServerStatus_BuildInfo_ProductName.into()
            );
            idx += 1;
        }

        // results[4]
        {
            let r = &results[idx];
            assert_eq!(r.status_code, StatusCode::BadBrowseNameInvalid);
            idx += 1;
        }

        // results[5]
        {
            let r = &results[idx];
            assert_eq!(r.status_code, StatusCode::BadNoMatch);
            idx += 1;
        }

        // results[6]
        {
            let r = &results[idx];
            assert_eq!(r.status_code, StatusCode::BadNoMatch);
            // idx += 1;
        }
    });
}

struct RegisterNodesImpl {
    pub session: Weak<RwLock<Session>>,
}

impl RegisterNodes for RegisterNodesImpl {
    fn register_nodes(
        &mut self,
        session: Arc<RwLock<Session>>,
        nodes_to_register: &[NodeId],
    ) -> Result<Vec<NodeId>, StatusCode> {
        let bad_node = ObjectId::ObjectsFolder.into();
        let good_node = NodeId::new(1, 100);
        let alias_node = NodeId::new(1, 200);

        if nodes_to_register.contains(&bad_node) {
            Err(StatusCode::BadNodeIdInvalid)
        } else {
            // Simulate holding a weak ref to the session
            self.session = Arc::downgrade(&session);

            // The result will be the input except for the good node which will be aliased on its
            // way out.
            let result = nodes_to_register
                .iter()
                .map(|n| if *n == good_node { &alias_node } else { n })
                .cloned()
                .collect();
            Ok(result)
        }
    }
}

struct UnregisterNodesImpl;

impl UnregisterNodes for UnregisterNodesImpl {
    fn unregister_nodes(
        &mut self,
        _session: Arc<RwLock<Session>>,
        _nodes_to_unregister: &[NodeId],
    ) -> Result<(), StatusCode> {
        Ok(())
    }
}

#[test]
fn register_nodes_nothing_to_do() {
    do_view_service_test(|server_state, session, _address_space, vs| {
        // Empty request
        let response = vs.register_nodes(
            server_state,
            session,
            &RegisterNodesRequest {
                request_header: make_request_header(),
                nodes_to_register: None,
            },
        );
        let response: ServiceFault = supported_message_as!(response, ServiceFault);
        assert_eq!(
            response.response_header.service_result,
            StatusCode::BadNothingToDo
        );
    });
}

#[test]
fn register_nodes_no_handler() {
    do_view_service_test(|server_state, session, _address_space, vs| {
        // Invalid request because impl has no registered handler
        let response = vs.register_nodes(
            server_state,
            session,
            &RegisterNodesRequest {
                request_header: make_request_header(),
                nodes_to_register: Some(vec![ObjectId::ObjectsFolder.into()]),
            },
        );
        let response: RegisterNodesResponse =
            supported_message_as!(response, RegisterNodesResponse);
        let registered_node_ids = response.registered_node_ids.unwrap();
        // The middle node should be aliased
        assert_eq!(registered_node_ids[0], ObjectId::ObjectsFolder.into());
    });
}

#[test]
fn register_nodes() {
    do_view_service_test(|server_state, session, _address_space, vs| {
        // Register the callbacks
        {
            let mut server_state = trace_write_lock!(server_state);
            server_state.set_register_nodes_callbacks(
                Box::new(RegisterNodesImpl {
                    session: Weak::new(),
                }),
                Box::new(UnregisterNodesImpl {}),
            );
        }

        // Make a good call to register
        let response = vs.register_nodes(
            server_state,
            session,
            &RegisterNodesRequest {
                request_header: make_request_header(),
                nodes_to_register: Some(vec![
                    NodeId::new(1, 99),
                    NodeId::new(1, 100),
                    NodeId::new(1, 101),
                ]),
            },
        );
        let response: RegisterNodesResponse =
            supported_message_as!(response, RegisterNodesResponse);
        let registered_node_ids = response.registered_node_ids.unwrap();
        // The middle node should be aliased
        assert_eq!(registered_node_ids[0], NodeId::new(1, 99));
        assert_eq!(registered_node_ids[1], NodeId::new(1, 200));
        assert_eq!(registered_node_ids[2], NodeId::new(1, 101));
    });
}

#[test]
fn unregister_nodes_nothing_to_do() {
    do_view_service_test(|server_state, session, _address_space, vs| {
        // Empty request
        let response = vs.unregister_nodes(
            server_state,
            session,
            &UnregisterNodesRequest {
                request_header: make_request_header(),
                nodes_to_unregister: None,
            },
        );
        let response: ServiceFault = supported_message_as!(response, ServiceFault);
        assert_eq!(
            response.response_header.service_result,
            StatusCode::BadNothingToDo
        );
    });
}

#[test]
fn unregister_nodes() {
    do_view_service_test(|server_state, session, _address_space, vs| {
        // Register the callbacks
        {
            let mut server_state = trace_write_lock!(server_state);
            server_state.set_register_nodes_callbacks(
                Box::new(RegisterNodesImpl {
                    session: Weak::new(),
                }),
                Box::new(UnregisterNodesImpl {}),
            );
        }

        // Not much to validate except that the function returns good
        let response = vs.unregister_nodes(
            server_state,
            session,
            &UnregisterNodesRequest {
                request_header: make_request_header(),
                nodes_to_unregister: Some(vec![
                    NodeId::new(1, 99),
                    ObjectId::ObjectsFolder.into(),
                    NodeId::new(1, 100),
                    NodeId::new(1, 101),
                ]),
            },
        );
        let response: UnregisterNodesResponse =
            supported_message_as!(response, UnregisterNodesResponse);
        assert_eq!(response.response_header.service_result, StatusCode::Good);
    });
}
