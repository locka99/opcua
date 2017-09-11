use prelude::*;
use server::ServerState;
use services::view::ViewService;
use super::*;

// View service tests

fn make_browse_request(nodes: &[NodeId], max_references_per_node: usize, browse_direction: BrowseDirection, reference_type: ReferenceTypeId) -> BrowseRequest {
    let request_header = make_request_header();
    let nodes_to_browse = nodes.iter().map(|n| {
        BrowseDescription {
            node_id: n.clone(),
            browse_direction,
            reference_type_id: reference_type.as_node_id(),
            include_subtypes: true,
            node_class_mask: 0xff,
            result_mask: 0xff,
        }
    }).collect();
    BrowseRequest {
        request_header,
        view: ViewDescription {
            view_id: NodeId::null(),
            timestamp: DateTime::now(),
            view_version: 0,
        },
        requested_max_references_per_node: max_references_per_node as UInt32,
        nodes_to_browse: Some(nodes_to_browse)
    }
}

fn make_browse_next_request(continuation_point: &ByteString, release_continuation_points: bool) -> BrowseNextRequest {
    let request_header = make_request_header();
    BrowseNextRequest {
        request_header,
        release_continuation_points,
        continuation_points: if continuation_point.is_null() { None } else { Some(vec![continuation_point.clone()]) },
    }
}

fn add_many_vars_to_address_space(address_space: &mut AddressSpace, vars_to_add: usize) -> NodeId {
    // Create a sample folder under objects folder
    let sample_folder_id = address_space.add_folder("Many Vars", "Many Vars", &AddressSpace::objects_folder_id()).unwrap();

    // Add as a bunch of sequential vars to the folder
    let mut vars = Vec::with_capacity(vars_to_add);
    for i in 0..vars_to_add {
        let var_name = format!("v{}", i);
        let node_id = NodeId::new_string(1, &var_name);
        let var = Variable::new_i32(&node_id, &var_name, &var_name, "", i as Int32);
        vars.push(var);
    }
    let _ = address_space.add_variables(vars, &sample_folder_id);

    sample_folder_id
}

fn verify_references_to_many_vars(references: &[ReferenceDescription], expected_size: usize, start_idx: usize) {
    // Verify that the reference descriptions point at sequential vars
    assert_eq!(references.len(), expected_size);
    for (i, r) in references.iter().enumerate() {
        let expected_node_id = NodeId::new_string(1, &format!("v{}", i + start_idx));
        assert_eq!(r.node_id.node_id, expected_node_id);
    }
}

fn do_browse(vs: &ViewService, server_state: &mut ServerState, session: &mut Session, nodes: &[NodeId], max_references_per_node: usize) -> BrowseResponse {
    let request = make_browse_request(nodes, max_references_per_node, BrowseDirection::Forward, ReferenceTypeId::Organizes);
    let result = vs.browse(server_state, session, request);
    assert!(result.is_ok());
    supported_message_as!(result.unwrap(), BrowseResponse)
}

fn do_browse_next(vs: &ViewService, server_state: &mut ServerState, session: &mut Session, continuation_point: &ByteString, release_continuation_points: bool) -> BrowseNextResponse {
    let request = make_browse_next_request(continuation_point, release_continuation_points);
    let result = vs.browse_next(server_state, session, request);
    assert!(result.is_ok());
    supported_message_as!(result.unwrap(), BrowseNextResponse)
}

#[test]
fn browse() {
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    let vs = ViewService::new();

    {
        let mut address_space = server_state.address_space.lock().unwrap();
        add_sample_vars_to_address_space(&mut address_space);
    }

    let nodes = vec![ObjectId::RootFolder.as_node_id()];
    let response = do_browse(&vs, &mut server_state, &mut session, &nodes, 1000);
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
}

#[test]
fn browse_next() {
    // Set up a server with more nodes than can fit in a response to test Browse, BrowseNext response
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();
    let parent_node_id = {
        let mut address_space = server_state.address_space.lock().unwrap();
        add_many_vars_to_address_space(&mut address_space, 100)
    };
    let nodes = vec![parent_node_id.clone()];

    let vs = ViewService::new();

    // Browse with requested_max_references_per_node = 101, expect 100 results, no continuation point
    {
        let response = do_browse(&vs, &mut server_state, &mut session, &nodes, 101);
        assert!(response.results.is_some());
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 100, 0);
    }

    // Browse with requested_max_references_per_node = 100, expect 100 results, no continuation point
    {
        let response = do_browse(&vs, &mut server_state, &mut session, &nodes, 100);
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 100, 0);
    }

    // Browse with requested_max_references_per_node = 99 expect 99 results and a continuation point
    // Browse next with continuation point, expect 1 result leaving off from last continuation point
    let continuation_point = {
        // Get first 99
        let response = do_browse(&vs, &mut server_state, &mut session, &nodes, 99);
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(!r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 99, 0);

        // Expect continuation point and browse next to return last var and no more continuation point
        let response = do_browse_next(&vs, &mut server_state, &mut session, &r1.continuation_point, false);
        let r2 = &response.results.unwrap()[0];
        assert!(r2.continuation_point.is_null());
        let references = r2.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 1, 99);

        // Browse next again with same continuation point, expect same 1 result
        let response = do_browse_next(&vs, &mut server_state, &mut session, &r1.continuation_point, false);
        let r2 = &response.results.unwrap()[0];
        assert!(r2.continuation_point.is_null());
        let references = r2.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 1, 99);

        r1.continuation_point.clone()
    };

    // Browse next and release the previous continuation points, expect Null result
    {
        let response = do_browse_next(&vs, &mut server_state, &mut session, &continuation_point, true);
        assert!(response.results.is_none());

        // Browse next again with same continuation point, expect BAD_CONTINUATION_POINT_INVALID
        let response = do_browse_next(&vs, &mut server_state, &mut session, &continuation_point, false);
        let r1 = &response.results.unwrap()[0];
        assert_eq!(r1.status_code, BAD_CONTINUATION_POINT_INVALID);
    }

    // Browse with 35 expect continuation point cp1
    // Browse next with cp1 with 35 expect cp2
    // Browse next with cp2 expect 30 results
    {
        // Get first 35
        let response = do_browse(&vs, &mut server_state, &mut session, &nodes, 35);
        let r1 = &response.results.unwrap()[0];
        let references = r1.references.as_ref().unwrap();
        assert!(!r1.continuation_point.is_null());
        verify_references_to_many_vars(references, 35, 0);

        // Expect continuation point and browse next to return last var and no more continuation point
        let response = do_browse_next(&vs, &mut server_state, &mut session, &r1.continuation_point, false);
        let r2 = &response.results.unwrap()[0];
        assert!(!r2.continuation_point.is_null());
        let references = r2.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 35, 35);

        // Expect continuation point and browse next to return last var and no more continuation point
        let response = do_browse_next(&vs, &mut server_state, &mut session, &r2.continuation_point, false);
        let r3 = &response.results.unwrap()[0];
        assert!(r3.continuation_point.is_null());
        let references = r3.references.as_ref().unwrap();
        verify_references_to_many_vars(references, 30, 70);
    }

    // Modify address space so existing continuation point is invalid
    // Browse next with continuation point, expect BAD_CONTINUATION_POINT_INVALID
    {
        use std::thread;
        use std::time::Duration;

        // Sleep a bit, modify the address space so the old continuation point is out of date
        thread::sleep(Duration::from_millis(50));
        {
            let mut address_space = server_state.address_space.lock().unwrap();
            let var_name = "xxxx";
            let node_id = NodeId::new_string(1, var_name);
            let var = Variable::new_i32(&node_id, var_name, var_name, "", 200);
            let _ = address_space.add_variable(var, &parent_node_id);
        }

        // Browsing with the old continuation point should fail
        let response = do_browse_next(&vs, &mut server_state, &mut session, &continuation_point, false);
        let r1 = &response.results.unwrap()[0];
        assert_eq!(r1.status_code, BAD_CONTINUATION_POINT_INVALID);
    }
}

#[test]
fn translate_browse_paths_to_node_ids() {
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    // This is a very basic test of this service. It just creates a relative path from root to the
    // Objects folder and tests that it comes back in the result
    {
        let mut browse_paths = Vec::new();
        let mut path_elements = Vec::new();
        path_elements.push(RelativePathElement {
            reference_type_id: ReferenceTypeId::HasChild.as_node_id(),
            is_inverse: false,
            include_subtypes: true,
            target_name: QualifiedName::new(0, "Objects"),
        });

        browse_paths.push(BrowsePath {
            starting_node: ObjectId::RootFolder.as_node_id(),
            relative_path: RelativePath {
                elements: Some(path_elements),
            }
        });

        let request = TranslateBrowsePathsToNodeIdsRequest {
            request_header: make_request_header(),
            browse_paths: Some(browse_paths)
        };

        let vs = ViewService::new();
        let result = vs.translate_browse_paths_to_node_ids(&mut server_state, &mut session, request);
        assert!(result.is_ok());
        let result: TranslateBrowsePathsToNodeIdsResponse = supported_message_as!(result.unwrap(), TranslateBrowsePathsToNodeIdsResponse);

        debug!("result = {:#?}", result);

        let results = result.results.unwrap();
        assert_eq!(results.len(), 1);
        let r1 = &results[0];
        /*
        let targets = r1.targets.as_ref().unwrap();
        assert_eq!(targets.len(), 1);
        let t1 = &targets[0];
        assert_eq!(&t1.target_id.node_id, &AddressSpace::objects_folder_id());
        */
    }
}
