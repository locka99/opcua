use std::sync::Arc;

use crate::server::{
    address_space::{
        references::Reference,
        relative_path::{find_node_from_browse_path, find_nodes_relative_path_simple},
        EventNotifier,
    },
    callbacks,
    prelude::*,
    tests::*,
};

#[test]
fn address_space() {
    let address_space = AddressSpace::new();

    let root_folder = address_space.root_folder();
    assert_eq!(root_folder.node_class(), NodeClass::Object);
    let objects_folder = address_space.objects_folder();
    assert_eq!(objects_folder.node_class(), NodeClass::Object);
    let types_folder = address_space.types_folder();
    assert_eq!(types_folder.node_class(), NodeClass::Object);
    let views_folder = address_space.views_folder();
    assert_eq!(views_folder.node_class(), NodeClass::Object);
}

#[test]
fn namespaces() {
    // Test that namespaces are listed properly
    let mut address_space = AddressSpace::new();

    let ns = address_space.register_namespace("urn:test").unwrap();

    assert_eq!(
        address_space
            .namespace_index("http://opcfoundation.org/UA/")
            .unwrap(),
        0u16
    );
    assert_eq!(address_space.namespace_index("urn:test").unwrap(), ns);
    // Error
    assert_eq!(address_space.register_namespace(""), Err(()));
    // Add new namespaces
    assert_eq!(address_space.register_namespace("foo").unwrap(), 2u16);
    assert_eq!(address_space.register_namespace("bar").unwrap(), 3u16);
    // Test if existing namespace is found
    assert_eq!(address_space.register_namespace("foo").unwrap(), 2u16);
}

#[test]
fn find_root_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&NodeId::new(0, 84));
    assert!(node_type.is_some());

    let node = node_type.unwrap().as_node();
    assert_eq!(node.node_id(), NodeId::new(0, 84));
    assert_eq!(node.node_id(), ObjectId::RootFolder.into());
}

#[test]
fn find_objects_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find(ObjectId::ObjectsFolder);
    assert!(node_type.is_some());
}

#[test]
fn find_types_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find(ObjectId::TypesFolder);
    assert!(node_type.is_some());
}

#[test]
fn find_views_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find(ObjectId::ViewsFolder);
    assert!(node_type.is_some());
}

#[test]
fn find_common_nodes() {
    let address_space = AddressSpace::new();
    let nodes: Vec<NodeId> = vec![
        ObjectId::RootFolder.into(),
        ObjectId::ObjectsFolder.into(),
        ObjectId::TypesFolder.into(),
        ObjectId::ViewsFolder.into(),
        ObjectId::DataTypesFolder.into(),
        DataTypeId::BaseDataType.into(),
        // Types
        DataTypeId::Boolean.into(),
        DataTypeId::ByteString.into(),
        DataTypeId::DataValue.into(),
        DataTypeId::DateTime.into(),
        DataTypeId::DiagnosticInfo.into(),
        DataTypeId::Enumeration.into(),
        DataTypeId::ExpandedNodeId.into(),
        DataTypeId::Guid.into(),
        DataTypeId::LocalizedText.into(),
        DataTypeId::NodeId.into(),
        DataTypeId::Number.into(),
        DataTypeId::QualifiedName.into(),
        DataTypeId::StatusCode.into(),
        DataTypeId::String.into(),
        DataTypeId::Structure.into(),
        DataTypeId::XmlElement.into(),
        DataTypeId::Double.into(),
        DataTypeId::Float.into(),
        DataTypeId::Integer.into(),
        DataTypeId::SByte.into(),
        DataTypeId::Int16.into(),
        DataTypeId::Int32.into(),
        DataTypeId::Int64.into(),
        DataTypeId::Byte.into(),
        DataTypeId::UInt16.into(),
        DataTypeId::UInt32.into(),
        DataTypeId::UInt64.into(),
        ObjectId::OPCBinarySchema_TypeSystem.into(),
        ObjectTypeId::DataTypeSystemType.into(),
        // Refs
        ObjectId::ReferenceTypesFolder.into(),
        ReferenceTypeId::References.into(),
        ReferenceTypeId::HierarchicalReferences.into(),
        ReferenceTypeId::HasChild.into(),
        ReferenceTypeId::HasSubtype.into(),
        ReferenceTypeId::Organizes.into(),
        ReferenceTypeId::NonHierarchicalReferences.into(),
        ReferenceTypeId::HasTypeDefinition.into(),
    ];
    for n in nodes {
        assert!(address_space.find_node(&n).is_some());
    }
}

#[test]
fn object_attributes() {
    let on = NodeId::new(1, "o1");
    let o = Object::new(&on, "Browse01", "Display01", EventNotifier::empty());
    assert_eq!(o.node_class(), NodeClass::Object);
    assert_eq!(o.node_id(), on);
    assert_eq!(o.browse_name(), QualifiedName::new(0, "Browse01"));
    assert_eq!(o.display_name(), LocalizedText::new("", "Display01"));
}

#[test]
fn find_node_by_id() {
    let address_space = make_sample_address_space();
    let mut address_space = trace_write_lock!(address_space);
    let ns = address_space.register_namespace("urn:test").unwrap();

    assert!(!address_space.node_exists(&NodeId::null()));
    assert!(!address_space.node_exists(&NodeId::new(11, "v3")));

    assert!(address_space.node_exists(&NodeId::new(ns, "v1")));
    assert!(address_space.node_exists(&NodeId::new(ns, 300)));
    assert!(address_space.node_exists(&NodeId::new(ns, "v3")));
}

fn dump_references(references: &Vec<Reference>) {
    for r in references {
        println!(
            "Referencs - type = {:?}, to = {:?}",
            r.reference_type, r.target_node
        );
    }
}

#[test]
fn find_references_by_direction() {
    let address_space = make_sample_address_space();
    let address_space = trace_read_lock!(address_space);

    let (references, _inverse_ref_idx) = address_space
        .find_references_by_direction::<ReferenceTypeId>(
            &NodeId::objects_folder_id(),
            BrowseDirection::Forward,
            None,
        );
    dump_references(&references);
    assert_eq!(references.len(), 3);

    // Should be same as filtering on None
    let reference_filter = Some((ReferenceTypeId::References, true));
    let (references, _inverse_ref_idx) = address_space.find_references_by_direction(
        &NodeId::objects_folder_id(),
        BrowseDirection::Forward,
        reference_filter,
    );
    dump_references(&references);
    assert_eq!(references.len(), 3);

    // Only organizes
    let reference_filter = Some((ReferenceTypeId::Organizes, false));
    let (references, _inverse_ref_idx) = address_space.find_references_by_direction(
        &NodeId::objects_folder_id(),
        BrowseDirection::Forward,
        reference_filter,
    );
    dump_references(&references);
    assert_eq!(references.len(), 2);

    // Reverse organises should == 1 (root organises objects)
    let (references, _inverse_ref_idx) = address_space.find_references_by_direction(
        &NodeId::objects_folder_id(),
        BrowseDirection::Inverse,
        reference_filter,
    );
    dump_references(&references);
    assert_eq!(references.len(), 1);

    // Both directions
    let (references, inverse_ref_idx) = address_space.find_references_by_direction(
        &NodeId::objects_folder_id(),
        BrowseDirection::Both,
        reference_filter,
    );
    dump_references(&references);
    assert_eq!(references.len(), 3);
    assert_eq!(inverse_ref_idx, 2);
}

#[test]
fn find_references() {
    let address_space = make_sample_address_space();
    let address_space = trace_read_lock!(address_space);

    let references = address_space.find_references(
        &NodeId::root_folder_id(),
        Some((ReferenceTypeId::Organizes, false)),
    );
    assert!(references.is_some());
    let references = references.as_ref().unwrap();
    dump_references(&references);
    assert_eq!(references.len(), 3);

    let references =
        address_space.find_references::<ReferenceTypeId>(&NodeId::root_folder_id(), None);
    assert!(references.is_some());
    let references = references.as_ref().unwrap();
    dump_references(&references);
    assert_eq!(references.len(), 4);

    let references = address_space.find_references(
        &NodeId::objects_folder_id(),
        Some((ReferenceTypeId::Organizes, false)),
    );
    assert!(references.is_some());
    let references = references.unwrap();
    dump_references(&references);
    assert_eq!(references.len(), 2);

    let r1 = &references[0];
    assert_eq!(r1.reference_type, ReferenceTypeId::Organizes.into());
    let child_node_id = r1.target_node.clone();

    let child = address_space.find_node(&child_node_id);
    assert!(child.is_some());
}

#[test]
fn find_inverse_references() {
    let address_space = make_sample_address_space();
    let address_space = trace_read_lock!(address_space);

    //println!("{:#?}", address_space);
    let references = address_space.find_inverse_references(
        &NodeId::root_folder_id(),
        Some((ReferenceTypeId::Organizes, false)),
    );
    assert!(references.is_none());

    let references = address_space.find_inverse_references(
        &NodeId::objects_folder_id(),
        Some((ReferenceTypeId::Organizes, false)),
    );
    assert!(references.is_some());
    let references = references.unwrap();
    assert_eq!(references.len(), 1);
}

#[test]
fn find_reference_subtypes() {
    let address_space = make_sample_address_space();
    let address_space = trace_read_lock!(address_space);

    let references = address_space.references();
    let reference_types = vec![
        (
            ReferenceTypeId::References,
            ReferenceTypeId::HierarchicalReferences,
        ),
        (ReferenceTypeId::References, ReferenceTypeId::HasChild),
        (ReferenceTypeId::References, ReferenceTypeId::HasSubtype),
        (ReferenceTypeId::References, ReferenceTypeId::Organizes),
        (ReferenceTypeId::References, ReferenceTypeId::Aggregates),
        (ReferenceTypeId::References, ReferenceTypeId::HasProperty),
        (ReferenceTypeId::References, ReferenceTypeId::HasComponent),
        (
            ReferenceTypeId::References,
            ReferenceTypeId::HasOrderedComponent,
        ),
        (ReferenceTypeId::References, ReferenceTypeId::HasEventSource),
        (ReferenceTypeId::References, ReferenceTypeId::HasNotifier),
        (ReferenceTypeId::References, ReferenceTypeId::GeneratesEvent),
        (
            ReferenceTypeId::References,
            ReferenceTypeId::AlwaysGeneratesEvent,
        ),
        (ReferenceTypeId::References, ReferenceTypeId::HasEncoding),
        (
            ReferenceTypeId::References,
            ReferenceTypeId::HasModellingRule,
        ),
        (ReferenceTypeId::References, ReferenceTypeId::HasDescription),
        (
            ReferenceTypeId::References,
            ReferenceTypeId::HasTypeDefinition,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasChild,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasSubtype,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::Organizes,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::Aggregates,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasProperty,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasComponent,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasOrderedComponent,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasEventSource,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasNotifier,
        ),
        (ReferenceTypeId::HasChild, ReferenceTypeId::Aggregates),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasComponent),
        (
            ReferenceTypeId::HasChild,
            ReferenceTypeId::HasHistoricalConfiguration,
        ),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasProperty),
        (
            ReferenceTypeId::HasChild,
            ReferenceTypeId::HasOrderedComponent,
        ),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasSubtype),
        (ReferenceTypeId::Aggregates, ReferenceTypeId::HasComponent),
        (
            ReferenceTypeId::Aggregates,
            ReferenceTypeId::HasHistoricalConfiguration,
        ),
        (ReferenceTypeId::Aggregates, ReferenceTypeId::HasProperty),
        (
            ReferenceTypeId::Aggregates,
            ReferenceTypeId::HasOrderedComponent,
        ),
        (
            ReferenceTypeId::HasComponent,
            ReferenceTypeId::HasOrderedComponent,
        ),
        (
            ReferenceTypeId::HasEventSource,
            ReferenceTypeId::HasNotifier,
        ),
        (
            ReferenceTypeId::HierarchicalReferences,
            ReferenceTypeId::HasNotifier,
        ),
        (
            ReferenceTypeId::References,
            ReferenceTypeId::NonHierarchicalReferences,
        ),
        (
            ReferenceTypeId::NonHierarchicalReferences,
            ReferenceTypeId::GeneratesEvent,
        ),
        (
            ReferenceTypeId::NonHierarchicalReferences,
            ReferenceTypeId::AlwaysGeneratesEvent,
        ),
        (
            ReferenceTypeId::NonHierarchicalReferences,
            ReferenceTypeId::HasEncoding,
        ),
        (
            ReferenceTypeId::NonHierarchicalReferences,
            ReferenceTypeId::HasModellingRule,
        ),
        (
            ReferenceTypeId::NonHierarchicalReferences,
            ReferenceTypeId::HasDescription,
        ),
        (
            ReferenceTypeId::NonHierarchicalReferences,
            ReferenceTypeId::HasTypeDefinition,
        ),
        (
            ReferenceTypeId::GeneratesEvent,
            ReferenceTypeId::AlwaysGeneratesEvent,
        ),
    ];

    // A type should always match itself
    assert!(references.reference_type_matches(
        &ReferenceTypeId::NonHierarchicalReferences.into(),
        &ReferenceTypeId::NonHierarchicalReferences.into(),
        true
    ));
    assert!(references.reference_type_matches(
        &ReferenceTypeId::NonHierarchicalReferences.into(),
        &ReferenceTypeId::NonHierarchicalReferences.into(),
        false
    ));

    // Make sure that subtypes match when subtypes are to be compared and doesn't when they should
    // not be compared.
    reference_types.iter().for_each(|r| {
        let r1 = r.0.into();
        let r2 = r.1.into();
        assert!(references.reference_type_matches(&r1, &r2, true));
        assert!(!references.reference_type_matches(&r1, &r2, false));
    });
}

/// This test is to ensure that adding a Variable with a value of Array to address space sets the
/// ValueRank and ArrayDimensions attributes correctly.
#[test]
fn array_as_variable() {
    // 1 dimensional array with 100 element
    let values = (0..100)
        .map(|i| Variant::Int32(i))
        .collect::<Vec<Variant>>();

    // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
    let node_id = NodeId::new(2, 1);
    let v = Variable::new(&node_id, "x", "x", (VariantTypeId::Int32, values));

    let value_rank = v.value_rank();
    assert_eq!(value_rank, 1);
    let array_dimensions = v.array_dimensions().unwrap();
    assert_eq!(array_dimensions, vec![100u32]);
}

/// This test is to ensure that adding a Variable with a value of Array to address space sets the
/// ValueRank and ArrayDimensions attributes correctly.
#[test]
fn multi_dimension_array_as_variable() {
    // 2 dimensional array with 10x10 elements

    let values = (0..100)
        .map(|i| Variant::Int32(i))
        .collect::<Vec<Variant>>();
    let mda = Array::new_multi(VariantTypeId::Int32, values, vec![10u32, 10u32]).unwrap();
    assert!(mda.is_valid());

    // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
    let node_id = NodeId::new(2, 1);
    let v = Variable::new(&node_id, "x", "x", mda);

    let value_rank = v.value_rank();
    assert_eq!(value_rank, 2);
    let array_dimensions = v.array_dimensions().unwrap();
    assert_eq!(array_dimensions, vec![10u32, 10u32]);
}

#[test]
fn browse_nodes() {
    let address_space = make_sample_address_space();
    let address_space = trace_read_lock!(address_space);

    // Test that a node can be found
    let object_id = ObjectId::RootFolder.into();
    let result = find_node_from_browse_path(
        &address_space,
        &object_id,
        &vec!["Objects".into(), "Sample".into(), "v1".into()],
    );
    let node = result.unwrap();
    assert_eq!(node.as_node().browse_name(), QualifiedName::from("v1"));

    // Test that a non existent node cannot be found
    let result = find_node_from_browse_path(
        &address_space,
        &object_id,
        &vec!["Objects".into(), "Sample".into(), "vxxx".into()],
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), StatusCode::BadNotFound);
}

#[test]
fn find_nodes_relative_path() {
    let address_space = make_sample_address_space();
    let address_space = trace_read_lock!(address_space);

    // Given some paths, find the nodes
    let parent_node = ObjectId::RootFolder.into();

    let relative_path = "/Objects/Server.ServerStatus.BuildInfo.ProductName";

    let results =
        find_nodes_relative_path_simple(&address_space, &parent_node, relative_path).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0],
        VariableId::Server_ServerStatus_BuildInfo_ProductName.into()
    );
}

#[test]
fn object_builder() {
    let mut address_space = AddressSpace::new();

    let node_type_id = NodeId::new(1, "HelloType");
    let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
        .subtype_of(ObjectTypeId::BaseObjectType)
        .insert(&mut address_space);

    let node_id = NodeId::new(1, "Hello");
    let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .organized_by(ObjectId::ObjectsFolder)
        .has_type_definition(node_type_id.clone())
        .insert(&mut address_space);

    // Verify the variable is there
    let _o = match address_space.find_node(&node_id).unwrap() {
        NodeType::Object(o) => o,
        _ => panic!(),
    };

    // Verify the reference to the objects folder is there
    assert!(address_space.has_reference(
        &ObjectId::ObjectsFolder.into(),
        &node_id,
        ReferenceTypeId::Organizes
    ));
    assert!(address_space.has_reference(
        &node_id,
        &node_type_id,
        ReferenceTypeId::HasTypeDefinition
    ));
}

#[test]
fn object_type_builder() {
    let mut address_space = AddressSpace::new();

    let node_type_id = NodeId::new(1, "HelloType");
    let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
        .subtype_of(ObjectTypeId::BaseObjectType)
        .insert(&mut address_space);

    let _ot = match address_space.find_node(&node_type_id).unwrap() {
        NodeType::ObjectType(ot) => ot,
        _ => panic!(),
    };

    assert!(address_space.has_reference(
        &ObjectTypeId::BaseObjectType.into(),
        &node_type_id,
        ReferenceTypeId::HasSubtype
    ));
}

#[test]
fn variable_builder() {
    let result = std::panic::catch_unwind(|| {
        // This should panic
        let _v = VariableBuilder::new(&NodeId::null(), "", "").build();
    });
    assert!(result.is_err());

    // This should build
    let _v = VariableBuilder::new(&NodeId::new(1, 1), "", "")
        .data_type(DataTypeId::Boolean)
        .build();

    // Check a variable with a bunch of fields set
    let v = VariableBuilder::new(&NodeId::new(1, "Hello"), "BrowseName", "DisplayName")
        .description("Desc")
        .data_type(DataTypeId::UInt32)
        .value_rank(10)
        .array_dimensions(&[1, 2, 3])
        .historizing(true)
        .value(Variant::from(999))
        .minimum_sampling_interval(123.0)
        .build();

    assert_eq!(v.node_id(), NodeId::new(1, "Hello"));
    assert_eq!(v.browse_name(), QualifiedName::new(0, "BrowseName"));
    assert_eq!(v.display_name(), LocalizedText::new("", "DisplayName"));
    assert_eq!(v.data_type(), DataTypeId::UInt32.into());
    assert_eq!(v.description().unwrap(), LocalizedText::new("", "Desc"));
    assert_eq!(v.value_rank(), 10);
    assert_eq!(v.array_dimensions().unwrap(), vec![1, 2, 3]);
    assert_eq!(v.historizing(), true);
    assert_eq!(
        v.value(
            TimestampsToReturn::Neither,
            NumericRange::None,
            &QualifiedName::null(),
            0.0
        )
        .value
        .unwrap(),
        Variant::from(999)
    );
    assert_eq!(v.minimum_sampling_interval().unwrap(), 123.0);

    // Add a variable to the address space

    let mut address_space = AddressSpace::new();
    let node_id = NodeId::new(1, "Hello");
    let _v = VariableBuilder::new(&node_id, "BrowseName", "DisplayName")
        .description("Desc")
        .value_rank(10)
        .data_type(DataTypeId::UInt32)
        .array_dimensions(&[1, 2, 3])
        .historizing(true)
        .value(Variant::from(999))
        .minimum_sampling_interval(123.0)
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut address_space);

    // Verify the variable is there
    assert!(address_space.find_variable_by_ref(&node_id).is_some());
    // Verify the reference to the objects folder is there
    assert!(address_space.has_reference(
        &ObjectId::ObjectsFolder.into(),
        &node_id,
        ReferenceTypeId::Organizes
    ));
}

#[test]
fn method_builder() {
    let mut address_space = AddressSpace::new();

    let ns = address_space.register_namespace("urn:test").unwrap();

    let object_id: NodeId = ObjectId::ObjectsFolder.into();

    let fn_node_id = NodeId::new(ns, "HelloWorld");

    let inserted = MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
        .component_of(object_id.clone())
        .output_args(&mut address_space, &[("Result", DataTypeId::String).into()])
        .callback(Box::new(HelloWorld))
        .insert(&mut address_space);
    assert!(inserted);

    let method = match address_space.find_node(&fn_node_id).unwrap() {
        NodeType::Method(m) => m,
        _ => panic!(),
    };

    assert!(method.has_callback());

    let refs = address_space
        .find_references(&fn_node_id, Some((ReferenceTypeId::HasProperty, false)))
        .unwrap();
    assert_eq!(refs.len(), 1);

    let child = address_space
        .find_node(&refs.get(0).unwrap().target_node)
        .unwrap();
    if let NodeType::Variable(v) = child {
        // verify OutputArguments
        // verify OutputArguments / Argument value
        assert_eq!(v.data_type(), DataTypeId::Argument.into());
        assert_eq!(v.display_name(), LocalizedText::from("OutputArguments"));
        let v = v
            .value(
                TimestampsToReturn::Neither,
                NumericRange::None,
                &QualifiedName::null(),
                0.0,
            )
            .value
            .unwrap();
        if let Variant::Array(array) = v {
            let v = array.values;
            assert_eq!(v.len(), 1);
            let v = v.get(0).unwrap().clone();
            if let Variant::ExtensionObject(v) = v {
                // deserialize the Argument here
                let decoding_options = DecodingOptions::test();
                let argument = v.decode_inner::<Argument>(&decoding_options).unwrap();
                assert_eq!(argument.name, UAString::from("Result"));
                assert_eq!(argument.data_type, DataTypeId::String.into());
                assert_eq!(argument.value_rank, -1);
                assert_eq!(argument.array_dimensions, None);
                assert_eq!(argument.description, LocalizedText::null());
            } else {
                panic!("Variant was expected to be extension object, was {:?}", v);
            }
        } else {
            panic!("Variant was expected to be array, was {:?}", v);
        }
    } else {
        panic!();
    }
}

struct HelloWorld;

impl callbacks::Method for HelloWorld {
    fn call(
        &mut self,
        _session_id: &NodeId,
        _session_map: Arc<RwLock<SessionManager>>,
        _request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode> {
        Ok(CallMethodResult {
            status_code: StatusCode::Good,
            input_argument_results: Some(vec![StatusCode::Good]),
            input_argument_diagnostic_infos: None,
            output_arguments: Some(vec![Variant::from("Hello World!")]),
        })
    }
}

#[test]
fn simple_delete_node() {
    crate::console_logging::init();

    // This is a super basic, debuggable delete test. There is a single Root node, and a
    // child object. After deleting the child, only the Root should exist with no references at
    // all to the child.

    // A blank address space, with nothing at all in it
    let mut address_space = AddressSpace::default();

    // Add a root node
    let root_node = NodeId::root_folder_id();

    let node = Object::new(&root_node, "Root", "", EventNotifier::empty());
    let _ = address_space.insert::<Object, ReferenceTypeId>(node, None);

    let node_id = NodeId::new(1, "Hello");
    let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
        .organized_by(root_node.clone())
        .insert(&mut address_space);

    // Verify the object and refs are there
    assert!(address_space.find_node(&node_id).is_some());
    assert!(address_space.has_reference(&root_node, &node_id, ReferenceTypeId::Organizes));

    // Try one time deleting references, the other time not deleting them.
    address_space.delete(&node_id, true);
    // Delete the node and the refs
    assert!(address_space.find_node(&node_id).is_none());
    assert!(address_space.find_node(&root_node).is_some());
    assert!(!address_space.has_reference(&root_node, &node_id, ReferenceTypeId::Organizes));
    assert!(!address_space
        .references()
        .reference_to_node_exists(&node_id));
}

#[test]
fn delete_node() {
    crate::console_logging::init();

    // Try creating and deleting a node, verifying that it's totally gone afterwards
    (0..2).for_each(|i| {
        let mut address_space = AddressSpace::new();

        let node_type_id = NodeId::new(1, "HelloType");
        let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

        let node_id = NodeId::new(1, "Hello");
        let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
            .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
            .organized_by(ObjectId::ObjectsFolder)
            .has_type_definition(node_type_id.clone())
            .insert(&mut address_space);

        // Verify the object and refs are there
        assert!(address_space.find_node(&node_id).is_some());
        assert!(address_space.has_reference(
            &ObjectId::ObjectsFolder.into(),
            &node_id,
            ReferenceTypeId::Organizes
        ));
        assert!(!address_space.has_reference(
            &node_id,
            &ObjectId::ObjectsFolder.into(),
            ReferenceTypeId::Organizes
        ));
        assert!(address_space.has_reference(
            &node_id,
            &node_type_id,
            ReferenceTypeId::HasTypeDefinition
        ));

        // Try one time deleting references, the other time not deleting them.
        let delete_references = i == 1;
        address_space.delete(&node_id, delete_references);
        if !delete_references {
            // Deleted the node but not refs
            assert!(address_space.find_node(&node_id).is_none());
            assert!(address_space.has_reference(
                &ObjectId::ObjectsFolder.into(),
                &node_id,
                ReferenceTypeId::Organizes
            ));
            assert!(address_space.has_reference(
                &node_id,
                &node_type_id,
                ReferenceTypeId::HasTypeDefinition
            ));
        } else {
            // Delete the node and the refs
            assert!(address_space.find_node(&node_id).is_none());
            assert!(!address_space.has_reference(
                &ObjectId::ObjectsFolder.into(),
                &node_id,
                ReferenceTypeId::Organizes
            ));
            assert!(!address_space.has_reference(
                &node_id,
                &node_type_id,
                ReferenceTypeId::HasTypeDefinition
            ));
            assert!(!address_space
                .references()
                .reference_to_node_exists(&node_id));
        }
    });
}

#[test]
fn is_subtype() {
    let address_space = AddressSpace::new();
    // Test subtypes against other and the expected result
    let subtypes = [
        // Positive
        (
            ObjectTypeId::BaseEventType,
            ObjectTypeId::BaseEventType,
            true,
        ),
        (
            ObjectTypeId::AuditEventType,
            ObjectTypeId::BaseEventType,
            true,
        ),
        (
            ObjectTypeId::BaseModelChangeEventType,
            ObjectTypeId::BaseEventType,
            true,
        ),
        (
            ObjectTypeId::AuditHistoryUpdateEventType,
            ObjectTypeId::BaseEventType,
            true,
        ),
        (
            ObjectTypeId::AuditUrlMismatchEventType,
            ObjectTypeId::AuditSessionEventType,
            true,
        ),
        // Negative
        //   BaseEventType is not a subtype of AuditEventType
        (
            ObjectTypeId::BaseEventType,
            ObjectTypeId::AuditEventType,
            false,
        ),
        //   DeviceFailureEventType is not a subtype of ProgressEventType (different branches)
        (
            ObjectTypeId::DeviceFailureEventType,
            ObjectTypeId::ProgressEventType,
            false,
        ),
        //   SystemEventType is not a subtype of ProgressEventType (peers)
        (
            ObjectTypeId::SystemEventType,
            ObjectTypeId::ProgressEventType,
            false,
        ),
    ];
    subtypes.iter().for_each(|v| {
        println!(
            "Expecting {:?} to be a subtype of {:?} == {:?}",
            v.0, v.1, v.2
        );
        assert_eq!(address_space.is_subtype(&v.0.into(), &v.1.into()), v.2);
    });
}

#[test]
fn hierarchical_references() {
    let address_space = AddressSpace::new();

    // Try with root
    let refs = address_space
        .find_hierarchical_references(&NodeId::root_folder_id())
        .unwrap();
    assert_eq!(refs.len(), 3);
    assert!(refs.contains(&NodeId::objects_folder_id()));
    assert!(refs.contains(&NodeId::views_folder_id()));
    assert!(refs.contains(&NodeId::types_folder_id()));

    // Try with an object that has some properties
    let node = ObjectId::Server_ServerCapabilities.into();
    let refs = address_space.find_hierarchical_references(&node).unwrap();
    println!("{:#?}", refs);
    assert_eq!(refs.len(), 15);
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_ServerProfileArray.into()));
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_LocaleIdArray.into()));
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_MinSupportedSampleRate.into()));
    assert!(
        refs.contains(&VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints.into())
    );
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints.into()));
    assert!(
        refs.contains(&VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints.into())
    );
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_SoftwareCertificates.into()));
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_MaxArrayLength.into()));
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_MaxStringLength.into()));
    assert!(refs.contains(&VariableId::Server_ServerCapabilities_MaxByteStringLength.into()));
    assert!(refs.contains(&ObjectId::Server_ServerCapabilities_OperationLimits.into()));
    assert!(refs.contains(&ObjectId::Server_ServerCapabilities_ModellingRules.into()));
    assert!(refs.contains(&ObjectId::Server_ServerCapabilities_AggregateFunctions.into()));
    assert!(refs.contains(&ObjectId::HistoryServerCapabilities.into()));
}
