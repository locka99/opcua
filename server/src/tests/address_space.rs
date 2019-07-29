use crate::prelude::*;

use crate::tests::*;
use crate::address_space::{
    EventNotifier,
    references::Reference,
    relative_path::find_node_from_browse_path,
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
    let node_type = address_space.find_node(&ObjectId::ObjectsFolder.into());
    assert!(node_type.is_some());
}

#[test]
fn find_types_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::TypesFolder.into());
    assert!(node_type.is_some());
}

#[test]
fn find_views_folder() {
    let address_space = AddressSpace::new();
    let node_type = address_space.find_node(&ObjectId::ViewsFolder.into());
    assert!(node_type.is_some());
}


#[test]
fn find_common_nodes() {
    let address_space = AddressSpace::new();
    let nodes: Vec<NodeId> = vec![
        AddressSpace::root_folder_id(),
        AddressSpace::objects_folder_id(),
        AddressSpace::types_folder_id(),
        AddressSpace::views_folder_id(),
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

    assert!(!address_space.node_exists(&NodeId::null()));
    assert!(!address_space.node_exists(&NodeId::new(11, "v3")));

    assert!(address_space.node_exists(&NodeId::new(1, "v1")));
    assert!(address_space.node_exists(&NodeId::new(2, 300)));
    assert!(address_space.node_exists(&NodeId::new(1, "v3")));
}

fn dump_references(references: &Vec<Reference>) {
    for r in references {
        println!("Referencs - type = {:?}, to = {:?}", r.reference_type_id, r.target_node_id);
    }
}

#[test]
fn find_references_by_direction() {
    let address_space = make_sample_address_space();

    let (references, _inverse_ref_idx) = address_space.find_references_by_direction::<ReferenceTypeId>(&AddressSpace::objects_folder_id(), BrowseDirection::Forward, None);
    dump_references(&references);
    assert_eq!(references.len(), 3);

    // Should be same as filtering on None
    let reference_filter = Some((ReferenceTypeId::References, true));
    let (references, _inverse_ref_idx) = address_space.find_references_by_direction(&AddressSpace::objects_folder_id(), BrowseDirection::Forward, reference_filter);
    dump_references(&references);
    assert_eq!(references.len(), 3);

    // Only organizes
    let reference_filter = Some((ReferenceTypeId::Organizes, false));
    let (references, _inverse_ref_idx) = address_space.find_references_by_direction(&AddressSpace::objects_folder_id(), BrowseDirection::Forward, reference_filter);
    dump_references(&references);
    assert_eq!(references.len(), 2);

    // Reverse organises should == 1 (root organises objects)
    let (references, _inverse_ref_idx) = address_space.find_references_by_direction(&AddressSpace::objects_folder_id(), BrowseDirection::Inverse, reference_filter);
    dump_references(&references);
    assert_eq!(references.len(), 1);

    // Both directions
    let (references, inverse_ref_idx) = address_space.find_references_by_direction(&AddressSpace::objects_folder_id(), BrowseDirection::Both, reference_filter);
    dump_references(&references);
    assert_eq!(references.len(), 3);
    assert_eq!(inverse_ref_idx, 2);
}

#[test]
fn find_references_from() {
    let address_space = make_sample_address_space();

    let references = address_space.find_references_from(&AddressSpace::root_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_some());
    let references = references.as_ref().unwrap();
    dump_references(&references);
    assert_eq!(references.len(), 3);

    let references = address_space.find_references_from::<ReferenceTypeId>(&AddressSpace::root_folder_id(), None);
    assert!(references.is_some());
    let references = references.as_ref().unwrap();
    dump_references(&references);
    assert_eq!(references.len(), 4);

    let references = address_space.find_references_from(&AddressSpace::objects_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_some());
    let references = references.unwrap();
    dump_references(&references);
    assert_eq!(references.len(), 2);

    let r1 = &references[0];
    assert_eq!(r1.reference_type_id, ReferenceTypeId::Organizes.into());
    let child_node_id = r1.target_node_id.clone();

    let child = address_space.find_node(&child_node_id);
    assert!(child.is_some());
}

#[test]
fn find_references_to() {
    let address_space = make_sample_address_space();

    //println!("{:#?}", address_space);
    let references = address_space.find_references_to(&AddressSpace::root_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_none());

    let references = address_space.find_references_to(&AddressSpace::objects_folder_id(), Some((ReferenceTypeId::Organizes, false)));
    assert!(references.is_some());
    let references = references.unwrap();
    assert_eq!(references.len(), 1);
}

#[test]
fn find_reference_subtypes() {
    let address_space = make_sample_address_space();
    let references = address_space.references();

    let reference_types = vec![
        (ReferenceTypeId::References, ReferenceTypeId::HierarchicalReferences),
        (ReferenceTypeId::References, ReferenceTypeId::HasChild),
        (ReferenceTypeId::References, ReferenceTypeId::HasSubtype),
        (ReferenceTypeId::References, ReferenceTypeId::Organizes),
        (ReferenceTypeId::References, ReferenceTypeId::Aggregates),
        (ReferenceTypeId::References, ReferenceTypeId::HasProperty),
        (ReferenceTypeId::References, ReferenceTypeId::HasComponent),
        (ReferenceTypeId::References, ReferenceTypeId::HasOrderedComponent),
        (ReferenceTypeId::References, ReferenceTypeId::HasEventSource),
        (ReferenceTypeId::References, ReferenceTypeId::HasNotifier),
        (ReferenceTypeId::References, ReferenceTypeId::GeneratesEvent),
        (ReferenceTypeId::References, ReferenceTypeId::AlwaysGeneratesEvent),
        (ReferenceTypeId::References, ReferenceTypeId::HasEncoding),
        (ReferenceTypeId::References, ReferenceTypeId::HasModellingRule),
        (ReferenceTypeId::References, ReferenceTypeId::HasDescription),
        (ReferenceTypeId::References, ReferenceTypeId::HasTypeDefinition),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasChild),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasSubtype),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::Organizes),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::Aggregates),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasProperty),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasComponent),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasOrderedComponent),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasEventSource),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasNotifier),
        (ReferenceTypeId::HasChild, ReferenceTypeId::Aggregates),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasComponent),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasHistoricalConfiguration),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasProperty),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasOrderedComponent),
        (ReferenceTypeId::HasChild, ReferenceTypeId::HasSubtype),
        (ReferenceTypeId::Aggregates, ReferenceTypeId::HasComponent),
        (ReferenceTypeId::Aggregates, ReferenceTypeId::HasHistoricalConfiguration),
        (ReferenceTypeId::Aggregates, ReferenceTypeId::HasProperty),
        (ReferenceTypeId::Aggregates, ReferenceTypeId::HasOrderedComponent),
        (ReferenceTypeId::HasComponent, ReferenceTypeId::HasOrderedComponent),
        (ReferenceTypeId::HasEventSource, ReferenceTypeId::HasNotifier),
        (ReferenceTypeId::HierarchicalReferences, ReferenceTypeId::HasNotifier),
        (ReferenceTypeId::References, ReferenceTypeId::NonHierarchicalReferences),
        (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::GeneratesEvent),
        (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::AlwaysGeneratesEvent),
        (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasEncoding),
        (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasModellingRule),
        (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasDescription),
        (ReferenceTypeId::NonHierarchicalReferences, ReferenceTypeId::HasTypeDefinition),
        (ReferenceTypeId::GeneratesEvent, ReferenceTypeId::AlwaysGeneratesEvent),
    ];

    // A type should always match itself
    assert!(references.reference_type_matches(&ReferenceTypeId::NonHierarchicalReferences.into(), &ReferenceTypeId::NonHierarchicalReferences.into(), true));
    assert!(references.reference_type_matches(&ReferenceTypeId::NonHierarchicalReferences.into(), &ReferenceTypeId::NonHierarchicalReferences.into(), false));

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
    let values = (0..100).map(|i| Variant::Int32(i)).collect::<Vec<Variant>>();

    // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
    let node_id = NodeId::new(2, 1);
    let v = Variable::new(&node_id, "x", "x", values);

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

    let values = (0..100).map(|i| Variant::Int32(i)).collect::<Vec<Variant>>();
    let mda = MultiDimensionArray::new(values, vec![10i32, 10i32]);
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

    // Test that a node can be found
    let result = find_node_from_browse_path(&address_space, &vec!["Objects".into(), "Sample".into(), "v1".into()]);
    let node = result.unwrap();
    assert_eq!(node.as_node().browse_name(), QualifiedName::from("v1"));

    // Test that a non existent node cannot be found
    let result = find_node_from_browse_path(&address_space, &vec!["Objects".into(), "Sample".into(), "vxxx".into()]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), StatusCode::BadNotFound);
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
    let _o = match address_space.find(node_id.clone()).unwrap() {
        NodeType::Object(o) => o,
        _ => panic!()
    };

    // Verify the reference to the objects folder is there
    assert!(address_space.has_reference(&ObjectId::ObjectsFolder.into(), &node_id, ReferenceTypeId::Organizes));
    assert!(address_space.has_reference(&node_id, &node_type_id, ReferenceTypeId::HasTypeDefinition));
}

#[test]
fn object_type_builder() {
    let mut address_space = AddressSpace::new();

    let node_type_id = NodeId::new(1, "HelloType");
    let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
        .subtype_of(ObjectTypeId::BaseObjectType)
        .insert(&mut address_space);

    let _ot = match address_space.find(node_type_id.clone()).unwrap() {
        NodeType::ObjectType(ot) => ot,
        _ => panic!()
    };

    assert!(address_space.has_reference(&ObjectTypeId::BaseObjectType.into(), &node_type_id, ReferenceTypeId::HasSubtype));
}

#[test]
fn variable_builder() {
    let result = std::panic::catch_unwind(|| {
        // This should panic
        let _v = VariableBuilder::new(&NodeId::null(), "", "")
            .build();
    });
    assert!(result.is_err());

    // This should build
    let _v = VariableBuilder::new(&NodeId::new(1, 1), "", "")
        .build();

    // Check a variable with a bunch of fields set
    let v = VariableBuilder::new(&NodeId::new(1, "Hello"), "BrowseName", "DisplayName")
        .description("Desc")
        .value_rank(10)
        .array_dimensions(&[1, 2, 3])
        .historizing(true)
        .value(Variant::from(999))
        .minimum_sampling_interval(123.0)
        .build();

    assert_eq!(v.node_id(), NodeId::new(1, "Hello"));
    assert_eq!(v.browse_name(), QualifiedName::new(0, "BrowseName"));
    assert_eq!(v.display_name(), LocalizedText::new("", "DisplayName"));
    assert_eq!(v.description().unwrap(), LocalizedText::new("", "Desc"));
    assert_eq!(v.value_rank(), 10);
    assert_eq!(v.array_dimensions().unwrap(), vec![1, 2, 3]);
    assert_eq!(v.historizing(), true);
    assert_eq!(v.value().value.unwrap(), Variant::from(999));
    assert_eq!(v.minimum_sampling_interval().unwrap(), 123.0);


    // Add a variable to the address space

    let mut address_space = AddressSpace::new();
    let node_id = NodeId::new(1, "Hello");
    let _v = VariableBuilder::new(&node_id, "BrowseName", "DisplayName")
        .description("Desc")
        .value_rank(10)
        .array_dimensions(&[1, 2, 3])
        .historizing(true)
        .value(Variant::from(999))
        .minimum_sampling_interval(123.0)
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut address_space);

    // Verify the variable is there
    assert!(address_space.find_variable_by_ref(&node_id).is_some());
    // Verify the reference to the objects folder is there
    assert!(address_space.has_reference(&ObjectId::ObjectsFolder.into(), &node_id, ReferenceTypeId::Organizes));
}
