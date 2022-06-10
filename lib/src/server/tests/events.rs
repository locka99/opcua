use std::collections::HashSet;

use crate::types::{
    node_ids::ReferenceTypeId,
    operand::{ContentFilterBuilder, Operand},
    service_types::ContentFilterElement,
    AttributeId, DataTypeId, LocalizedText, NodeId, ObjectId, ObjectTypeId, QualifiedName,
    UAString, VariableTypeId, Variant,
};

use crate::server::{
    address_space::{object_type::ObjectTypeBuilder, variable::VariableBuilder, AddressSpace},
    events::event::{BaseEventType, Event},
    events::event_filter,
    events::operator,
    tests::*,
};

fn event_id() -> NodeId {
    NodeId::new(2, 1000)
}

pub struct TestEventType {
    base: BaseEventType,
    foo: i32,
}

impl Event for TestEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        match self.base.raise(address_space) {
            Ok(node_id) => {
                let property_id = NodeId::next_numeric(2);
                self.add_property(
                    &node_id,
                    property_id,
                    "Foo",
                    "Foo",
                    DataTypeId::Int32,
                    self.foo,
                    address_space,
                );
                Ok(node_id)
            }
            err => err,
        }
    }
}

base_event_impl!(TestEventType, base);

impl TestEventType {
    fn new<R, S, T, U, V>(
        node_id: R,
        browse_name: S,
        display_name: T,
        parent_node: U,
        source_node: V,
        foo: i32,
    ) -> Self
    where
        R: Into<NodeId>,
        S: Into<QualifiedName>,
        T: Into<LocalizedText>,
        U: Into<NodeId>,
        V: Into<NodeId>,
    {
        let event_type_id = Self::event_type_id();
        let source_node: NodeId = source_node.into();
        Self {
            base: BaseEventType::new_now(
                node_id,
                event_type_id,
                browse_name,
                display_name,
                parent_node,
            )
            .source_node(source_node.clone())
            .message(LocalizedText::from(format!(
                "A Test event from {:?}",
                source_node
            ))),
            foo,
        }
    }

    fn event_type_id() -> NodeId {
        NodeId::new(2, "TestEventType")
    }
}

fn create_event(
    address_space: &mut AddressSpace,
    node_id: NodeId,
    source_machine_id: &NodeId,
    foo: i32,
) {
    let event_name = format!("Event{}", foo);
    let mut event = TestEventType::new(
        &node_id,
        event_name.clone(),
        event_name,
        NodeId::objects_folder_id(),
        source_machine_id,
        foo,
    );
    let _ = event.raise(address_space);
}

fn address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();

    let ns = address_space.register_namespace("urn:test").unwrap();

    // Create an event type
    let event_type_id = TestEventType::event_type_id();
    ObjectTypeBuilder::new(&event_type_id, "TestEventType", "TestEventType")
        .is_abstract(false)
        .subtype_of(ObjectTypeId::BaseEventType)
        .insert(&mut address_space);

    // Add attribute to event type
    let attr_foo_id = NodeId::new(ns, "Foo");
    VariableBuilder::new(&attr_foo_id, "Foo", "Foo")
        .property_of(event_type_id.clone())
        .data_type(DataTypeId::UInt32)
        .has_type_definition(VariableTypeId::PropertyType)
        .has_modelling_rule(ObjectId::ModellingRule_Mandatory)
        .insert(&mut address_space);

    // Create an event of that type
    create_event(
        &mut address_space,
        event_id(),
        &ObjectId::Server.into(),
        100,
    );

    address_space
}

fn do_operator_test<T>(f: T)
where
    T: FnOnce(&AddressSpace, &NodeId, &mut HashSet<u32>, &Vec<ContentFilterElement>),
{
    crate::console_logging::init();

    let mut used_elements = HashSet::new();
    let elements = vec![];
    let address_space = address_space();

    // use object_id of a generated event
    let object_id = event_id();

    f(&address_space, &object_id, &mut used_elements, &elements);
}

#[test]
fn test_eq() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::eq(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::eq(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(10), Operand::literal(11)];
        let result = operator::eq(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_lt() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::lt(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::lt(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(11), Operand::literal(10)];
        let result = operator::lt(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_lte() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::lte(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::lte(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(11), Operand::literal(10)];
        let result = operator::lte(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_gt() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = [Operand::literal(11), Operand::literal(10)];
        let result = operator::gt(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::gt(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::gt(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_gte() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(11), Operand::literal(10)];
        let result = operator::gte(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::gte(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::gte(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_not() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(false)];
        let result = operator::not(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(true)];
        let result = operator::not(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        // String
        let operands = &[Operand::literal("0")];
        let result = operator::not(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        // String(2)
        let operands = &[Operand::literal("true")];
        let result = operator::not(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        // Invalid - Double
        let operands = &[Operand::literal(99.9)];
        let result = operator::not(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);

        // Invalid - Int32
        let operands = &[Operand::literal(1)];
        let result = operator::not(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);
    });
}

#[test]
fn test_between() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Test operator with some ranges and mix of types with implicit conversion
        let operands = &[
            Operand::literal(12),
            Operand::literal(12),
            Operand::literal(13),
        ];
        let result = operator::between(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[
            Operand::literal(13),
            Operand::literal(12),
            Operand::literal(13),
        ];
        let result = operator::between(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[
            Operand::literal(12.3),
            Operand::literal(12.0),
            Operand::literal(12.4),
        ];
        let result = operator::between(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[
            Operand::literal(11.99),
            Operand::literal(12.0),
            Operand::literal(13.0),
        ];
        let result = operator::between(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[
            Operand::literal(13.0001),
            Operand::literal(12.0),
            Operand::literal(13.0),
        ];
        let result = operator::between(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        //        let operands = &[Operand::literal("12.5"), Operand::literal(12), Operand::literal(13)]);
        //        let result = operator::between(&operands[..], used_elements, elements, address_space).unwrap();
        //        assert_eq!(result, Variant::Boolean(true));
    })
}

#[test]
fn test_and() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(true), Operand::literal(true)];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(true)];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(false)];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(false), Operand::literal(false)];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(())];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);

        let operands = &[Operand::literal(()), Operand::literal(true)];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);

        let operands = &[Operand::literal(false), Operand::literal(())];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(()), Operand::literal(false)];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(()), Operand::literal(())];
        let result = operator::and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);
    })
}

#[test]
fn test_or() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(true), Operand::literal(true)];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(true), Operand::literal(false)];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(true)];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(false)];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(())];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(()), Operand::literal(true)];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(())];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);

        let operands = &[Operand::literal(()), Operand::literal(false)];
        let result = operator::or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Empty);
    })
}

#[test]
fn test_in_list() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(10), Operand::literal(false)];
        let result = operator::in_list(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(false)];
        let result = operator::in_list(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::Boolean(false));
        /*
        let operands = &[Operand::literal("true"), Operand::literal(true)];
        let result = operator::in_list(&operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(99), Operand::literal(11), Operand::literal(()), Operand::literal(99.0)];
        let result = operator::in_list(&operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(()), Operand::literal(11), Operand::literal(()), Operand::literal(99.0)];
        let result = operator::in_list(&operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(33), Operand::literal(11), Operand::literal(()), Operand::literal(99.0)];
        let result = operator::in_list(&operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));
        */
    })
}

#[test]
fn test_bitwise_or() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(0xff00u16), Operand::literal(0x00ffu16)];
        let result = operator::bitwise_or(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::UInt16(0xffff));
    })
}

#[test]
fn test_bitwise_and() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(0xf00fu16), Operand::literal(0x00ffu16)];
        let result = operator::bitwise_and(
            &object_id,
            &operands[..],
            used_elements,
            elements,
            address_space,
        )
        .unwrap();
        assert_eq!(result, Variant::UInt16(0x000f));
    })
}

#[test]
fn test_where_clause() {
    crate::console_logging::init();

    let address_space = address_space();

    let object_id = NodeId::root_folder_id();

    // IsNull(NULL)
    let f = ContentFilterBuilder::new()
        .null(Operand::literal(()))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // (550 == "550") && (10.5 == "10.5")
    let f = ContentFilterBuilder::new()
        .and(Operand::element(1), Operand::element(2))
        .eq(Operand::literal(550), Operand::literal("550"))
        .eq(Operand::literal(10.5), Operand::literal("10.5"))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // Like operator
    let f = ContentFilterBuilder::new()
        .like(
            Operand::literal("Hello world"),
            Operand::literal("[Hh]ello w%"),
        )
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // Not equals
    let f = ContentFilterBuilder::new()
        .not(Operand::element(1))
        .eq(Operand::literal(550), Operand::literal(551))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // Do some relative path comparisons against the event to ensure content filters appear to work
    let expected = vec![
        // Valid
        (NodeId::root_folder_id(), "Objects/Event100/Foo", 100, true),
        (NodeId::objects_folder_id(), "Event100/Foo", 100, true),
        (event_id(), "Foo", 100, true),
        // Invalid
        (NodeId::root_folder_id(), "Objects/Event101/Foo", 100, false),
        (NodeId::root_folder_id(), "Objects/Foo", 100, false),
        (NodeId::root_folder_id(), "Objects/Event100/Foo", 101, false),
        (NodeId::objects_folder_id(), "Event100/Foo", 101, false),
        (event_id(), "Foo", 101, false),
        (NodeId::objects_folder_id(), "Event100/Foo/Bar", 100, false),
        (event_id(), "", 100, false),
    ];
    expected
        .into_iter()
        .for_each(|(node_id, browse_path, value_to_compare, expected)| {
            let f = ContentFilterBuilder::new()
                .eq(
                    Operand::simple_attribute(
                        ReferenceTypeId::Organizes,
                        browse_path,
                        AttributeId::Value,
                        UAString::null(),
                    ),
                    Operand::literal(value_to_compare),
                )
                .build();
            let result = event_filter::evaluate_where_clause(&node_id, &f, &address_space);
            assert_eq!(result.unwrap(), expected.into());
        });
}
