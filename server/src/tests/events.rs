use std::collections::HashSet;

use opcua_types::{
    Variant, NodeId, AttributeId, UAString, ObjectId, ObjectTypeId, VariableTypeId,
    operand::{Operand, ContentFilterBuilder},
    node_ids::ReferenceTypeId,
    service_types::ContentFilterElement,
};

use crate::{
    tests::*,
    address_space::{
        AddressSpace,
        object_type::ObjectTypeBuilder,
        variable::{Variable, VariableBuilder},
    },
    events::operator,
    events::event_filter,
};

const VAR_I32_1: i32 = 30;
const VAR_F64_1: f64 = 100.99;
const VAR_S_1: &str = "Hello World";
const VAR_B_1: bool = true;

fn event_type_id() -> NodeId {
    NodeId::new(2, "TestEventType")
}

fn address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();

    // Add a few variables
    let sample_folder_id = address_space.add_folder("Vars", "Vars", &NodeId::objects_folder_id()).unwrap();
    let vars = vec![
        Variable::new(&NodeId::new(1, "i32-1"), "i32-1", "", VAR_I32_1),
        Variable::new(&NodeId::new(1, "f64-1"), "f64-1", "", VAR_F64_1),
        Variable::new(&NodeId::new(1, "s-1"), "s-1", "", UAString::from(VAR_S_1)),
        Variable::new(&NodeId::new(1, "b-1"), "b-1", "", VAR_B_1),
    ];
    let _ = address_space.add_variables(vars, &sample_folder_id);

    // Create an event type
    let event_type_id = event_type_id();
    ObjectTypeBuilder::new(&event_type_id, "TestEventType", "TestEventType")
        .is_abstract(false)
        .subtype_of(ObjectTypeId::BaseEventType)
        .insert(&mut address_space);

    // Add attribute to event type
    let attr_foo_id = NodeId::new(2, "Foo");
    VariableBuilder::new(&attr_foo_id, "Foo", "Foo")
        .property_of(event_type_id.clone())
        .has_type_definition(VariableTypeId::PropertyType)
        .has_modelling_rule(ObjectId::ModellingRule_Mandatory)
        .insert(&mut address_space);

    // TODO Create some events of that type

    address_space
}

fn do_operator_test<T>(f: T)
    where T: FnOnce(&AddressSpace, &NodeId, &mut HashSet<u32>, &Vec<ContentFilterElement>)
{
    opcua_console_logging::init();
    let mut used_elements = HashSet::new();
    let elements = vec![];
    let address_space = address_space();

    // TODO use object_id of a generated event
    let object_id = NodeId::null();

    f(&address_space, &object_id, &mut used_elements, &elements);
}

#[test]
fn test_eq() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::eq(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::eq(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(10), Operand::literal(11)];
        let result = operator::eq(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_lt() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::lt(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::lt(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(11), Operand::literal(10)];
        let result = operator::lt(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_lte() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::lte(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::lte(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(11), Operand::literal(10)];
        let result = operator::lte(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_gt() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = [Operand::literal(11), Operand::literal(10)];
        let result = operator::gt(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::gt(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::gt(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_gte() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Simple test, compare two values of the same kind
        let operands = &[Operand::literal(11), Operand::literal(10)];
        let result = operator::gte(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(10), Operand::literal(10)];
        let result = operator::gte(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(9), Operand::literal(10)];
        let result = operator::gte(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));
    });
}

#[test]
fn test_not() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(false)];
        let result = operator::not(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(true)];
        let result = operator::not(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        // String
        let operands = &[Operand::literal("0")];
        let result = operator::not(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        // String(2)
        let operands = &[Operand::literal("true")];
        let result = operator::not(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        // Invalid - Double
        let operands = &[Operand::literal(99.9)];
        let result = operator::not(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);

        // Invalid - Int32
        let operands = &[Operand::literal(1)];
        let result = operator::not(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);
    });
}

#[test]
fn test_between() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        // Test operator with some ranges and mix of types with implicit conversion
        let operands = &[Operand::literal(12), Operand::literal(12), Operand::literal(13)];
        let result = operator::between(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(13), Operand::literal(12), Operand::literal(13)];
        let result = operator::between(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(12.3), Operand::literal(12.0), Operand::literal(12.4)];
        let result = operator::between(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(11.99), Operand::literal(12.0), Operand::literal(13.0)];
        let result = operator::between(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(13.0001), Operand::literal(12.0), Operand::literal(13.0)];
        let result = operator::between(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
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
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(true)];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(false)];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(false), Operand::literal(false)];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(())];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);

        let operands = &[Operand::literal(()), Operand::literal(true)];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);

        let operands = &[Operand::literal(false), Operand::literal(())];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(()), Operand::literal(false)];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(()), Operand::literal(())];
        let result = operator::and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);
    })
}

#[test]
fn test_or() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(true), Operand::literal(true)];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(true), Operand::literal(false)];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(true)];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(false)];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(())];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(()), Operand::literal(true)];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(true));

        let operands = &[Operand::literal(false), Operand::literal(())];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);

        let operands = &[Operand::literal(()), Operand::literal(false)];
        let result = operator::or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Empty);
    })
}


#[test]
fn test_in_list() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(10), Operand::literal(false)];
        let result = operator::in_list(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::Boolean(false));

        let operands = &[Operand::literal(true), Operand::literal(false)];
        let result = operator::in_list(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
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
        let result = operator::bitwise_or(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::UInt16(0xffff));
    })
}

#[test]
fn test_bitwise_and() {
    do_operator_test(|address_space, object_id, used_elements, elements| {
        let operands = &[Operand::literal(0xf00fu16), Operand::literal(0x00ffu16)];
        let result = operator::bitwise_and(&object_id, &operands[..], used_elements, elements, address_space).unwrap();
        assert_eq!(result, Variant::UInt16(0x000f));
    })
}

#[test]
fn test_where_clause() {
    let address_space = address_space();

    let object_id = NodeId::root_folder_id();

    // IsNull(NULL)
    let f = ContentFilterBuilder::new()
        .is_null(Operand::literal(()))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // (550 == "550") && (10.5 == "10.5")
    let f = ContentFilterBuilder::new()
        .and(Operand::element(1), Operand::element(2))
        .equals(Operand::literal(550), Operand::literal("550"))
        .equals(Operand::literal(10.5), Operand::literal("10.5"))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // Like operator
    let f = ContentFilterBuilder::new()
        .like(Operand::literal("Hello world"), Operand::literal("[Hh]ello w%"))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // Not equals
    let f = ContentFilterBuilder::new()
        .not(Operand::element(1))
        .equals(Operand::literal(550), Operand::literal(551))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());

    // Compare to a i32 variable value
    let f = ContentFilterBuilder::new()
        .gt(Operand::simple_attribute(ReferenceTypeId::Organizes, "Objects/Vars/i32-1", AttributeId::Value, UAString::null()), Operand::literal(VAR_I32_1 - 1))
        .build();
    let result = event_filter::evaluate_where_clause(&object_id, &f, &address_space);
    assert_eq!(result.unwrap(), true.into());
}