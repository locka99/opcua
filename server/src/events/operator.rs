//! Operator implementations for event filters
use std::collections::HashSet;
use std::convert::TryFrom;

use opcua_types::{
    ExtensionObject, Variant,
    status_code::StatusCode,
    operand::Operand,
    service_types::{ContentFilterElement, FilterOperator},
};

use crate::address_space::AddressSpace;

/// Evaluates the expression
pub fn evaluate(element: &ContentFilterElement, used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let operands = element.filter_operands.as_ref().unwrap();
    if element.filter_operands.is_none() {
        // All operators need at least one operand
        Err(StatusCode::BadFilterOperandCountMismatch)
    } else {
        let result = match element.filter_operator {
            FilterOperator::Equals => eq(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::IsNull => is_null(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::GreaterThan => gt(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::LessThan => lt(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::GreaterThanOrEqual => gte(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::LessThanOrEqual => lte(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::Like => like(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::Not => not(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::Between => between(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::InList => like(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::And => and(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::Or => or(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::Cast => cast(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::BitwiseAnd => bitwise_and(&operands[..], used_elements, elements, address_space)?,
            FilterOperator::BitwiseOr => bitwise_or(&operands[..], used_elements, elements, address_space)?,
        };
        Ok(result)
    }
}

// This function fetches the value of the operand.
fn value_of(operand: &Operand, used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    match operand {
        Operand::ElementOperand(ref o) => {
            if used_elements.contains(&o.index) {
                error!("Operator contains elements that have already been used cyclical and is invalid");
                Err(StatusCode::BadFilterOperandInvalid)
            } else {
                used_elements.insert(o.index);
                let result = evaluate(&elements[o.index as usize], used_elements, elements, address_space);
                used_elements.remove(&o.index);
                result
            }
        }
        Operand::LiteralOperand(ref o) => {
            Ok(o.value.clone())
        }
        Operand::SimpleAttributeOperand(ref o) => {
            // Get the Object / Variable by browse path
            // TODO address_space.find_node(o.)
            Ok(Variant::Empty)
        }
        Operand::AttributeOperand(_) => {
            panic!();
        }
    }
}

fn eq(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;

    // Table 118 conversion rules here.
    // Implicitly convertable types are converted before comparison

    // TODO implicit conversion
    Ok((v1 == v2).into())
}

#[test]
fn test_eq() {
    // Simple test, compare two values of the same kind
    let operands = [
        Operand::from(10), Operand::from(10)
    ].iter().map(|v| v.into() ).collect::<Vec<ExtensionObject>>();
    let mut used_elements = HashSet::new();
    let mut elements = Vec::new();
    let address_space = AddressSpace::new();
    let result = eq(&operands[..], &mut used_elements, &elements, &address_space).unwrap();
    assert_eq!(result, Variant::Boolean(true));
}

fn is_null(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;

    // TODO
    Ok(false.into())
}

fn gt(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;

    // Same conversion rules as Equals

    // TODO
    Ok(false.into())
}

fn lt(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // Same conversion rules as GreaterThan
    // TODO
    Ok(false.into())
}

fn gte(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // Same conversion rules as GreaterThan
    // TODO
    Ok(false.into())
}

fn lte(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // Same conversion rules as GreaterThan
    // TODO
    Ok(false.into())
}

fn like(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;

    // If 0 matches a pattern in 1. See table 117
    //
    // 0 and 1 are operands that resolve to a string
    //
    // Returns FALSE if no operand can be resolved to a string
    //
    // % Match zero or more chars
    // _ Match any single character
    // \ Escape character
    // [] Match any single character in a list
    // [^] Not matching any single character in a list

    // TODO
    Ok(false.into())
}

fn not(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;

    // TODO
    //
    // 0 resolves to a boolean
    //
    // TRUE if 0 is FALSE
    // If resolve fails, result is NULL

    Ok(false.into())
}

fn between(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    let v3 = value_of(&Operand::try_from(&operands[2])?, used_elements, elements, address_space)?;
    // TODO
    // 0, 1, 2 are ordered values
    Ok(false.into())
}

fn in_list(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // TODO
    // Performs equality against 0 vs items in list
    Ok(false.into())
}

fn and(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // TODO
    // 0, 1 resolve to a boolean
    Ok(false.into())
}

fn or(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // TODO
    // 0, 1 resolve to a boolean
    Ok(false.into())
}

fn cast(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;

    // Explicitly casts operand 0 to a value with the data type with a node if identified in node 1
    // [0] Any operand
    // [1] Any operand that resolves to a NodeId or ExpandedNodeId where the node is of type DataType
    //
    // In case of error evaluates to NULL.

    // TODO
    Ok(false.into())
}

fn bitwise_and(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // TODO
    // 0, 1 resolve to an integer
    Ok(false.into())
}

fn bitwise_or(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    // TODO
    // 0, 1 resolve to an integer
    Ok(false.into())
}
