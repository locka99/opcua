// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Operator implementations for event filters
use std::collections::HashSet;
use std::convert::TryFrom;

use regex::Regex;

use crate::types::{
    operand::Operand,
    service_types::{ContentFilterElement, FilterOperator, SimpleAttributeOperand},
    status_code::StatusCode,
    AttributeId, ExtensionObject, NodeId, NumericRange, QualifiedName, TimestampsToReturn, Variant,
    VariantTypeId,
};

use crate::server::address_space::{
    node::{NodeBase, NodeType},
    relative_path::find_node_from_browse_path,
    AddressSpace,
};

/// Turns a list of operands inside extension objects to their analogous Operand objects
fn make_filter_operands(filter_operands: &[ExtensionObject]) -> Result<Vec<Operand>, StatusCode> {
    // If any operand cannot be converted then the whole action is in error
    let operands = filter_operands
        .iter()
        .map(Operand::try_from)
        .take_while(|v| v.is_ok())
        .map(|v| v.unwrap())
        .collect::<Vec<Operand>>();

    // Every operand must have been converted
    if operands.len() == filter_operands.len() {
        Ok(operands)
    } else {
        error!("One or more operands could not be parsed");
        Err(StatusCode::BadFilterOperandInvalid)
    }
}

/// Evaluates the expression
pub(crate) fn evaluate(
    object_id: &NodeId,
    element: &ContentFilterElement,
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    if let Some(ref filter_operands) = element.filter_operands {
        if !filter_operands.is_empty() {
            // Turn ExtensionObjects into Operands here. This should be externalised even further so it
            // doesn't have to be done on each evaluation, e.g. turn ContentFilterElement into a ServerContentFilterElement
            // which has the operands .
            let operands = make_filter_operands(filter_operands)?;
            match element.filter_operator {
                FilterOperator::Equals => eq(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::IsNull => is_null(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::GreaterThan => gt(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::LessThan => lt(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::GreaterThanOrEqual => gte(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::LessThanOrEqual => lte(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::Like => like(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::Not => not(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::Between => between(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::InList => in_list(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::And => and(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::Or => or(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::Cast => cast(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::BitwiseAnd => bitwise_and(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                FilterOperator::BitwiseOr => bitwise_or(
                    object_id,
                    &operands[..],
                    used_elements,
                    elements,
                    address_space,
                ),
                _ => Err(StatusCode::BadFilterOperatorUnsupported),
            }
        } else {
            // All operators need at least one operand
            warn!("evaluate() called with no operands (zero len)");
            Err(StatusCode::BadFilterOperandCountMismatch)
        }
    } else {
        // All operators need at least one operand
        warn!("evaluate() called with no operands (None)");
        Err(StatusCode::BadFilterOperandCountMismatch)
    }
}

/// Get the value of something and convert to the expected type.
fn value_as(
    object_id: &NodeId,
    as_type: VariantTypeId,
    operand: &Operand,
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let v = value_of(object_id, operand, used_elements, elements, address_space)?;
    Ok(v.convert(as_type))
}

pub(crate) fn value_of_simple_attribute(
    object_id: &NodeId,
    o: &SimpleAttributeOperand,
    address_space: &AddressSpace,
) -> Variant {
    // Get the Object / Variable by browse path
    if let Some(ref browse_path) = o.browse_path {
        // TODO o.data_type is ignored but be used to restrict the browse
        // path to subtypes of HierarchicalReferences

        // Find the actual node via browse path
        if let Ok(node) = find_node_from_browse_path(address_space, object_id, browse_path) {
            match node {
                NodeType::Object(ref node) => {
                    if o.attribute_id == AttributeId::NodeId as u32 {
                        node.node_id().into()
                    } else {
                        error!(
                            "value_of, unsupported attribute id {} on object",
                            o.attribute_id
                        );
                        Variant::Empty
                    }
                }
                NodeType::Variable(ref node) => {
                    if o.attribute_id == AttributeId::Value as u32 {
                        if let Some(ref value) = node
                            .value(
                                TimestampsToReturn::Neither,
                                NumericRange::None,
                                &QualifiedName::null(),
                                0.0,
                            )
                            .value
                        {
                            value.clone()
                        } else {
                            Variant::Empty
                        }
                    } else {
                        error!(
                            "value_of, unsupported attribute id {} on Variable",
                            o.attribute_id
                        );
                        Variant::Empty
                    }
                }
                _ => Variant::Empty,
            }
        } else {
            error!(
                "value_of, cannot find node from browse path {:?}",
                browse_path
            );
            Variant::Empty
        }
    } else {
        error!("value_of, invalid browse path supplied to operand");
        Variant::Empty
    }
}

// This function fetches the value of the operand.
pub(crate) fn value_of(
    object_id: &NodeId,
    operand: &Operand,
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    match operand {
        Operand::ElementOperand(ref o) => {
            if used_elements.contains(&o.index) {
                error!("Operator contains elements that have already been used cyclical and is invalid");
                Err(StatusCode::BadFilterOperandInvalid)
            } else {
                used_elements.insert(o.index);
                let result = evaluate(
                    object_id,
                    &elements[o.index as usize],
                    used_elements,
                    elements,
                    address_space,
                );
                used_elements.remove(&o.index);
                result
            }
        }
        Operand::LiteralOperand(ref o) => Ok(o.value.clone()),
        Operand::SimpleAttributeOperand(ref o) => {
            Ok(value_of_simple_attribute(object_id, o, address_space))
        }
        Operand::AttributeOperand(_) => {
            panic!();
        }
    }
}

fn convert(v1: Variant, v2: Variant) -> (Variant, Variant) {
    // Types may have to be converted to be compared
    let dt1 = v1.type_id();
    let dt2 = v2.type_id();
    if dt1 != dt2 {
        if dt1.precedence() < dt2.precedence() {
            (v1, v2.convert(dt1))
        } else {
            (v1.convert(dt2), v2)
        }
    } else {
        (v1, v2)
    }
}

// Tests if the operand is null (empty). TRUE if operand[0] is a null value.
pub(crate) fn is_null(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let v1 = value_of(
        object_id,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    Ok((Variant::Empty == v1).into())
}

#[derive(PartialEq)]
enum ComparisonResult {
    // Value 1 is less than value 2
    LessThan,
    // Value 1 is equal to value 2
    Equals,
    // Value 1 is greater than value 2
    GreaterThan,
    // Not equals, for boolean comparisons
    NotEquals,
    // Error
    Error,
}

macro_rules! compare_values {
    ( $v1: expr, $v2: expr, $variant_type: ident ) => {{
        if let Variant::$variant_type(v1) = $v1 {
            if let Variant::$variant_type(v2) = $v2 {
                if v1 < v2 {
                    ComparisonResult::LessThan
                } else if v1 == v2 {
                    ComparisonResult::Equals
                } else {
                    ComparisonResult::GreaterThan
                }
            } else {
                panic!();
            }
        } else {
            panic!();
        }
    }};
}

/// Compares to operands by taking their numeric value, comparing the value and saying
/// which of the two is less than, greater than or equal. If the values cannot be compared, the
/// result is an error.
fn compare_operands(
    object_id: &NodeId,
    o1: &Operand,
    o2: &Operand,
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<ComparisonResult, StatusCode> {
    let v1 = value_of(object_id, o1, used_elements, elements, address_space)?;
    let v2 = value_of(object_id, o2, used_elements, elements, address_space)?;
    // Try and convert one value or the other to the same type
    let (v1, v2) = convert(v1, v2);
    let result = match v1.type_id() {
        VariantTypeId::SByte => compare_values!(v1, v2, SByte),
        VariantTypeId::Byte => compare_values!(v1, v2, Byte),
        VariantTypeId::Int16 => compare_values!(v1, v2, Int16),
        VariantTypeId::Int32 => compare_values!(v1, v2, Int32),
        VariantTypeId::Int64 => compare_values!(v1, v2, Int64),
        VariantTypeId::UInt16 => compare_values!(v1, v2, UInt16),
        VariantTypeId::UInt32 => compare_values!(v1, v2, UInt32),
        VariantTypeId::UInt64 => compare_values!(v1, v2, UInt64),
        VariantTypeId::Double => compare_values!(v1, v2, Double),
        VariantTypeId::Float => compare_values!(v1, v2, Float),
        VariantTypeId::Boolean => {
            if v1 == v2 {
                ComparisonResult::Equals
            } else {
                ComparisonResult::NotEquals
            }
        }
        _ => ComparisonResult::Error,
    };
    Ok(result)
}

// Check if the two values are equal to each other. If the operands are of different types,
// the system shall perform any implicit conversion to a common type. This operator resolves to
// FALSE if no implicit conversion is available and the operands are of different types. This
// operator returns FALSE if the implicit conversion fails.
pub(crate) fn eq(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let result = compare_operands(
        object_id,
        &operands[0],
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;
    Ok((result == ComparisonResult::Equals).into())
}

// Check if operand[0] is greater than operand[1]
pub(crate) fn gt(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let result = compare_operands(
        object_id,
        &operands[0],
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;
    Ok((result == ComparisonResult::GreaterThan).into())
}

// Check if operand[0] is less than operand[1]
pub(crate) fn lt(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let result = compare_operands(
        object_id,
        &operands[0],
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;
    Ok((result == ComparisonResult::LessThan).into())
}

// Check if operand[0] is greater than or equal to operand[1]
pub(crate) fn gte(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let result = compare_operands(
        object_id,
        &operands[0],
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;
    Ok((result == ComparisonResult::GreaterThan || result == ComparisonResult::Equals).into())
}

// Check if operand[0] is less than or equal to operand[1]
pub(crate) fn lte(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let result = compare_operands(
        object_id,
        &operands[0],
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;
    Ok((result == ComparisonResult::LessThan || result == ComparisonResult::Equals).into())
}

/// Converts the OPC UA SQL-esque Like format into a regular expression.
fn like_to_regex(v: &str) -> Result<Regex, ()> {
    // Give a reasonable buffer
    let mut pattern = String::with_capacity(v.len() * 2);

    let mut in_list = false;

    // Turn the chars into a vec to make it easier to index them
    let v = v.chars().collect::<Vec<char>>();

    pattern.push('^');
    v.iter().enumerate().for_each(|(i, c)| {
        if in_list {
            if *c == ']' && (i == 0 || v[i - 1] != '\\') {
                // Close the list
                in_list = false;
                pattern.push(*c);
            } else {
                // Chars in list are escaped if required
                match c {
                    '$' | '(' | ')' | '.' | '+' | '*' | '?' => {
                        // Other regex chars except for ^ are escaped
                        pattern.push('\\');
                        pattern.push(*c);
                    }
                    _ => {
                        // Everything between two [] will be treated as-is
                        pattern.push(*c);
                    }
                }
            }
        } else {
            match c {
                '$' | '^' | '(' | ')' | '.' | '+' | '*' | '?' => {
                    // Other regex chars are escaped
                    pattern.push('\\');
                    pattern.push(*c);
                }
                '[' => {
                    // Opens a list of chars to match
                    if i == 0 || v[i - 1] != '\\' {
                        // Open the list
                        in_list = true;
                    }
                    pattern.push(*c);
                }
                '%' => {
                    if i == 0 || v[i - 1] != '\\' {
                        // A % is a match on zero or more chans unless it is escaped
                        pattern.push_str(".*");
                    } else {
                        pattern.push(*c);
                    }
                }
                '_' => {
                    if i == 0 || v[i - 1] != '\\' {
                        // A _ is a match on a single char unless it is escaped
                        pattern.push('?');
                    } else {
                        // Remove escaping of the underscore
                        let _ = pattern.pop();
                        pattern.push(*c);
                    }
                }
                _ => {
                    pattern.push(*c);
                }
            }
        }
    });
    pattern.push('$');
    Regex::new(&pattern).map_err(|err| {
        error!("Problem parsing, error = {}", err);
    })
}

#[cfg(test)]
fn compare_regex(r1: Regex, r2: Regex) {
    assert_eq!(r1.as_str(), r2.as_str());
}

#[test]
fn like_to_regex_tests() {
    compare_regex(like_to_regex("").unwrap(), Regex::new("^$").unwrap());
    compare_regex(like_to_regex("^$").unwrap(), Regex::new(r"^\^\$$").unwrap());
    compare_regex(like_to_regex("%").unwrap(), Regex::new("^.*$").unwrap());
    compare_regex(like_to_regex("[%]").unwrap(), Regex::new("^[%]$").unwrap());
    compare_regex(like_to_regex("[_]").unwrap(), Regex::new("^[_]$").unwrap());
    compare_regex(
        like_to_regex(r"[\]]").unwrap(),
        Regex::new(r"^[\]]$").unwrap(),
    );
    compare_regex(
        like_to_regex("[$().+*?]").unwrap(),
        Regex::new(r"^[\$\(\)\.\+\*\?]$").unwrap(),
    );
    compare_regex(like_to_regex("_").unwrap(), Regex::new("^?$").unwrap());
    compare_regex(
        like_to_regex("[a-z]").unwrap(),
        Regex::new("^[a-z]$").unwrap(),
    );
    compare_regex(
        like_to_regex("[abc]").unwrap(),
        Regex::new("^[abc]$").unwrap(),
    );
    compare_regex(
        like_to_regex(r"\[\]").unwrap(),
        Regex::new(r"^\[\]$").unwrap(),
    );
    compare_regex(
        like_to_regex("[^0-9]").unwrap(),
        Regex::new("^[^0-9]$").unwrap(),
    );

    // Some samples from OPC UA part 4
    let re = like_to_regex("Th[ia][ts]%").unwrap();
    assert!(re.is_match("That is fine"));
    assert!(re.is_match("This is fine"));
    assert!(re.is_match("That as one"));
    assert!(!re.is_match("Then at any")); // Spec says this should pass when it obviously wouldn't

    let re = like_to_regex("%en%").unwrap();
    assert!(re.is_match("entail"));
    assert!(re.is_match("green"));
    assert!(re.is_match("content"));

    let re = like_to_regex("abc[13-68]").unwrap();
    assert!(re.is_match("abc1"));
    assert!(!re.is_match("abc2"));
    assert!(re.is_match("abc3"));
    assert!(re.is_match("abc4"));
    assert!(re.is_match("abc5"));
    assert!(re.is_match("abc6"));
    assert!(!re.is_match("abc7"));
    assert!(re.is_match("abc8"));

    let re = like_to_regex("ABC[^13-5]").unwrap();
    assert!(!re.is_match("ABC1"));
    assert!(re.is_match("ABC2"));
    assert!(!re.is_match("ABC3"));
    assert!(!re.is_match("ABC4"));
    assert!(!re.is_match("ABC5"));
}

// Check if operand[0] is matches the pattern defined by operand[1].
pub(crate) fn like(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
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

    let v1 = value_as(
        object_id,
        VariantTypeId::String,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    let v2 = value_as(
        object_id,
        VariantTypeId::String,
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;

    let result = if let Variant::String(v1) = v1 {
        if let Variant::String(v2) = v2 {
            // Turn the pattern into a regex. Certain chars will be replaced with their regex equivalents, others will be escaped.
            if let Ok(re) = like_to_regex(v2.as_ref()) {
                re.is_match(v1.as_ref())
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };
    Ok(result.into())
}

// TRUE if operand[0] is FALSE.
pub(crate) fn not(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    // operand[0] resolves to a boolean
    // TRUE if 0 is FALSE
    // If resolve fails, result is NULL
    let v = value_as(
        object_id,
        VariantTypeId::Boolean,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    let result = if let Variant::Boolean(v) = v {
        (!v).into()
    } else {
        Variant::Empty
    };
    Ok(result)
}

// TRUE if operand[0] is greater or equal to operand[1] and less than or equal to operand[2].
pub(crate) fn between(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    // 0, 1, 2 are ordered values
    // Element 0 must be greater or equal than element 1
    let result = match compare_operands(
        object_id,
        &operands[0],
        &operands[1],
        used_elements,
        elements,
        address_space,
    )? {
        ComparisonResult::GreaterThan | ComparisonResult::Equals => {
            // Element must be less than or equal to element 2
            match compare_operands(
                object_id,
                &operands[0],
                &operands[2],
                used_elements,
                elements,
                address_space,
            )? {
                ComparisonResult::LessThan | ComparisonResult::Equals => true,
                _ => false,
            }
        }
        _ => false,
    };
    Ok(result.into())
}

// TRUE if operand[0] is equal to one or more of the remaining operands
pub(crate) fn in_list(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    // TRUE if operand[0] is equal to one or more of the remaining operands.
    // The Equals Operator is evaluated for operand[0] and each remaining operand in the list.
    // If any Equals evaluation is TRUE, InList returns TRUE.
    let found = operands[1..].iter().any(|o| {
        if let Ok(result) = compare_operands(
            object_id,
            &operands[0],
            o,
            used_elements,
            elements,
            address_space,
        ) {
            result == ComparisonResult::Equals
        } else {
            false
        }
    });
    Ok(found.into())
}

// TRUE if operand[0] and operand[1] are TRUE.
pub(crate) fn and(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    // The following restrictions apply to the operands:
    //  [0]: Any operand that resolves to a Boolean.
    //  [1]: Any operand that resolves to a Boolean.
    // If any operand cannot be resolved to a Boolean it is considered a NULL.
    let v1 = value_as(
        object_id,
        VariantTypeId::Boolean,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    let v2 = value_as(
        object_id,
        VariantTypeId::Boolean,
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;

    // Derived from Table 120 Logical AND Truth Table
    let result = if v1 == Variant::Boolean(true) && v2 == Variant::Boolean(true) {
        true.into()
    } else if v1 == Variant::Boolean(false) || v2 == Variant::Boolean(false) {
        false.into()
    } else {
        Variant::Empty
    };
    Ok(result)
}

// TRUE if operand[0] or operand[1] are TRUE.
pub(crate) fn or(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    // The following restrictions apply to the operands:
    //  [0]: Any operand that resolves to a Boolean.
    //  [1]: Any operand that resolves to a Boolean.
    // If any operand cannot be resolved to a Boolean it is considered a NULL.
    let v1 = value_as(
        object_id,
        VariantTypeId::Boolean,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    let v2 = value_as(
        object_id,
        VariantTypeId::Boolean,
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;

    // Derived from Table 121 Logical OR Truth Table.
    let result = if v1 == Variant::Boolean(true) || v2 == Variant::Boolean(true) {
        true.into()
    } else if v1 == Variant::Boolean(false) && v2 == Variant::Boolean(false) {
        false.into()
    } else {
        // One or both values are NULL
        Variant::Empty
    };
    Ok(result)
}

// Converts operand[0] to a value with a data type with a NodeId identified by operand[1].
pub(crate) fn cast(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    // Explicitly casts operand 0 to a value with the data type with a node if identified in node 1
    // [0] Any operand
    // [1] Any operand that resolves to a NodeId or ExpandedNodeId where the node is of type DataType
    //
    // In case of error evaluates to NULL.

    let v1 = value_of(
        object_id,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    let v2 = value_of(
        object_id,
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;

    // Cast v1 using the datatype in v2
    let result = match v2 {
        Variant::NodeId(node_id) => {
            if let Ok(type_id) = VariantTypeId::try_from(&(*node_id)) {
                v1.cast(type_id)
            } else {
                Variant::Empty
            }
        }
        Variant::ExpandedNodeId(node_id) => {
            if let Ok(type_id) = VariantTypeId::try_from(&node_id.node_id) {
                v1.cast(type_id)
            } else {
                Variant::Empty
            }
        }
        _ => Variant::Empty,
    };
    Ok(result)
}

#[derive(PartialEq)]
enum BitOperation {
    And,
    Or,
}

macro_rules! bitwise_operation {
    ( $v1: expr, $v2: expr, $op: expr, $variant_type: ident ) => {{
        if let Variant::$variant_type(v1) = $v1 {
            if let Variant::$variant_type(v2) = $v2 {
                match $op {
                    BitOperation::And => (v1 & v2).into(),
                    BitOperation::Or => (v1 | v2).into(),
                }
            } else {
                panic!();
            }
        } else {
            panic!();
        }
    }};
}

fn bitwise_operation(
    object_id: &NodeId,
    operation: BitOperation,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    let v1 = value_of(
        object_id,
        &operands[0],
        used_elements,
        elements,
        address_space,
    )?;
    let v2 = value_of(
        object_id,
        &operands[1],
        used_elements,
        elements,
        address_space,
    )?;
    // Try and convert one value or the other to the same type
    let (v1, v2) = convert(v1, v2);
    let result = match v1.type_id() {
        VariantTypeId::SByte => bitwise_operation!(v1, v2, operation, SByte),
        VariantTypeId::Byte => bitwise_operation!(v1, v2, operation, Byte),
        VariantTypeId::Int16 => bitwise_operation!(v1, v2, operation, Int16),
        VariantTypeId::Int32 => bitwise_operation!(v1, v2, operation, Int32),
        VariantTypeId::Int64 => bitwise_operation!(v1, v2, operation, Int64),
        VariantTypeId::UInt16 => bitwise_operation!(v1, v2, operation, UInt16),
        VariantTypeId::UInt32 => bitwise_operation!(v1, v2, operation, UInt32),
        VariantTypeId::UInt64 => bitwise_operation!(v1, v2, operation, UInt64),
        _ => Variant::Empty,
    };
    Ok(result)
}

// The result is an integer which matches the size of the largest operand and contains a bitwise
// And operation of the two operands where both have been converted to the same size (largest of
// the two operands).
pub(crate) fn bitwise_and(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    bitwise_operation(
        object_id,
        BitOperation::And,
        operands,
        used_elements,
        elements,
        address_space,
    )
}

// The result is an integer which matches the size of the largest operand and contains a bitwise Or
// operation of the two operands where both have been converted to the same size (largest of the
// two operands).
pub(crate) fn bitwise_or(
    object_id: &NodeId,
    operands: &[Operand],
    used_elements: &mut HashSet<u32>,
    elements: &[ContentFilterElement],
    address_space: &AddressSpace,
) -> Result<Variant, StatusCode> {
    bitwise_operation(
        object_id,
        BitOperation::Or,
        operands,
        used_elements,
        elements,
        address_space,
    )
}
