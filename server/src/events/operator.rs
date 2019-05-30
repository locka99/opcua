//! Operator implementations for event filters
use std::collections::HashSet;
use std::convert::TryFrom;

use opcua_types::{
    AttributeId, ExtensionObject, Variant, VariantTypeId,
    status_code::StatusCode,
    node_id::Identifier,
    node_ids::DataTypeId,
    operand::Operand,
    service_types::{ContentFilterElement, FilterOperator},
};

use crate::address_space::{
    AddressSpace,
    node::{Node, NodeType},
    relative_path::find_node_from_browse_path,
};

/// Evaluates the expression
pub fn evaluate(element: &ContentFilterElement, used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let operands = element.filter_operands.as_ref().unwrap();
    if element.filter_operands.is_none() {
        // All operators need at least one operand
        Err(StatusCode::BadFilterOperandCountMismatch)
    } else {
        match element.filter_operator {
            FilterOperator::Equals => eq(&operands[..], used_elements, elements, address_space),
            FilterOperator::IsNull => is_null(&operands[..], used_elements, elements, address_space),
            FilterOperator::GreaterThan => gt(&operands[..], used_elements, elements, address_space),
            FilterOperator::LessThan => lt(&operands[..], used_elements, elements, address_space),
            FilterOperator::GreaterThanOrEqual => gte(&operands[..], used_elements, elements, address_space),
            FilterOperator::LessThanOrEqual => lte(&operands[..], used_elements, elements, address_space),
            FilterOperator::Like => like(&operands[..], used_elements, elements, address_space),
            FilterOperator::Not => not(&operands[..], used_elements, elements, address_space),
            FilterOperator::Between => between(&operands[..], used_elements, elements, address_space),
            FilterOperator::InList => in_list(&operands[..], used_elements, elements, address_space),
            FilterOperator::And => and(&operands[..], used_elements, elements, address_space),
            FilterOperator::Or => or(&operands[..], used_elements, elements, address_space),
            FilterOperator::Cast => cast(&operands[..], used_elements, elements, address_space),
            FilterOperator::BitwiseAnd => bitwise_and(&operands[..], used_elements, elements, address_space),
            FilterOperator::BitwiseOr => bitwise_or(&operands[..], used_elements, elements, address_space),
        }
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
            let value = if let Some(ref browse_path) = o.browse_path {
                // TODO o.data_type is ignored but should be used to restrict the browse
                // path to subtypes of HierarchicalReferences

                // Find the actual node via browse path
                if let Ok(node) = find_node_from_browse_path(address_space, browse_path) {
                    match node {
                        NodeType::Object(ref node) => {
                            if o.attribute_id == AttributeId::NodeId as u32 {
                                node.node_id().into()
                            } else {
                                error!("value_of, unsupported attribute id {} on object", o.attribute_id);
                                Variant::Empty
                            }
                        }
                        NodeType::Variable(ref node) => {
                            if o.attribute_id == AttributeId::Value as u32 {
                                if let Some(ref value) = node.value().value {
                                    value.clone()
                                } else {
                                    Variant::Empty
                                }
                            } else {
                                error!("value_of, unsupported attribute id {} on Variable", o.attribute_id);
                                Variant::Empty
                            }
                        }
                        _ => Variant::Empty
                    }
                } else {
                    error!("value_of, cannot find node from browse path");
                    Variant::Empty
                }
            } else {
                error!("value_of, invalid browse path supplied to operand");
                Variant::Empty
            };
            Ok(value)
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
pub(crate) fn is_null(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
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
    ( $v1: expr, $v2: expr, $variant_type: ident ) => {
        {
            if let Variant::$variant_type(v1) = $v1 {
                if let Variant::$variant_type(v2) = $v2 {
                    if v1 < v2 {
                        ComparisonResult::LessThan
                    }
                    else if v1 == v2 {
                        ComparisonResult::Equals
                    }
                    else {
                        ComparisonResult::GreaterThan
                    }
                } else {
                    panic!();
                }
            } else {
                panic!();
            }
        }
    }
}

/// Compares to operands by taking their numeric value, comparing the value and saying
/// which of the two is less than, greater than or equal. If the values cannot be compared, the
/// result is an error.
fn compare_operands(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<ComparisonResult, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
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
        VariantTypeId::Boolean => if v1 == v2 {
            ComparisonResult::Equals
        } else {
            ComparisonResult::NotEquals
        }
        _ => ComparisonResult::Error
    };
    Ok(result)
}

// Check if the two values are equal to each other. If the operands are of different types,
// the system shall perform any implicit conversion to a common type. This operator resolves to
// FALSE if no implicit conversion is available and the operands are of different types. This
// operator returns FALSE if the implicit conversion fails.
pub(crate) fn eq(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let result = compare_operands(operands, used_elements, elements, address_space)?;
    Ok((result == ComparisonResult::Equals).into())
}

// Check if operand[0] is greater than operand[1]
pub(crate) fn gt(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let result = compare_operands(operands, used_elements, elements, address_space)?;
    Ok((result == ComparisonResult::GreaterThan).into())
}

// Check if operand[0] is less than operand[1]
pub(crate) fn lt(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let result = compare_operands(operands, used_elements, elements, address_space)?;
    Ok((result == ComparisonResult::LessThan).into())
}

// Check if operand[0] is greater than or equal to operand[1]
pub(crate) fn gte(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let result = compare_operands(operands, used_elements, elements, address_space)?;
    Ok((result == ComparisonResult::GreaterThan || result == ComparisonResult::Equals).into())
}

// Check if operand[0] is less than or equal to operand[1]
pub(crate) fn lte(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let result = compare_operands(operands, used_elements, elements, address_space)?;
    Ok((result == ComparisonResult::LessThan || result == ComparisonResult::Equals).into())
}

// Check if operand[0] is matches the pattern defined by operand[1].
pub(crate) fn like(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
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

// TRUE if operand[0] is FALSE.
pub(crate) fn not(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // operand[0] resolves to a boolean
    // TRUE if 0 is FALSE
    // If resolve fails, result is NULL
    let v = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v = v.convert(VariantTypeId::Boolean);
    let result = if let Variant::Boolean(v) = v {
        (!v).into()
    } else {
        Variant::Empty
    };
    Ok(result)
}

// TRUE if operand[0] is greater or equal to operand[1] and less than or equal to operand[2].
pub(crate) fn between(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // 0, 1, 2 are ordered values
    // Element 0 must be greater or equal than element 1
    let result = match compare_operands(&operands[0..2], used_elements, elements, address_space)? {
        ComparisonResult::GreaterThan | ComparisonResult::Equals => {
            // Element must be less than or equal to element 2
            let operands = vec![operands[0].clone(), operands[2].clone()];
            match compare_operands(&operands[0..2], used_elements, elements, address_space)? {
                ComparisonResult::LessThan | ComparisonResult::Equals => true,
                _ => false
            }
        }
        _ => false
    };
    Ok(result.into())
}

// TRUE if operand[0] is equal to one or more of the remaining operands
pub(crate) fn in_list(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // TRUE if operand[0] is equal to one or more of the remaining operands.
    // The Equals Operator is evaluated for operand[0] and each remaining operand in the list.
    // If any Equals evaluation is TRUE, InList returns TRUE.
    let mut found = false;
    for operand in &operands[1..] {
        // Use a comparison with the first element and the current and check the response
        let operands = vec![operands[0].clone(), operand.clone()];
        if compare_operands(&operands, used_elements, elements, address_space)? == ComparisonResult::Equals {
            found = true;
            break;
        }
    }
    Ok(found.into())
}

// TRUE if operand[0] and operand[1] are TRUE.
pub(crate) fn and(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // The following restrictions apply to the operands:
    //  [0]: Any operand that resolves to a Boolean.
    //  [1]: Any operand that resolves to a Boolean.
    // If any operand cannot be resolved to a Boolean it is considered a NULL.
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v1 = v1.convert(VariantTypeId::Boolean);
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    let v2 = v2.convert(VariantTypeId::Boolean);

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
pub(crate) fn or(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // The following restrictions apply to the operands:
    //  [0]: Any operand that resolves to a Boolean.
    //  [1]: Any operand that resolves to a Boolean.
    // If any operand cannot be resolved to a Boolean it is considered a NULL.
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v1 = v1.convert(VariantTypeId::Boolean);
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
    let v2 = v2.convert(VariantTypeId::Boolean);

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
pub(crate) fn cast(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // Explicitly casts operand 0 to a value with the data type with a node if identified in node 1
    // [0] Any operand
    // [1] Any operand that resolves to a NodeId or ExpandedNodeId where the node is of type DataType
    //
    // In case of error evaluates to NULL.

    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;

    let result = match v2 {
        Variant::NodeId(node_id) => {
            if node_id.namespace == 0 {
                if let Identifier::Numeric(type_id) = node_id.identifier {
                    let type_id = match type_id {
                        type_id if type_id == DataTypeId::Boolean as u32 => VariantTypeId::Boolean,
                        type_id if type_id == DataTypeId::Byte as u32 => VariantTypeId::Byte,
                        type_id if type_id == DataTypeId::Int16 as u32 => VariantTypeId::Int16,
                        type_id if type_id == DataTypeId::UInt16 as u32 => VariantTypeId::UInt16,
                        type_id if type_id == DataTypeId::Int32 as u32 => VariantTypeId::Int32,
                        type_id if type_id == DataTypeId::UInt32 as u32 => VariantTypeId::UInt32,
                        type_id if type_id == DataTypeId::Int64 as u32 => VariantTypeId::Int64,
                        type_id if type_id == DataTypeId::UInt64 as u32 => VariantTypeId::UInt64,
                        type_id if type_id == DataTypeId::Float as u32 => VariantTypeId::Float,
                        type_id if type_id == DataTypeId::Double as u32 => VariantTypeId::Double,
                        type_id if type_id == DataTypeId::String as u32 => VariantTypeId::String,
                        type_id if type_id == DataTypeId::DateTime as u32 => VariantTypeId::DateTime,
                        type_id if type_id == DataTypeId::Guid as u32 => VariantTypeId::Guid,
                        type_id if type_id == DataTypeId::ByteString as u32 => VariantTypeId::ByteString,
                        type_id if type_id == DataTypeId::XmlElement as u32 => VariantTypeId::XmlElement,
                        type_id if type_id == DataTypeId::NodeId as u32 => VariantTypeId::NodeId,
                        type_id if type_id == DataTypeId::ExpandedNodeId as u32 => VariantTypeId::ExpandedNodeId,
                        type_id if type_id == DataTypeId::XmlElement as u32 => VariantTypeId::XmlElement,
                        type_id if type_id == DataTypeId::StatusCode as u32 => VariantTypeId::StatusCode,
                        type_id if type_id == DataTypeId::QualifiedName as u32 => VariantTypeId::QualifiedName,
                        type_id if type_id == DataTypeId::LocalizedText as u32 => VariantTypeId::LocalizedText,
                        _ => {
                            return Err(StatusCode::BadFilterOperandInvalid);
                        }
                    };
                    v1.cast(type_id)
                } else {
                    Variant::Empty
                }
            } else {
                Variant::Empty
            }
        }
        // TODO ExpandedNodeId
        _ => Variant::Empty
    };

    Ok(result)
}

#[derive(PartialEq)]
enum BitOperation {
    And,
    Or,
}

macro_rules! bitwise_operation {
    ( $v1: expr, $v2: expr, $op: expr, $variant_type: ident ) => {
        {
            if let Variant::$variant_type(v1) = $v1 {
                if let Variant::$variant_type(v2) = $v2 {
                    match $op {
                        BitOperation::And => (v1 & v2).into(),
                        BitOperation::Or => (v1 | v2).into()
                    }
                } else {
                    panic!();
                }
            } else {
                panic!();
            }
        }
    }
}

fn bitwise_operation(operation: BitOperation, operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    let v1 = value_of(&Operand::try_from(&operands[0])?, used_elements, elements, address_space)?;
    let v2 = value_of(&Operand::try_from(&operands[1])?, used_elements, elements, address_space)?;
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
        _ => Variant::Empty
    };
    Ok(result)
}

// The result is an integer which matches the size of the largest operand and contains a bitwise
// And operation of the two operands where both have been converted to the same size (largest of
// the two operands).
pub(crate) fn bitwise_and(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    bitwise_operation(BitOperation::And, operands, used_elements, elements, address_space)
}

// The result is an integer which matches the size of the largest operand and contains a bitwise Or
// operation of the two operands where both have been converted to the same size (largest of the
// two operands).
pub(crate) fn bitwise_or(operands: &[ExtensionObject], used_elements: &mut HashSet<u32>, elements: &[ContentFilterElement], address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    bitwise_operation(BitOperation::Or, operands, used_elements, elements, address_space)
}
