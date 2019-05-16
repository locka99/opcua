use std::convert::TryFrom;

use opcua_types::{
    ExtensionObject, DecodingLimits,
    status_code::StatusCode,
    node_ids::ObjectId,
    service_types::{
        FilterOperator, EventFilter, EventFilterResult, ContentFilter, ContentFilterResult, ContentFilterElementResult, SimpleAttributeOperand,
        ElementOperand, LiteralOperand, AttributeOperand,
    },
};

use crate::address_space::address_space::AddressSpace;

pub enum Operand {
    ElementOperand(ElementOperand),
    LiteralOperand(LiteralOperand),
    AttributeOperand(AttributeOperand),
    SimpleAttributeOperand(SimpleAttributeOperand),
}

impl TryFrom<&ExtensionObject> for Operand {
    type Error = StatusCode;

    fn try_from(v: &ExtensionObject) -> Result<Self, Self::Error> {
        let object_id = v.object_id().map_err(|_| StatusCode::BadFilterOperandInvalid)?;
        let decoding_limits = DecodingLimits::default();
        let operand = match object_id {
            ObjectId::ElementOperand_Encoding_DefaultBinary =>
                Operand::ElementOperand(v.decode_inner::<ElementOperand>(&decoding_limits)?),
            ObjectId::LiteralOperand_Encoding_DefaultBinary =>
                Operand::LiteralOperand(v.decode_inner::<LiteralOperand>(&decoding_limits)?),
            ObjectId::AttributeOperand_Encoding_DefaultBinary =>
                Operand::AttributeOperand(v.decode_inner::<AttributeOperand>(&decoding_limits)?),
            ObjectId::SimpleAttributeOperand_Encoding_DefaultBinary =>
                Operand::SimpleAttributeOperand(v.decode_inner::<SimpleAttributeOperand>(&decoding_limits)?),
            _ => {
                return Err(StatusCode::BadFilterOperandInvalid);
            }
        };
        Ok(operand)
    }
}

impl Operand {
    pub fn operand_type(&self) -> OperandType {
        match self {
            &Operand::ElementOperand(_) => OperandType::ElementOperand,
            &Operand::LiteralOperand(_) => OperandType::LiteralOperand,
            &Operand::AttributeOperand(_) => OperandType::AttributeOperand,
            &Operand::SimpleAttributeOperand(_) => OperandType::SimpleAttributeOperand
        }
    }

    pub fn is_element(&self) -> bool {
        self.operand_type() == OperandType::ElementOperand
    }

    pub fn is_literal(&self) -> bool {
        self.operand_type() == OperandType::LiteralOperand
    }

    pub fn is_attribute(&self) -> bool {
        self.operand_type() == OperandType::AttributeOperand
    }

    pub fn is_simple_attribute(&self) -> bool {
        self.operand_type() == OperandType::SimpleAttributeOperand
    }
}

#[derive(PartialEq)]
pub enum OperandType {
    ElementOperand,
    LiteralOperand,
    AttributeOperand,
    SimpleAttributeOperand,
}

fn validate_select_clause(clause: &SimpleAttributeOperand, address_space: &AddressSpace) -> StatusCode {

    // Check that the event type is supported by the server

    // Using the browse path obtain the instance declaration

    // Each instance declaration in the path shall be an object or variable node. The final node in the
    // path may be an object node; however, object nodes are only available for Events which are
    // visible in the server's address space

    // The SimpleAttributeOperand allows the client to specify any attribute; however the server
    // is only required to support the value attribute for variable nodes and the NodeId attribute
    // for object nodes. That said, profiles defined in Part 7 may make support for
    // additional attributes mandatory.

    // The SimpleAttributeOperand structure is used in the selectClauses to select the value to return
    // if an Event meets the criteria specified by the whereClause. A null value is returned in the correspeonding
    // event field in the publish response if the selected field is not part of the event or an
    // error was returned in the selectClauseResults of the EventFilterResult.

    // TODO List of the values to return with each Event in a Notification. At least one valid clause
    //  shall be specified. See 7.4.4.5 for the definition of SimpleAttributeOperand.
    StatusCode::BadNodeIdUnknown
}

fn validate_where_class(where_clause: &ContentFilter, address_space: &AddressSpace) -> ContentFilterResult {
    //
    // The ContentFilter structure defines a collection of elements that define filtering criteria.
    // Each element in the collection describes an operator and an array of operands to be used by
    // the operator. The operators that can be used in a ContentFilter are described in Table 119.
    // The filter is evaluated by evaluating the first entry in the element array starting with the
    // first operand in the operand array. The operands of an element may contain References to
    // sub-elements resulting in the evaluation continuing to the referenced elements in the element
    // array. The evaluation shall not introduce loops. For example evaluation starting from element
    // “A” shall never be able to return to element “A”. However there may be more than one path
    // leading to another element “B”. If an element cannot be traced back to the starting element
    // it is ignored. Extra operands for any operator shall result in an error. Annex B provides
    // examples using the ContentFilter structure.

    let element_results = if let Some(ref elements) = where_clause.elements {
        let element_results = elements.iter().map(|e| {
            let (status_code, operand_status_codes) = if e.filter_operands.is_none() {
                // All operators need at least one operand
                (StatusCode::BadFilterOperandCountMismatch, None)
            } else {
                let filter_operands = e.filter_operands.as_ref().unwrap();

                // The right number of operators? The spec implies its okay to pass
                // >= than the required #, but less is an error.
                let operand_count_mismatch = match e.filter_operator {
                    FilterOperator::Equals => filter_operands.len() < 2,
                    FilterOperator::IsNull => filter_operands.len() < 1,
                    FilterOperator::GreaterThan => filter_operands.len() < 2,
                    FilterOperator::LessThan => filter_operands.len() < 2,
                    FilterOperator::GreaterThanOrEqual => filter_operands.len() < 2,
                    FilterOperator::LessThanOrEqual => filter_operands.len() < 2,
                    FilterOperator::Like => filter_operands.len() < 2,
                    FilterOperator::Not => filter_operands.len() < 1,
                    FilterOperator::Between => filter_operands.len() < 3,
                    FilterOperator::InList => filter_operands.len() < 2, // 2..n
                    FilterOperator::And => filter_operands.len() < 2,
                    FilterOperator::Or => filter_operands.len() < 2,
                    FilterOperator::Cast => filter_operands.len() < 2,
                    FilterOperator::BitwiseAnd => filter_operands.len() < 2,
                    FilterOperator::BitwiseOr => filter_operands.len() < 2,
                };

                // Unsupported operators?
                let unsupported_operator = match e.filter_operator {
                    FilterOperator::Like => false,
                    _ => true
                };

                // Check if the operands look okay
                let operand_status_codes = filter_operands.iter().map(|e| {
                    // Look to see if any operand cannot be parsed
                    if <Operand>::try_from(e).is_err() {
                        StatusCode::BadFilterOperandInvalid
                    } else {
                        StatusCode::Good
                    }
                }).collect::<Vec<StatusCode>>();

                // Check if any operands were invalid
                let operator_invalid = operand_status_codes.iter().find(|e| !e.is_good()).is_some();

                // Check what error status to return
                let status_code = if operand_count_mismatch {
                    StatusCode::BadFilterOperandCountMismatch
                } else if unsupported_operator {
                    StatusCode::BadFilterOperatorUnsupported
                } else if operator_invalid {
                    StatusCode::BadFilterOperatorInvalid
                } else {
                    StatusCode::Good
                };

                (status_code, Some(operand_status_codes))
            };

            ContentFilterElementResult {
                status_code,
                operand_status_codes,
                operand_diagnostic_infos: None,
            }
        }).collect();
        Some(element_results)
    } else {
        None
    };

    // TODO Limit the Notifications to those Events that match the criteria defined by this ContentFilter. The ContentFilter structure is described in 7.4.
    //  The AttributeOperand structure may not be used in an EventFilter.
    ContentFilterResult {
        element_results,
        element_diagnostic_infos: None,
    }
}

#[test]
fn validate_where_class_test() {
    let address_space = AddressSpace::new();
    let where_clause = ContentFilter       {
        elements: None
    };
    let result = validate_where_class(&where_clause, &address_space);

// TODO
//
// check for at least one filter operand
// check for less than required number of operands
// check for unsupported operators
// check for operand invalid
}

pub fn validate_event_filter(event_filter: &EventFilter, address_space: &AddressSpace) -> EventFilterResult {
    let select_clause_results = if let Some(ref select_clauses) = event_filter.select_clauses {
        Some(select_clauses.iter().map(|clause| {
            validate_select_clause(clause, address_space)
        }).collect())
    } else {
        None
    };
    let where_clause_result = validate_where_class(&event_filter.where_clause, address_space);
    EventFilterResult {
        select_clause_results,
        select_clause_diagnostic_infos: None,
        where_clause_result,
    }
}