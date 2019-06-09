use std::convert::TryFrom;

use opcua_types::{
    AttributeId, Variant,
    operand::Operand,
    status_code::StatusCode,
    service_types::{
        FilterOperator, EventFilter, EventFieldList, EventFilterResult, ContentFilter,
        ContentFilterResult, ContentFilterElementResult, SimpleAttributeOperand,
    },
};

use crate::{
    address_space::{
        address_space::AddressSpace,
        node::NodeType,
        relative_path::*,
    },
    events::operator,
};

/// This validates the event filter as best it can to make sure it doesn't contain nonsense.
pub fn validate(event_filter: &EventFilter, address_space: &AddressSpace) -> Result<EventFilterResult, StatusCode> {
    let select_clause_results = if let Some(ref select_clauses) = event_filter.select_clauses {
        Some(select_clauses.iter().map(|clause| {
            validate_select_clause(clause, address_space)
        }).collect())
    } else {
        None
    };
    let where_clause_result = validate_where_clause(&event_filter.where_clause, address_space)?;
    Ok(EventFilterResult {
        select_clause_results,
        select_clause_diagnostic_infos: None,
        where_clause_result,
    })
}

/// Evaluate the event filt er and see if it triggers.
pub fn evaluate(event_filter: &EventFilter, address_space: &AddressSpace, client_handle: u32) -> Option<EventFieldList>
{
    if let Ok(result) = evaluate_where_clause(&event_filter.where_clause, address_space) {
        if result == Variant::Boolean(true) {
            // Produce an event notification list from the select clauses.
            let fields = event_filter.select_clauses.as_ref().unwrap().iter().map(|v| {
                operator::value_of_simple_attribute(v, address_space)
            }).collect();
            Some(EventFieldList {
                client_handle,
                event_fields: Some(fields),
            })
        } else {
            None
        }
    } else {
        None
    }
}

/// Evaluates a where clause which is a tree of conditionals
pub(crate) fn evaluate_where_clause(where_clause: &ContentFilter, address_space: &AddressSpace) -> Result<Variant, StatusCode> {
    // Clause is meant to have been validated before now so this code is not as stringent and makes some expectations.
    if let Some(ref elements) = where_clause.elements {
        use std::collections::HashSet;
        let mut used_elements = HashSet::new();
        used_elements.insert(0);
        let result = operator::evaluate(&elements[0], &mut used_elements, elements, address_space)?;
        Ok(result)
    } else {
        Ok(false.into())
    }
}

fn validate_select_clause(clause: &SimpleAttributeOperand, address_space: &AddressSpace) -> StatusCode {
    // The SimpleAttributeOperand structure is used in the selectClauses to select the value to return
    // if an Event meets the criteria specified by the whereClause. A null value is returned in the corresponding
    // event field in the publish response if the selected field is not part of the event or an
    // error was returned in the selectClauseResults of the EventFilterResult.

    if !clause.index_range.is_empty() {
        // TODO support index ranges
        error!("Select clause specifies an index range and will be rejected");
        StatusCode::BadIndexRangeInvalid
    } else if let Some(ref browse_path) = clause.browse_path {
        if let Ok(node) = find_node_from_browse_path(&address_space, browse_path) {
            // Validate the attribute id. Per spec:
            //
            //   The SimpleAttributeOperand allows the client to specify any attribute; however the server
            //   is only required to support the value attribute for variable nodes and the NodeId attribute
            //   for object nodes. That said, profiles defined in Part 7 may make support for
            //   additional attributes mandatory.
            //
            // So code will implement the bare minimum for now.
            let valid_attribute_id = match node {
                NodeType::Object(_) => {
                    // Only the node id
                    clause.attribute_id == AttributeId::NodeId as u32
                }
                NodeType::Variable(_) => {
                    // Only the value
                    clause.attribute_id == AttributeId::Value as u32
                }
                _ => {
                    // find_node_from_browse_path shouldn't have returned anything except an object
                    // or variable node.
                    panic!()
                }
            };
            if !valid_attribute_id {
                StatusCode::BadAttributeIdInvalid
            } else {
                StatusCode::Good
            }
        } else {
            error!("Invalid select clause node not found {:?}", clause);
            StatusCode::BadNodeIdUnknown
        }
    } else {
        error!("Invalid select clause with no browse path supplied");
        StatusCode::BadNodeIdUnknown
    }
}

fn validate_where_clause(where_clause: &ContentFilter, address_space: &AddressSpace) -> Result<ContentFilterResult, StatusCode> {
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

    if let Some(ref elements) = where_clause.elements {
        let element_results = elements.iter().map(|e| {
            let (status_code, operand_status_codes) = if e.filter_operands.is_none() {
                // All operators need at least one operand
                (StatusCode::BadFilterOperandCountMismatch, None)
            } else {
                let filter_operands = e.filter_operands.as_ref().unwrap();

                // The right number of operators? The spec implies it is okay to pass
                // more operands than the required #, but less is an error.
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

                // Check if the operands look okay
                let operand_status_codes = filter_operands.iter().map(|e| {
                    // Look to see if any operand cannot be parsed
                    match <Operand>::try_from(e) {
                        Ok(operand) => {
                            match operand {
                                Operand::AttributeOperand(_) => {
                                    // AttributeOperand may not be used in an EventFilter where clause
                                    error!("AttributeOperand is not permitted in EventFilter where clause");
                                    StatusCode::BadFilterOperandInvalid
                                }
                                Operand::ElementOperand(ref o) => {
                                    // Check that operands have to have an index <= number of elements
                                    if o.index as usize >= elements.len() {
                                        error!("Invalid element operand is out of range");
                                        StatusCode::BadFilterOperandInvalid
                                    } else {
                                        StatusCode::Good
                                    }
                                    // TODO operand should not refer to itself either directly or through circular
                                    //  references
                                }
                                Operand::SimpleAttributeOperand(ref o) => {
                                    // Check the element exists in the address space
                                    if let Some(ref browse_path) = o.browse_path {
                                        if let Ok(_node) = find_node_from_browse_path(address_space, browse_path) {
                                            StatusCode::Good
                                        } else {
                                            StatusCode::BadFilterOperandInvalid
                                        }
                                    } else {
                                        StatusCode::BadFilterOperandInvalid
                                    }
                                }
                                _ => StatusCode::Good
                            }
                        }
                        Err(err) => {
                            error!("Operand cannot be read from extension object, err = {}", err);
                            StatusCode::BadFilterOperandInvalid
                        }
                    }
                }).collect::<Vec<StatusCode>>();

                // Check if any operands were invalid
                let operator_invalid = operand_status_codes.iter().find(|e| !e.is_good()).is_some();

                // Check what error status to return
                let status_code = if operand_count_mismatch {
                    error!("Where clause has invalid filter operand count");
                    StatusCode::BadFilterOperandCountMismatch
                } else if operator_invalid {
                    error!("Where clause has invalid filter operator");
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
        }).collect::<Vec<ContentFilterElementResult>>();

        if !element_results.is_empty() {
            Ok(ContentFilterResult {
                element_results: Some(element_results),
                element_diagnostic_infos: None,
            })
        } else {
            // The where clause has to contain something
            Err(StatusCode::BadEventFilterInvalid)
        }
    } else {
        // The where clause has to contain something
        Err(StatusCode::BadEventFilterInvalid)
    }
}

#[test]
fn validate_where_clause_test() {
    use opcua_types::service_types::ContentFilterElement;

    let address_space = AddressSpace::new();

    {
        let where_clause = ContentFilter {
            elements: None
        };
        // check for at least one filter operand
        let result = validate_where_clause(&where_clause, &address_space);
        assert_eq!(result.unwrap_err(), StatusCode::BadEventFilterInvalid);
    }

    // Make a where clause where every single operator is included but each has the wrong number of operands.
    // We should expect them all to be in error
    {
        let where_clause = ContentFilter {
            elements: Some(vec![
                ContentFilterElement::from((FilterOperator::Equals, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::IsNull, vec![])),
                ContentFilterElement::from((FilterOperator::GreaterThan, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::LessThan, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::GreaterThanOrEqual, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::LessThanOrEqual, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Like, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Not, vec![])),
                ContentFilterElement::from((FilterOperator::Between, vec![Operand::literal(10), Operand::literal(20)])),
                ContentFilterElement::from((FilterOperator::InList, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::And, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Or, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Cast, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::BitwiseAnd, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::BitwiseOr, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Like, vec![Operand::literal(10)])),
            ])
        };
        // Check for less than required number of operands
        let result = validate_where_clause(&where_clause, &address_space).unwrap();
        result.element_results.unwrap().iter().for_each(|e| {
            assert_eq!(e.status_code, StatusCode::BadFilterOperandCountMismatch)
        });
    }

    // check for filter operator invalid, by giving it a bogus extension object for an element
    {
        use opcua_types::{ExtensionObject, service_types::ContentFilterElement};
        let bad_operator = ExtensionObject::null();
        let where_clause = ContentFilter {
            elements: Some(vec![ContentFilterElement {
                filter_operator: FilterOperator::IsNull,
                filter_operands: Some(vec![bad_operator]),
            }])
        };
        let result = validate_where_clause(&where_clause, &address_space).unwrap();
        let element_results = result.element_results.unwrap();
        assert_eq!(element_results.len(), 1);
        assert_eq!(element_results[0].status_code, StatusCode::BadFilterOperatorInvalid);
    }

    // TODO check operands are compatible with operator
    // TODO check for ElementOperand which are self referential or out of range
}

