use std::collections::HashSet;

use hashbrown::HashMap;

use crate::{
    async_server::node_manager::TypeTree,
    server::prelude::{
        AttributeId, ContentFilter, ContentFilterElementResult, ContentFilterResult,
        ElementOperand, EventFilter, EventFilterResult, FilterOperator, LiteralOperand, NodeClass,
        NodeId, NumericRange, ObjectTypeId, Operand, QualifiedName, RelativePath,
        SimpleAttributeOperand, StatusCode, UAString,
    },
};

#[derive(Debug, Clone)]
pub struct ParsedAttributeOperand {
    pub node_id: NodeId,
    pub alias: UAString,
    pub browse_path: RelativePath,
    pub attribute_id: AttributeId,
    pub index_range: NumericRange,
}

#[derive(Debug, Clone)]
pub struct ParsedSimpleAttributeOperand {
    pub type_definition_id: NodeId,
    pub browse_path: Vec<QualifiedName>,
    pub attribute_id: AttributeId,
    pub index_range: NumericRange,
}

#[derive(Debug, Clone)]
pub enum ParsedOperand {
    ElementOperand(ElementOperand),
    LiteralOperand(LiteralOperand),
    AttributeOperand(ParsedAttributeOperand),
    SimpleAttributeOperand(ParsedSimpleAttributeOperand),
}

impl ParsedOperand {
    pub(crate) fn parse(
        operand: Operand,
        num_elements: usize,
        type_tree: &TypeTree,
        allow_attribute_operand: bool,
    ) -> Result<Self, StatusCode> {
        match operand {
            Operand::ElementOperand(e) => {
                if e.index as usize >= num_elements {
                    Err(StatusCode::BadFilterOperandInvalid)
                } else {
                    Ok(Self::ElementOperand(e))
                }
            }
            Operand::LiteralOperand(o) => Ok(Self::LiteralOperand(o)),
            Operand::AttributeOperand(o) => {
                if !allow_attribute_operand {
                    return Err(StatusCode::BadFilterOperandInvalid);
                }
                let attribute_id = AttributeId::from_u32(o.attribute_id)
                    .map_err(|_| StatusCode::BadAttributeIdInvalid)?;
                let index_range = o
                    .index_range
                    .as_ref()
                    .parse::<NumericRange>()
                    .map_err(|_| StatusCode::BadIndexRangeInvalid)?;
                Ok(Self::AttributeOperand(ParsedAttributeOperand {
                    node_id: o.node_id,
                    attribute_id,
                    alias: o.alias,
                    browse_path: o.browse_path,
                    index_range,
                }))
            }
            Operand::SimpleAttributeOperand(o) => Ok(Self::SimpleAttributeOperand(
                validate_select_clause(o, type_tree)?,
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedEventFilter {
    pub(super) content_filter: ParsedContentFilter,
    pub(super) select_clauses: Vec<ParsedSimpleAttributeOperand>,
}

impl ParsedEventFilter {
    pub fn new(
        raw: EventFilter,
        type_tree: &TypeTree,
    ) -> (EventFilterResult, Result<Self, StatusCode>) {
        validate(raw, type_tree)
    }
}

#[derive(Debug, Clone)]
pub struct ParsedContentFilter {
    pub(super) elements: Vec<ParsedContentFilterElement>,
}

impl ParsedContentFilter {
    pub fn empty() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    pub(crate) fn parse(
        filter: ContentFilter,
        type_tree: &TypeTree,
        allow_attribute_operand: bool,
        allow_complex_operators: bool,
    ) -> (ContentFilterResult, Result<ParsedContentFilter, StatusCode>) {
        validate_where_clause(
            filter,
            type_tree,
            allow_attribute_operand,
            allow_complex_operators,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ParsedContentFilterElement {
    pub(super) operator: FilterOperator,
    pub(super) operands: Vec<ParsedOperand>,
}

/// This validates the event filter as best it can to make sure it doesn't contain nonsense.
fn validate(
    event_filter: EventFilter,
    type_tree: &TypeTree,
) -> (EventFilterResult, Result<ParsedEventFilter, StatusCode>) {
    let num_select_clauses = event_filter
        .select_clauses
        .as_ref()
        .map(|r| r.len())
        .unwrap_or_default();
    let mut select_clause_results = Vec::with_capacity(num_select_clauses);
    let mut final_select_clauses = Vec::with_capacity(num_select_clauses);
    for clause in event_filter.select_clauses.into_iter().flatten() {
        match validate_select_clause(clause, type_tree) {
            Ok(result) => {
                select_clause_results.push(StatusCode::Good);
                final_select_clauses.push(result);
            }
            Err(e) => select_clause_results.push(e),
        }
    }
    let (where_clause_result, parsed_where_clause) =
        validate_where_clause(event_filter.where_clause, type_tree, false, false);

    (
        EventFilterResult {
            select_clause_results: if select_clause_results.is_empty() {
                None
            } else {
                Some(select_clause_results)
            },
            select_clause_diagnostic_infos: None,
            where_clause_result,
        },
        parsed_where_clause.map(|f| ParsedEventFilter {
            content_filter: f,
            select_clauses: final_select_clauses,
        }),
    )
}

fn validate_select_clause(
    clause: SimpleAttributeOperand,
    type_tree: &TypeTree,
) -> Result<ParsedSimpleAttributeOperand, StatusCode> {
    let Some(path) = clause.browse_path else {
        return Err(StatusCode::BadNodeIdUnknown);
    };

    let Ok(index_range) = clause.index_range.as_ref().parse::<NumericRange>() else {
        return Err(StatusCode::BadIndexRangeInvalid);
    };

    let Ok(attribute_id) = AttributeId::from_u32(clause.attribute_id) else {
        return Err(StatusCode::BadAttributeIdInvalid);
    };

    // From the standard:  If the SimpleAttributeOperand is used in an EventFilter
    // and the typeDefinitionId is BaseEventType the Server shall evaluate the
    // browsePath without considering the typeDefinitionId.
    if clause.type_definition_id == ObjectTypeId::BaseEventType.into() {
        // Do a simpler form of the attribute ID check in this case.
        if attribute_id != AttributeId::NodeId && attribute_id != AttributeId::Value {
            return Err(StatusCode::BadAttributeIdInvalid);
        }
        // We could in theory evaluate _every_ event type here, but that would be painful
        // and potentially expensive on servers with lots of types. It also wouldn't
        // be all that helpful.
        return Ok(ParsedSimpleAttributeOperand {
            type_definition_id: clause.type_definition_id,
            browse_path: path,
            attribute_id,
            index_range,
        });
    }

    let Some(node) = type_tree.find_type_prop_by_browse_path(&clause.type_definition_id, &path)
    else {
        return Err(StatusCode::BadNodeIdUnknown);
    };

    // Validate the attribute id. Per spec:
    //
    //   The SimpleAttributeOperand allows the client to specify any attribute; however the server
    //   is only required to support the value attribute for variable nodes and the NodeId attribute
    //   for object nodes. That said, profiles defined in Part 7 may make support for
    //   additional attributes mandatory.
    //
    // So code will implement the bare minimum for now.
    let is_valid = match node.node_class {
        NodeClass::Object => attribute_id == AttributeId::NodeId,
        NodeClass::Variable => attribute_id == AttributeId::Value,
        _ => false,
    };

    if !is_valid {
        Err(StatusCode::BadAttributeIdInvalid)
    } else {
        Ok(ParsedSimpleAttributeOperand {
            type_definition_id: clause.type_definition_id,
            browse_path: path,
            attribute_id,
            index_range,
        })
    }
}

fn validate_where_clause(
    where_clause: ContentFilter,
    type_tree: &TypeTree,
    allow_attribute_operand: bool,
    allow_complex_operators: bool,
) -> (ContentFilterResult, Result<ParsedContentFilter, StatusCode>) {
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

    let Some(elements) = &where_clause.elements else {
        return (
            ContentFilterResult {
                element_results: None,
                element_diagnostic_infos: None,
            },
            Ok(ParsedContentFilter::empty()),
        );
    };

    let mut operand_refs: HashMap<usize, Vec<usize>> = HashMap::new();

    let element_result_pairs: Vec<(
        ContentFilterElementResult,
        Option<ParsedContentFilterElement>,
    )> = elements
        .iter()
        .enumerate()
        .map(|(element_idx, e)| {
            let Some(filter_operands) = &e.filter_operands else {
                return (
                    ContentFilterElementResult {
                        status_code: StatusCode::BadFilterOperandCountMismatch,
                        operand_status_codes: None,
                        operand_diagnostic_infos: None,
                    },
                    None,
                );
            };

            let operand_count_mismatch = match e.filter_operator {
                FilterOperator::Equals => filter_operands.len() != 2,
                FilterOperator::IsNull => filter_operands.len() != 1,
                FilterOperator::GreaterThan => filter_operands.len() != 2,
                FilterOperator::LessThan => filter_operands.len() != 2,
                FilterOperator::GreaterThanOrEqual => filter_operands.len() != 2,
                FilterOperator::LessThanOrEqual => filter_operands.len() != 2,
                FilterOperator::Like => filter_operands.len() != 2,
                FilterOperator::Not => filter_operands.len() != 1,
                FilterOperator::Between => filter_operands.len() != 3,
                FilterOperator::InList => filter_operands.len() < 2, // 2..n
                FilterOperator::And => filter_operands.len() != 2,
                FilterOperator::Or => filter_operands.len() != 2,
                FilterOperator::Cast => filter_operands.len() != 2,
                FilterOperator::BitwiseAnd => filter_operands.len() != 2,
                FilterOperator::BitwiseOr => filter_operands.len() != 2,
                FilterOperator::InView => filter_operands.len() != 1,
                FilterOperator::OfType => filter_operands.len() != 1,
                FilterOperator::RelatedTo => filter_operands.len() != 6,
            };

            if !allow_complex_operators
                && matches!(
                    e.filter_operator,
                    FilterOperator::InView | FilterOperator::OfType | FilterOperator::RelatedTo
                )
            {
                return (
                    ContentFilterElementResult {
                        status_code: StatusCode::BadFilterOperatorUnsupported,
                        operand_status_codes: None,
                        operand_diagnostic_infos: None,
                    },
                    None,
                );
            }

            let mut valid_operands = Vec::with_capacity(filter_operands.len());
            let mut operand_status_codes = Vec::with_capacity(filter_operands.len());

            let operand_results: Vec<_> = filter_operands
                .iter()
                .map(|e| {
                    let operand = <Operand>::try_from(e)?;
                    ParsedOperand::parse(
                        operand,
                        elements.len(),
                        type_tree,
                        allow_attribute_operand,
                    )
                })
                .collect();

            for res in operand_results {
                match res {
                    Ok(op) => {
                        operand_status_codes.push(StatusCode::Good);
                        if let ParsedOperand::ElementOperand(e) = &op {
                            operand_refs
                                .entry(element_idx)
                                .or_default()
                                .push(e.index as usize);
                        }
                        valid_operands.push(op);
                    }
                    Err(e) => operand_status_codes.push(e),
                }
            }
            let operator_invalid = valid_operands.len() != filter_operands.len();

            // Check what error status to return
            let status_code = if operand_count_mismatch {
                StatusCode::BadFilterOperandCountMismatch
            } else if operator_invalid {
                StatusCode::BadFilterOperandInvalid
            } else {
                StatusCode::Good
            };

            let res = if status_code.is_good() {
                Some(ParsedContentFilterElement {
                    operator: e.filter_operator,
                    operands: valid_operands,
                })
            } else {
                None
            };

            (
                ContentFilterElementResult {
                    status_code,
                    operand_status_codes: Some(operand_status_codes),
                    operand_diagnostic_infos: None,
                },
                res,
            )
        })
        .collect();

    let mut is_valid = true;
    let mut valid_elements = Vec::with_capacity(elements.len());
    let mut element_results = Vec::with_capacity(elements.len());
    for (result, element) in element_result_pairs {
        if let Some(element) = element {
            valid_elements.push(element);
        } else {
            is_valid = false;
        }
        element_results.push(result);
    }

    // Discover cycles. The operators must form a tree starting from the first
    let mut path = HashSet::new();
    match has_cycles(&operand_refs, 0, &mut path) {
        Ok(()) => (),
        Err(()) => is_valid = false,
    }

    (
        ContentFilterResult {
            element_results: Some(element_results),
            element_diagnostic_infos: None,
        },
        if is_valid {
            Ok(ParsedContentFilter {
                elements: valid_elements,
            })
        } else {
            Err(StatusCode::BadEventFilterInvalid)
        },
    )
}

fn has_cycles(
    children: &HashMap<usize, Vec<usize>>,
    id: usize,
    path: &mut HashSet<usize>,
) -> Result<(), ()> {
    let Some(child_refs) = children.get(&id) else {
        return Ok(());
    };
    if !path.insert(id) {
        return Err(());
    }

    for child in child_refs {
        has_cycles(children, *child, path)?;
    }

    path.remove(&id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        async_server::{events::validation::validate_where_clause, node_manager::TypeTree},
        server::prelude::{
            AttributeId, ContentFilter, ContentFilterElement, ContentFilterResult, FilterOperator,
            NodeClass, NodeId, ObjectTypeId, Operand, SimpleAttributeOperand, StatusCode,
        },
    };

    #[test]
    fn test_validate_empty_where_clause() {
        let type_tree = TypeTree::new();
        // check for at least one filter operand
        let where_clause = ContentFilter { elements: None };
        let (result, filter) = validate_where_clause(where_clause, &type_tree, false, false);
        assert_eq!(
            result,
            ContentFilterResult {
                element_results: None,
                element_diagnostic_infos: None,
            }
        );
        assert!(filter.is_ok());
    }

    #[test]
    fn test_validate_operator_len() {
        let type_tree = TypeTree::new();

        // Make a where clause where every single operator is included but each has the wrong number of operands.
        // We should expect them all to be in error
        let where_clause = ContentFilter {
            elements: Some(vec![
                ContentFilterElement::from((FilterOperator::Equals, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::IsNull, vec![])),
                ContentFilterElement::from((
                    FilterOperator::GreaterThan,
                    vec![Operand::literal(10)],
                )),
                ContentFilterElement::from((FilterOperator::LessThan, vec![Operand::literal(10)])),
                ContentFilterElement::from((
                    FilterOperator::GreaterThanOrEqual,
                    vec![Operand::literal(10)],
                )),
                ContentFilterElement::from((
                    FilterOperator::LessThanOrEqual,
                    vec![Operand::literal(10)],
                )),
                ContentFilterElement::from((FilterOperator::Like, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Not, vec![])),
                ContentFilterElement::from((
                    FilterOperator::Between,
                    vec![Operand::literal(10), Operand::literal(20)],
                )),
                ContentFilterElement::from((FilterOperator::InList, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::And, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Or, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Cast, vec![Operand::literal(10)])),
                ContentFilterElement::from((
                    FilterOperator::BitwiseAnd,
                    vec![Operand::literal(10)],
                )),
                ContentFilterElement::from((FilterOperator::BitwiseOr, vec![Operand::literal(10)])),
                ContentFilterElement::from((FilterOperator::Like, vec![Operand::literal(10)])),
            ]),
        };
        // Check for less than required number of operands
        let (result, filter) = validate_where_clause(where_clause, &type_tree, false, false);
        result
            .element_results
            .unwrap()
            .iter()
            .for_each(|e| assert_eq!(e.status_code, StatusCode::BadFilterOperandCountMismatch));
        assert_eq!(filter.unwrap_err(), StatusCode::BadEventFilterInvalid);
    }

    #[test]
    fn test_validate_bad_filter_operand() {
        let type_tree = TypeTree::new();

        // check for filter operator invalid, by giving it a bogus extension object for an element
        use crate::types::{service_types::ContentFilterElement, ExtensionObject};
        let bad_operator = ExtensionObject::null();
        let where_clause = ContentFilter {
            elements: Some(vec![ContentFilterElement {
                filter_operator: FilterOperator::IsNull,
                filter_operands: Some(vec![bad_operator]),
            }]),
        };
        let (result, filter) = validate_where_clause(where_clause, &type_tree, false, false);
        let element_results = result.element_results.unwrap();
        assert_eq!(element_results.len(), 1);
        assert_eq!(
            element_results[0].status_code,
            StatusCode::BadFilterOperandInvalid
        );
        let err = filter.unwrap_err();
        assert_eq!(err, StatusCode::BadEventFilterInvalid);
    }

    #[test]
    fn test_validate_select_operands() {
        let mut type_tree = TypeTree::new();

        type_tree.add_type_node(
            &NodeId::new(1, "event"),
            &ObjectTypeId::BaseEventType.into(),
            NodeClass::ObjectType,
        );
        type_tree.add_type_property(
            &NodeId::new(1, "prop"),
            &NodeId::new(1, "event"),
            &[&"Prop".into()],
            NodeClass::Variable,
        );

        // One attribute that exists, one that doesn't.
        let where_clause = ContentFilter {
            elements: Some(vec![
                ContentFilterElement::from((
                    FilterOperator::IsNull,
                    vec![Operand::SimpleAttributeOperand(SimpleAttributeOperand {
                        type_definition_id: NodeId::new(1, "event"),
                        browse_path: Some(vec!["Prop".into()]),
                        attribute_id: AttributeId::Value as u32,
                        index_range: Default::default(),
                    })],
                )),
                ContentFilterElement::from((
                    FilterOperator::IsNull,
                    vec![Operand::SimpleAttributeOperand(SimpleAttributeOperand {
                        type_definition_id: NodeId::new(1, "event"),
                        browse_path: Some(vec!["Prop2".into()]),
                        attribute_id: AttributeId::Value as u32,
                        index_range: Default::default(),
                    })],
                )),
            ]),
        };

        let (result, filter) = validate_where_clause(where_clause, &type_tree, false, false);
        let element_results = result.element_results.unwrap();
        assert_eq!(element_results.len(), 2);
        assert_eq!(element_results[0].status_code, StatusCode::Good);
        assert_eq!(
            element_results[1].status_code,
            StatusCode::BadFilterOperandInvalid
        );
        let status_codes = element_results[1].operand_status_codes.as_ref().unwrap();
        assert_eq!(status_codes.len(), 1);
        assert_eq!(status_codes[0], StatusCode::BadNodeIdUnknown);
        assert_eq!(filter.unwrap_err(), StatusCode::BadEventFilterInvalid);
    }

    #[test]
    fn test_validate_circular_filter() {
        let type_tree = TypeTree::new();

        let where_clause = ContentFilter {
            elements: Some(vec![
                ContentFilterElement::from((
                    FilterOperator::And,
                    vec![Operand::element(1), Operand::element(2)],
                )),
                ContentFilterElement::from((FilterOperator::IsNull, vec![Operand::literal(10)])),
                ContentFilterElement::from((
                    FilterOperator::Or,
                    vec![Operand::element(1), Operand::element(3)],
                )),
                ContentFilterElement::from((FilterOperator::Not, vec![Operand::element(0)])),
            ]),
        };

        let (_result, filter) = validate_where_clause(where_clause, &type_tree, false, false);
        assert_eq!(filter.unwrap_err(), StatusCode::BadEventFilterInvalid);
    }
}
