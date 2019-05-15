use crate::address_space::address_space::AddressSpace;

use opcua_types::{
    *,
    status_code::StatusCode,
    service_types::{EventFilter, EventFilterResult, ContentFilter, ContentFilterResult, SimpleAttributeOperand},
};

fn validate_select_clause(clause: &SimpleAttributeOperand, address_space: &AddressSpace) -> StatusCode {
    // TODO List of the values to return with each Event in a Notification. At least one valid clause
    //  shall be specified. See 7.4.4.5 for the definition of SimpleAttributeOperand.
    StatusCode::BadNodeIdUnknown
}

fn validate_where_class(where_clause: &ContentFilter, address_space: &AddressSpace) -> ContentFilterResult {
    // TODO Limit the Notifications to those Events that match the criteria defined by this ContentFilter. The ContentFilter structure is described in 7.4.
    //  The AttributeOperand structure may not be used in an EventFilter.
    ContentFilterResult {
        element_results: None,
        element_diagnostic_infos: None,
    }
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