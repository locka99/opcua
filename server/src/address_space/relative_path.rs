use opcua_types::{
    node_ids::*,
    service_types::{RelativePath, RelativePathElement},
};

use crate::{
    address_space::AddressSpace,
};

const BROWSE_NAME_RESERVED_CHARS: &str = "&/.<>:#!";

/// Escapes reserved characters in the browse name
pub(crate) fn escape_browse_name(name: &str) -> String {
    let mut result = String::from(name);
    BROWSE_NAME_RESERVED_CHARS.chars().for_each(|c| {
        result = result.replace(c, &format!("&{}", c));
    });
    result
}

/// Unescapes reserved characters in the browse name
pub(crate) fn unescape_browse_name(name: &str) -> String {
    let mut result = String::from(name);
    BROWSE_NAME_RESERVED_CHARS.chars().for_each(|c| {
        result = result.replace(&format!("&{}", c), &c.to_string());
    });
    result
}

/// Constructs a string representation of the reference type in the relative path
pub(crate) fn relative_path_reference_type(address_space: &AddressSpace, e: &RelativePathElement) -> Result<String, ()> {
    if let Some(node) = address_space.find_node(&e.reference_type_id) {
        let node = node.as_node();
        let mut result = String::with_capacity(1024);
        // Common references will come out as '/' or '.'
        if !e.include_subtypes && !e.is_inverse {
            if e.reference_type_id == ReferenceTypeId::HierarchicalReferences.into() {
                result.push('/');
            } else if e.reference_type_id == ReferenceTypeId::Aggregates.into() {
                result.push('.');
            }
        };
        // Other kinds of reference are built as a string
        if result.is_empty() {
            result.push('<');
            if !e.include_subtypes {
                result.push('#');
            }
            if e.is_inverse {
                result.push('!');
            }
            let browse_name = escape_browse_name(node.browse_name().name.as_ref());
            if e.reference_type_id.namespace != 0 {
                result.push_str(&format!("{}:{}", e.reference_type_id.namespace, browse_name));
            } else {
                result.push_str(&browse_name);
            }
            result.push('>');
        }

        Ok(result)
    } else {
        Err(())
    }
}

pub(crate) fn from_relative_path_element(address_space: &AddressSpace, element: &RelativePathElement) -> Result<String, ()>
{
    let target_browse_name = escape_browse_name(element.target_name.name.as_ref());
    let mut result = relative_path_reference_type(address_space, element)?;
    result.push_str(&format!("{}:{}", element.target_name.namespace_index, target_browse_name));
    Ok(result)
}

pub(crate) fn from_relative_path(address_space: &AddressSpace, path: &RelativePath) -> Result<String, ()> {
    let result = if let Some(ref elements) = path.elements {
        let mut result = String::with_capacity(1024);
        for e in elements.iter() {
            result.push_str(from_relative_path_element(address_space, e)?.as_ref());
        };
        result
    } else {
        String::new()
    };
    Ok(result)
}

pub fn make_relative_path(address_space: &AddressSpace, path: &str) -> Result<RelativePath, ()> {
    // Tokenize the buffer
    let mut token = String::with_capacity(path.len());

    // Break the string into segments
    let mut escaped_char = false;
    let mut reference_type = ReferenceTypeId::HierarchicalReferences;

    let mut include_subtypes = true;
    let mut is_inverse = false;

    path.chars().for_each(|c| {
        // Parse the
        match c {
            '&' => {
                // The next character is escaped and part of the token
                escaped_char = true;
            }
            '/' => {
                // Follow any subtype of HierarchicalReferences
                if !token.is_empty() {}
                reference_type = ReferenceTypeId::HierarchicalReferences;
            }
            '.' => {
                // Follow any subtype of Aggregates
                if !token.is_empty() {}
                reference_type = ReferenceTypeId::Aggregates;
            }
            '>' => {
                // Process the token as a reference type
                // TODO this code needs to look up the reference type from the namespace:browsename
                reference_type = match token.as_ref() {
                    "References" => ReferenceTypeId::References,
                    "NonHierarchicalReferences" => ReferenceTypeId::NonHierarchicalReferences,
                    "HierarchicalReferences" => ReferenceTypeId::HierarchicalReferences,
                    "HasChild" => ReferenceTypeId::HasChild,
                    "Organizes" => ReferenceTypeId::Organizes,
                    "HasEventSource" => ReferenceTypeId::HasEventSource,
                    "HasModellingRule" => ReferenceTypeId::HasModellingRule,
                    "HasEncoding" => ReferenceTypeId::HasEncoding,
                    "HasDescription" => ReferenceTypeId::HasDescription,
                    "HasTypeDefinition" => ReferenceTypeId::HasTypeDefinition,
                    "GeneratesEvent" => ReferenceTypeId::GeneratesEvent,
                    "Aggregates" => ReferenceTypeId::Aggregates,
                    "HasSubtype" => ReferenceTypeId::HasSubtype,
                    "HasProperty" => ReferenceTypeId::HasProperty,
                    "HasComponent" => ReferenceTypeId::HasComponent,
                    "HasNotifier" => ReferenceTypeId::HasNotifier,
                    "HasOrderedComponent" => ReferenceTypeId::HasOrderedComponent,
                    "FromState" => ReferenceTypeId::FromState,
                    "ToState" => ReferenceTypeId::ToState,
                    "HasCause" => ReferenceTypeId::HasCause,
                    "HasEffect" => ReferenceTypeId::HasEffect,
                    "HasHistoricalConfiguration" => ReferenceTypeId::HasHistoricalConfiguration,
                    "HasSubStateMachine" => ReferenceTypeId::HasSubStateMachine,
                    "AlwaysGeneratesEvent" => ReferenceTypeId::AlwaysGeneratesEvent,
                    "HasTrueSubState" => ReferenceTypeId::HasTrueSubState,
                    "HasFalseSubState" => ReferenceTypeId::HasFalseSubState,
                    "HasCondition" => ReferenceTypeId::HasCondition,
                    _ => ReferenceTypeId::References,
                };
            }
            '<' => {}
            c => {
                token.push(c)
            }
        }
    });
    Err(())
}
