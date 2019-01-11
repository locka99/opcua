//! Contains functions used for making relative paths from / to strings, as per OPC UA Part 4, Appendix A

use crate::{
    node_ids::*,
    node_id::{Identifier, NodeId},
    service_types::{RelativePath, RelativePathElement},
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

fn reference_type_browse_name(node_id: &NodeId) -> Result<String, ()> {
    match &node_id.identifier {
        Identifier::String(browse_name) => Ok(browse_name.to_string()),
        Identifier::Numeric(id) => {
            if node_id.namespace == 0 {
                let id = *id;
                // This syntax for matching a number to an enum is just the worst
                let browse_name = match id {
                    id if id == ReferenceTypeId::References as u32 => "References",
                    id if id == ReferenceTypeId::NonHierarchicalReferences as u32 => "NonHierarchicalReferences",
                    id if id == ReferenceTypeId::HierarchicalReferences as u32 => "HierarchicalReferences",
                    id if id == ReferenceTypeId::HasChild as u32 => "HasChild",
                    id if id == ReferenceTypeId::Organizes as u32 => "Organizes",
                    id if id == ReferenceTypeId::HasEventSource as u32 => "HasEventSource",
                    id if id == ReferenceTypeId::HasModellingRule as u32 => "HasModellingRule",
                    id if id == ReferenceTypeId::HasEncoding as u32 => "HasEncoding",
                    id if id == ReferenceTypeId::HasDescription as u32 => "HasDescription",
                    id if id == ReferenceTypeId::HasTypeDefinition as u32 => "HasTypeDefinition",
                    id if id == ReferenceTypeId::GeneratesEvent as u32 => "GeneratesEvent",
                    id if id == ReferenceTypeId::Aggregates as u32 => "Aggregates",
                    id if id == ReferenceTypeId::HasSubtype as u32 => "HasSubtype",
                    id if id == ReferenceTypeId::HasProperty as u32 => "HasProperty",
                    id if id == ReferenceTypeId::HasComponent as u32 => "HasComponent",
                    id if id == ReferenceTypeId::HasNotifier as u32 => "HasNotifier",
                    id if id == ReferenceTypeId::HasOrderedComponent as u32 => "HasOrderedComponent",
                    id if id == ReferenceTypeId::FromState as u32 => "FromState",
                    id if id == ReferenceTypeId::ToState as u32 => "ToState",
                    id if id == ReferenceTypeId::HasCause as u32 => "HasCause",
                    id if id == ReferenceTypeId::HasEffect as u32 => "HasEffect",
                    id if id == ReferenceTypeId::HasHistoricalConfiguration as u32 => "HasHistoricalConfiguration",
                    id if id == ReferenceTypeId::HasSubStateMachine as u32 => "HasSubStateMachine",
                    id if id == ReferenceTypeId::AlwaysGeneratesEvent as u32 => "AlwaysGeneratesEvent",
                    id if id == ReferenceTypeId::HasTrueSubState as u32 => "HasTrueSubState",
                    id if id == ReferenceTypeId::HasFalseSubState as u32 => "HasFalseSubState",
                    id if id == ReferenceTypeId::HasCondition as u32 => "HasCondition",
                    _ => return Err(())
                };
                Ok(browse_name.to_string())
            } else {
                Err(())
            }
        }
        _ => Err(())
    }
}

/// Constructs a string representation of the reference type in the relative path.
/// This code assumes that the reference type's node id has a string identifier and that
/// the string identifier is the same as the browse name.
pub(crate) fn relative_path_reference_type(e: &RelativePathElement) -> Result<String, ()> {
    let browse_name = reference_type_browse_name(&e.reference_type_id)?;
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

        let browse_name = escape_browse_name(browse_name.as_ref());
        if e.reference_type_id.namespace != 0 {
            result.push_str(&format!("{}:{}", e.reference_type_id.namespace, browse_name));
        } else {
            result.push_str(&browse_name);
        }
        result.push('>');
    }

    Ok(result)
}

pub(crate) fn from_relative_path_element(element: &RelativePathElement, always_use_namespace: bool) -> Result<String, ()>
{
    let target_browse_name = escape_browse_name(element.target_name.name.as_ref());
    let mut result = relative_path_reference_type(element)?;
    if always_use_namespace || element.target_name.namespace_index > 0 {
        result.push_str(&format!("{}:{}", element.target_name.namespace_index, target_browse_name));
    } else {
        result.push_str(&target_browse_name);
    }
    Ok(result)
}

pub fn from_relative_path(path: &RelativePath) -> Result<String, ()> {
    let result = if let Some(ref elements) = path.elements {
        let mut result = String::with_capacity(1024);
        for e in elements.iter() {
            result.push_str(from_relative_path_element(e, true)?.as_ref());
        };
        result
    } else {
        String::new()
    };
    Ok(result)
}

pub fn make_relative_path(path: &str) -> Result<RelativePath, ()> {
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

/// Test that escaping of browse names works as expected in each direction
#[test]
fn test_escape_browse_name() {
    [
        ("", ""),
        ("Hello World", "Hello World"),
        ("Hello &World", "Hello &&World"),
        ("Hello &&World", "Hello &&&&World"),
        ("Block.Output", "Block&.Output"),
        ("/Name_1", "&/Name_1"),
        (".Name_2", "&.Name_2"),
        (":Name_3", "&:Name_3"),
        ("&Name_4", "&&Name_4"),
    ].iter().for_each(|n| {
        let original = n.0.to_string();
        let escaped = n.1.to_string();
        assert_eq!(escaped, escape_browse_name(&original));
        assert_eq!(unescape_browse_name(&escaped), original);
    });
}

/// Test that given a relative path element that it can be converted to/from a string
/// and a RelativePathElement type
#[test]
fn test_relative_path_element() {
    use crate::basic_types::QualifiedName;

    [
        (RelativePathElement {
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            is_inverse: false,
            include_subtypes: false,
            target_name: QualifiedName::new(0, "foo"),
        }, "/0:foo"),
        (RelativePathElement {
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            is_inverse: false,
            include_subtypes: false,
            target_name: QualifiedName::new(0, ".foo"),
        }, "/0:&.foo"),
        (RelativePathElement {
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            is_inverse: true,
            include_subtypes: true,
            target_name: QualifiedName::new(2, "foo"),
        }, "<!HierarchicalReferences>2:foo"),
        (RelativePathElement {
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            is_inverse: true,
            include_subtypes: false,
            target_name: QualifiedName::new(0, "foo"),
        }, "<#!HierarchicalReferences>0:foo"),
        (RelativePathElement {
            reference_type_id: ReferenceTypeId::Aggregates.into(),
            is_inverse: false,
            include_subtypes: false,
            target_name: QualifiedName::new(0, "foo"),
        }, ".0:foo"),
        (RelativePathElement {
            reference_type_id: ReferenceTypeId::HasHistoricalConfiguration.into(),
            is_inverse: false,
            include_subtypes: true,
            target_name: QualifiedName::new(0, "bar"),
        }, "<HasHistoricalConfiguration>0:bar"),
    ].iter().for_each(|n| {
        let element = &n.0;
        let expected = n.1.to_string();
        let actual = from_relative_path_element(element, true).unwrap();
        assert_eq!(expected, actual);
        // TODO convert path string back to relative path element, expect it to equal element
    });
}

/// Test that the given entire relative path, that it can be converted to/from a string
/// and a RelativePath type.
#[test]
fn test_relative_path() {
    use crate::basic_types::QualifiedName;

    // Samples are from OPC UA Part 4 Appendix A
    let mut tests = vec![
        (vec![
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: false,
                include_subtypes: false,
                target_name: QualifiedName::new(2, "Block.Output"),
            }
        ], "/2:Block&.Output"),
        (vec![
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: false,
                include_subtypes: false,
                target_name: QualifiedName::new(3, "Truck"),
            },
            RelativePathElement {
                reference_type_id: ReferenceTypeId::Aggregates.into(),
                is_inverse: false,
                include_subtypes: false,
                target_name: QualifiedName::new(0, "NodeVersion"),
            }],
         "/3:Truck.0:NodeVersion"),
    ];

    tests.drain(..).for_each(|n| {
        let relative_path = RelativePath {
            elements: Some(n.0)
        };
        let expected = n.1.to_string();
        let actual = from_relative_path(&relative_path).unwrap();
        assert_eq!(expected, actual);
        // TODO convert path string back to relative path, expect it to equal element
    });
}