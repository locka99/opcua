// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains functions used for making relative paths from / to strings, as per OPC UA Part 4, Appendix A
//!
//! Functions are implemented on the `RelativePath` and `RelativePathElement` structs where
//! there are most useful.
//!
use std::{error::Error, fmt};

use regex::Regex;

use crate::types::{
    node_id::{Identifier, NodeId},
    node_ids::*,
    qualified_name::QualifiedName,
    service_types::{RelativePath, RelativePathElement},
    string::UAString,
};

#[derive(Debug)]
struct RelativePathError;

impl fmt::Display for RelativePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelativePathError")
    }
}

impl Error for RelativePathError {}

impl RelativePath {
    /// The maximum size in chars of any path element.
    const MAX_TOKEN_LEN: usize = 256;
    /// The maximum number of elements in total.
    const MAX_ELEMENTS: usize = 32;

    /// Converts a string into a relative path. Caller must supply a `node_resolver` which will
    /// be used to look up nodes from their browse name. The function will reject strings
    /// that look unusually long or contain too many elements.
    pub fn from_str<CB>(path: &str, node_resolver: &CB) -> Result<RelativePath, ()>
    where
        CB: Fn(u16, &str) -> Option<NodeId>,
    {
        let mut elements: Vec<RelativePathElement> = Vec::new();

        // This loop will break the string up into path segments. For each segment it will
        // then parse it into a relative path element. When the string is successfully parsed,
        // the elements will be returned.
        let mut escaped_char = false;
        let mut token = String::with_capacity(path.len());
        for c in path.chars() {
            if escaped_char {
                token.push(c);
                escaped_char = false;
            } else {
                // Parse the
                match c {
                    '&' => {
                        // The next character is escaped and part of the token
                        escaped_char = true;
                    }
                    '/' | '.' | '<' => {
                        // We have reached the start of a token and need to process the previous one
                        if !token.is_empty() {
                            if elements.len() == Self::MAX_ELEMENTS {
                                break;
                            }
                            elements.push(RelativePathElement::from_str(&token, node_resolver)?);
                            token.clear();
                        }
                    }
                    _ => {}
                }
                token.push(c);
            }
            if token.len() > Self::MAX_TOKEN_LEN {
                error!("Path segment seems unusually long and has been rejected");
                return Err(());
            }
        }

        if !token.is_empty() {
            if elements.len() == Self::MAX_ELEMENTS {
                error!("Number of elements in relative path is too long, rejecting it");
                return Err(());
            }
            elements.push(RelativePathElement::from_str(&token, node_resolver)?);
        }

        Ok(RelativePath {
            elements: Some(elements),
        })
    }
}

impl<'a> From<&'a RelativePathElement> for String {
    fn from(element: &'a RelativePathElement) -> String {
        let mut result = element
            .relative_path_reference_type(&RelativePathElement::default_browse_name_resolver);
        if !element.target_name.name.is_null() {
            let always_use_namespace = true;
            let target_browse_name = escape_browse_name(element.target_name.name.as_ref());
            if always_use_namespace || element.target_name.namespace_index > 0 {
                result.push_str(&format!(
                    "{}:{}",
                    element.target_name.namespace_index, target_browse_name
                ));
            } else {
                result.push_str(&target_browse_name);
            }
        }
        result
    }
}

impl RelativePathElement {
    /// This is the default node resolver that attempts to resolve a browse name onto a
    /// reference type id. The default implementation resides in the types module so it
    /// doesn't have access to the address space.
    ///
    /// Therefore it makes a best guess by testing the browse name against the standard reference
    /// types and if fails to match it will produce a node id from the namespace and browse name.
    pub fn default_node_resolver(namespace: u16, browse_name: &str) -> Option<NodeId> {
        let node_id = if namespace == 0 {
            match browse_name {
                "References" => ReferenceTypeId::References.into(),
                "NonHierarchicalReferences" => ReferenceTypeId::NonHierarchicalReferences.into(),
                "HierarchicalReferences" => ReferenceTypeId::HierarchicalReferences.into(),
                "HasChild" => ReferenceTypeId::HasChild.into(),
                "Organizes" => ReferenceTypeId::Organizes.into(),
                "HasEventSource" => ReferenceTypeId::HasEventSource.into(),
                "HasModellingRule" => ReferenceTypeId::HasModellingRule.into(),
                "HasEncoding" => ReferenceTypeId::HasEncoding.into(),
                "HasDescription" => ReferenceTypeId::HasDescription.into(),
                "HasTypeDefinition" => ReferenceTypeId::HasTypeDefinition.into(),
                "GeneratesEvent" => ReferenceTypeId::GeneratesEvent.into(),
                "Aggregates" => ReferenceTypeId::Aggregates.into(),
                "HasSubtype" => ReferenceTypeId::HasSubtype.into(),
                "HasProperty" => ReferenceTypeId::HasProperty.into(),
                "HasComponent" => ReferenceTypeId::HasComponent.into(),
                "HasNotifier" => ReferenceTypeId::HasNotifier.into(),
                "HasOrderedComponent" => ReferenceTypeId::HasOrderedComponent.into(),
                "FromState" => ReferenceTypeId::FromState.into(),
                "ToState" => ReferenceTypeId::ToState.into(),
                "HasCause" => ReferenceTypeId::HasCause.into(),
                "HasEffect" => ReferenceTypeId::HasEffect.into(),
                "HasHistoricalConfiguration" => ReferenceTypeId::HasHistoricalConfiguration.into(),
                "HasSubStateMachine" => ReferenceTypeId::HasSubStateMachine.into(),
                "AlwaysGeneratesEvent" => ReferenceTypeId::AlwaysGeneratesEvent.into(),
                "HasTrueSubState" => ReferenceTypeId::HasTrueSubState.into(),
                "HasFalseSubState" => ReferenceTypeId::HasFalseSubState.into(),
                "HasCondition" => ReferenceTypeId::HasCondition.into(),
                _ => NodeId::new(0, UAString::from(browse_name)),
            }
        } else {
            NodeId::new(namespace, UAString::from(browse_name))
        };
        Some(node_id)
    }

    fn id_from_reference_type(id: u32) -> Option<String> {
        // This syntax is horrible - it casts the u32 into an enum if it can
        Some(
            match id {
                id if id == ReferenceTypeId::References as u32 => "References",
                id if id == ReferenceTypeId::NonHierarchicalReferences as u32 => {
                    "NonHierarchicalReferences"
                }
                id if id == ReferenceTypeId::HierarchicalReferences as u32 => {
                    "HierarchicalReferences"
                }
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
                id if id == ReferenceTypeId::HasHistoricalConfiguration as u32 => {
                    "HasHistoricalConfiguration"
                }
                id if id == ReferenceTypeId::HasSubStateMachine as u32 => "HasSubStateMachine",
                id if id == ReferenceTypeId::AlwaysGeneratesEvent as u32 => "AlwaysGeneratesEvent",
                id if id == ReferenceTypeId::HasTrueSubState as u32 => "HasTrueSubState",
                id if id == ReferenceTypeId::HasFalseSubState as u32 => "HasFalseSubState",
                id if id == ReferenceTypeId::HasCondition as u32 => "HasCondition",
                _ => return None,
            }
            .to_string(),
        )
    }

    pub fn default_browse_name_resolver(node_id: &NodeId) -> Option<String> {
        match &node_id.identifier {
            Identifier::String(browse_name) => Some(browse_name.as_ref().to_string()),
            Identifier::Numeric(id) => {
                if node_id.namespace == 0 {
                    Self::id_from_reference_type(*id)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Parse a relative path element according to the OPC UA Part 4 Appendix A BNF
    ///
    /// `<relative-path> ::= <reference-type> <browse-name> [relative-path]`
    /// `<reference-type> ::= '/' | '.' | '<' ['#'] ['!'] <browse-name> '>'`
    /// `<browse-name> ::= [<namespace-index> ':'] <name>`
    /// `<namespace-index> ::= <digit> [<digit>]`
    /// `<digit> ::= '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'`
    /// `<name> ::= (<name-char> | '&' <reserved-char>) [<name>]`
    /// `<reserved-char> ::= '/' | '.' | '<' | '>' | ':' | '#' | '!' | '&'`
    /// `<name-char> ::= All valid characters for a String (see Part 3) excluding reserved-chars.`
    ///
    /// # Examples
    ///
    /// * `/foo`
    /// * `/0:foo`
    /// * `.bar`
    /// * `<0:HasEncoding>bar`
    /// * `<!NonHierarchicalReferences>foo`
    /// * `<#!2:MyReftype>2:blah`
    ///
    pub fn from_str<CB>(path: &str, node_resolver: &CB) -> Result<RelativePathElement, ()>
    where
        CB: Fn(u16, &str) -> Option<NodeId>,
    {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"(?P<reftype>/|\.|(<(?P<flags>#|!|#!)?((?P<nsidx>[0-9]+):)?(?P<name>[^#!].*)>))(?P<target>.*)").unwrap();
        }

        // NOTE: This could be more safely done with a parser library, e.g. nom.

        if let Some(captures) = RE.captures(path) {
            let target_name = target_name(captures.name("target").unwrap().as_str())?;

            let reference_type = captures.name("reftype").unwrap();
            let (reference_type_id, include_subtypes, is_inverse) = match reference_type.as_str() {
                "/" => (ReferenceTypeId::HierarchicalReferences.into(), true, false),
                "." => (ReferenceTypeId::Aggregates.into(), true, false),
                _ => {
                    let (include_subtypes, is_inverse) = if let Some(flags) = captures.name("flags")
                    {
                        match flags.as_str() {
                            "#" => (false, false),
                            "!" => (true, true),
                            "#!" => (false, true),
                            _ => panic!("Error in regular expression for flags"),
                        }
                    } else {
                        (true, false)
                    };

                    let browse_name = captures.name("name").unwrap().as_str();

                    // Process the token as a reference type
                    let reference_type_id = if let Some(namespace) = captures.name("nsidx") {
                        let namespace = namespace.as_str();
                        if namespace == "0" || namespace.is_empty() {
                            node_resolver(0, browse_name)
                        } else if let Ok(namespace) = namespace.parse::<u16>() {
                            node_resolver(namespace, browse_name)
                        } else {
                            error!("Namespace {} is out of range", namespace);
                            return Err(());
                        }
                    } else {
                        node_resolver(0, browse_name)
                    };
                    if reference_type_id.is_none() {
                        error!(
                            "Supplied node resolver was unable to resolve a reference type from {}",
                            path
                        );
                        return Err(());
                    }
                    (reference_type_id.unwrap(), include_subtypes, is_inverse)
                }
            };
            Ok(RelativePathElement {
                reference_type_id,
                is_inverse,
                include_subtypes,
                target_name,
            })
        } else {
            error!("Path {} does not match a relative path", path);
            Err(())
        }
    }

    /// Constructs a string representation of the reference type in the relative path.
    /// This code assumes that the reference type's node id has a string identifier and that
    /// the string identifier is the same as the browse name.
    pub(crate) fn relative_path_reference_type<CB>(&self, browse_name_resolver: &CB) -> String
    where
        CB: Fn(&NodeId) -> Option<String>,
    {
        let browse_name = browse_name_resolver(&self.reference_type_id).unwrap();
        let mut result = String::with_capacity(1024);
        // Common references will come out as '/' or '.'
        if self.include_subtypes && !self.is_inverse {
            if self.reference_type_id == ReferenceTypeId::HierarchicalReferences.into() {
                result.push('/');
            } else if self.reference_type_id == ReferenceTypeId::Aggregates.into() {
                result.push('.');
            }
        };
        // Other kinds of reference are built as a string
        if result.is_empty() {
            result.push('<');
            if !self.include_subtypes {
                result.push('#');
            }
            if self.is_inverse {
                result.push('!');
            }

            let browse_name = escape_browse_name(browse_name.as_ref());
            if self.reference_type_id.namespace != 0 {
                result.push_str(&format!(
                    "{}:{}",
                    self.reference_type_id.namespace, browse_name
                ));
            } else {
                result.push_str(&browse_name);
            }
            result.push('>');
        }

        result
    }
}

impl<'a> From<&'a RelativePath> for String {
    fn from(path: &'a RelativePath) -> String {
        if let Some(ref elements) = path.elements {
            let mut result = String::with_capacity(1024);
            for e in elements.iter() {
                result.push_str(String::from(e).as_ref());
            }
            result
        } else {
            String::new()
        }
    }
}

/// Reserved characters in the browse name which must be escaped with a &
const BROWSE_NAME_RESERVED_CHARS: &str = "&/.<>:#!";

/// Escapes reserved characters in the browse name
fn escape_browse_name(name: &str) -> String {
    let mut result = String::from(name);
    BROWSE_NAME_RESERVED_CHARS.chars().for_each(|c| {
        result = result.replace(c, &format!("&{}", c));
    });
    result
}

/// Unescapes reserved characters in the browse name
fn unescape_browse_name(name: &str) -> String {
    let mut result = String::from(name);
    BROWSE_NAME_RESERVED_CHARS.chars().for_each(|c| {
        result = result.replace(&format!("&{}", c), &c.to_string());
    });
    result
}

/// Parse a target name into a qualified name. The name is either `nsidx:name` or just
/// `name`, where `nsidx` is a numeric index and `name` may contain escaped reserved chars.
///
/// # Examples
///
/// * 0:foo
/// * bar
///
fn target_name(target_name: &str) -> Result<QualifiedName, ()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"((?P<nsidx>[0-9+]):)?(?P<name>.*)").unwrap();
    }
    if let Some(captures) = RE.captures(target_name) {
        let namespace = if let Some(namespace) = captures.name("nsidx") {
            if let Ok(namespace) = namespace.as_str().parse::<u16>() {
                namespace
            } else {
                error!(
                    "Namespace {} for target name is out of range",
                    namespace.as_str()
                );
                return Err(());
            }
        } else {
            0
        };
        let name = if let Some(name) = captures.name("name") {
            let name = name.as_str();
            if name.is_empty() {
                UAString::null()
            } else {
                UAString::from(unescape_browse_name(name))
            }
        } else {
            UAString::null()
        };
        Ok(QualifiedName::new(namespace, name))
    } else {
        Ok(QualifiedName::null())
    }
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
    ]
    .iter()
    .for_each(|n| {
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
    use crate::types::qualified_name::QualifiedName;

    [
        (
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(0, "foo1"),
            },
            "/0:foo1",
        ),
        (
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(0, ".foo2"),
            },
            "/0:&.foo2",
        ),
        (
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: true,
                include_subtypes: true,
                target_name: QualifiedName::new(2, "foo3"),
            },
            "<!HierarchicalReferences>2:foo3",
        ),
        (
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: true,
                include_subtypes: false,
                target_name: QualifiedName::new(0, "foo4"),
            },
            "<#!HierarchicalReferences>0:foo4",
        ),
        (
            RelativePathElement {
                reference_type_id: ReferenceTypeId::Aggregates.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(0, "foo5"),
            },
            ".0:foo5",
        ),
        (
            RelativePathElement {
                reference_type_id: ReferenceTypeId::HasHistoricalConfiguration.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(0, "foo6"),
            },
            "<HasHistoricalConfiguration>0:foo6",
        ),
    ]
    .iter()
    .for_each(|n| {
        let element = &n.0;
        let expected = n.1.to_string();

        // Compare string to expected
        let actual = String::from(element);
        assert_eq!(expected, actual);

        // Turn string back to element, compare to original element
        let actual =
            RelativePathElement::from_str(&actual, &RelativePathElement::default_node_resolver)
                .unwrap();
        assert_eq!(*element, actual);
    });
}

/// Test that the given entire relative path, that it can be converted to/from a string
/// and a RelativePath type.
#[test]
fn test_relative_path() {
    use crate::types::qualified_name::QualifiedName;

    // Samples are from OPC UA Part 4 Appendix A
    let tests = vec![
        (
            vec![RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(2, "Block.Output"),
            }],
            "/2:Block&.Output",
        ),
        (
            vec![
                RelativePathElement {
                    reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(3, "Truck"),
                },
                RelativePathElement {
                    reference_type_id: ReferenceTypeId::Aggregates.into(),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(0, "NodeVersion"),
                },
            ],
            "/3:Truck.0:NodeVersion",
        ),
        (
            vec![
                RelativePathElement {
                    reference_type_id: NodeId::new(1, "ConnectedTo"),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(1, "Boiler"),
                },
                RelativePathElement {
                    reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(1, "HeatSensor"),
                },
            ],
            "<1:ConnectedTo>1:Boiler/1:HeatSensor",
        ),
        (
            vec![
                RelativePathElement {
                    reference_type_id: NodeId::new(1, "ConnectedTo"),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(1, "Boiler"),
                },
                RelativePathElement {
                    reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::null(),
                },
            ],
            "<1:ConnectedTo>1:Boiler/",
        ),
        (
            vec![RelativePathElement {
                reference_type_id: ReferenceTypeId::HasChild.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(2, "Wheel"),
            }],
            "<HasChild>2:Wheel",
        ),
        (
            vec![RelativePathElement {
                reference_type_id: ReferenceTypeId::HasChild.into(),
                is_inverse: true,
                include_subtypes: true,
                target_name: QualifiedName::new(0, "Truck"),
            }],
            "<!HasChild>0:Truck",
        ),
        (
            vec![RelativePathElement {
                reference_type_id: ReferenceTypeId::HasChild.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::null(),
            }],
            "<HasChild>",
        ),
    ];

    tests.into_iter().for_each(|n| {
        let relative_path = RelativePath {
            elements: Some(n.0),
        };
        let expected = n.1.to_string();

        // Convert path to string, compare to expected
        let actual = String::from(&relative_path);
        assert_eq!(expected, actual);

        // Turn string back to element, compare to original path
        let actual =
            RelativePath::from_str(&actual, &RelativePathElement::default_node_resolver).unwrap();
        assert_eq!(relative_path, actual);
    });
}
