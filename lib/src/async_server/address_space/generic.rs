use crate::{
    async_server::node_manager::AddNodeAttributes,
    server::prelude::{
        AttributeId, DataValue, DateTime, NodeClass, NodeId, QualifiedName, StatusCode,
    },
};

use super::{
    base::Base, DataType, EventNotifier, Method, NodeType, Object, ObjectType, ReferenceType,
    Variable, VariableType, View,
};

const fn mask(attribute: AttributeId) -> u32 {
    match attribute {
        AttributeId::AccessLevel => 0,
        AttributeId::ArrayDimensions => 1,
        AttributeId::ContainsNoLoops => 3,
        AttributeId::DataType => 4,
        AttributeId::Description => 5,
        AttributeId::DisplayName => 6,
        AttributeId::EventNotifier => 7,
        AttributeId::Executable => 8,
        AttributeId::Historizing => 9,
        AttributeId::InverseName => 10,
        AttributeId::IsAbstract => 11,
        AttributeId::MinimumSamplingInterval => 12,
        AttributeId::Symmetric => 15,
        AttributeId::UserAccessLevel => 16,
        AttributeId::UserExecutable => 17,
        AttributeId::UserWriteMask => 18,
        AttributeId::ValueRank => 19,
        AttributeId::WriteMask => 20,
        AttributeId::Value => 21,
        _ => 31,
    }
}

macro_rules! masked_or_default {
    ($attr:expr, $attrs:expr, $field:ident) => {
        if (1 << mask($attr)) & $attrs.specified_attributes != 0 {
            $attrs.$field
        } else {
            Default::default()
        }
    };
}

macro_rules! masked_or_default_opt {
    ($attr:expr, $attrs:expr, $field:ident) => {
        if (1 << mask($attr)) & $attrs.specified_attributes != 0 {
            Some($attrs.$field)
        } else {
            Default::default()
        }
    };
}

macro_rules! base {
    ($attrs:expr, $node_id:expr, $node_class:expr, $browse_name:expr) => {
        Base {
            node_id: $node_id,
            node_class: $node_class,
            browse_name: $browse_name,
            display_name: masked_or_default!(AttributeId::DisplayName, $attrs, display_name),
            description: masked_or_default_opt!(AttributeId::Description, $attrs, description),
            write_mask: masked_or_default_opt!(AttributeId::WriteMask, $attrs, write_mask),
            user_write_mask: masked_or_default_opt!(
                AttributeId::UserWriteMask,
                $attrs,
                user_write_mask
            ),
        }
    };
}

pub fn new_node_from_attributes(
    node_id: NodeId,
    browse_name: QualifiedName,
    node_class: NodeClass,
    node_attributes: AddNodeAttributes,
) -> Result<NodeType, StatusCode> {
    let now = DateTime::now();
    let r = match node_attributes {
        AddNodeAttributes::Object(a) => NodeType::Object(Box::new(Object {
            base: base!(a, node_id, node_class, browse_name),
            event_notifier: if (1 << mask(AttributeId::EventNotifier)) & a.specified_attributes != 0
            {
                EventNotifier::from_bits(a.event_notifier)
                    .ok_or_else(|| StatusCode::BadNodeAttributesInvalid)?
            } else {
                EventNotifier::empty()
            },
        })),
        AddNodeAttributes::Variable(a) => NodeType::Variable(Box::new(Variable {
            base: base!(a, node_id, node_class, browse_name),
            data_type: masked_or_default!(AttributeId::DataType, a, data_type),
            historizing: masked_or_default!(AttributeId::Historizing, a, historizing),
            value_rank: masked_or_default!(AttributeId::ValueRank, a, value_rank),
            value: if (1 << mask(AttributeId::Value)) & a.specified_attributes != 0 {
                DataValue {
                    source_timestamp: Some(now),
                    server_timestamp: Some(now),
                    value: Some(a.value),
                    status: Some(StatusCode::Good),
                    ..Default::default()
                }
            } else {
                DataValue::default()
            },
            access_level: masked_or_default!(AttributeId::AccessLevel, a, access_level),
            user_access_level: masked_or_default!(
                AttributeId::UserAccessLevel,
                a,
                user_access_level
            ),
            array_dimensions: masked_or_default!(AttributeId::ArrayDimensions, a, array_dimensions),
            minimum_sampling_interval: masked_or_default_opt!(
                AttributeId::MinimumSamplingInterval,
                a,
                minimum_sampling_interval
            ),
        })),
        AddNodeAttributes::Method(a) => NodeType::Method(Box::new(Method {
            base: base!(a, node_id, node_class, browse_name),
            executable: masked_or_default!(AttributeId::Executable, a, executable),
            user_executable: masked_or_default!(AttributeId::UserExecutable, a, user_executable),
        })),
        AddNodeAttributes::ObjectType(a) => NodeType::ObjectType(Box::new(ObjectType {
            base: base!(a, node_id, node_class, browse_name),
            is_abstract: masked_or_default!(AttributeId::IsAbstract, a, is_abstract),
        })),
        AddNodeAttributes::VariableType(a) => NodeType::VariableType(Box::new(VariableType {
            base: base!(a, node_id, node_class, browse_name),
            data_type: masked_or_default!(AttributeId::DataType, a, data_type),
            is_abstract: masked_or_default!(AttributeId::IsAbstract, a, is_abstract),
            value_rank: masked_or_default!(AttributeId::ValueRank, a, value_rank),
            value: if (1 << mask(AttributeId::Value)) & a.specified_attributes != 0 {
                Some(DataValue {
                    source_timestamp: Some(now),
                    server_timestamp: Some(now),
                    value: Some(a.value),
                    status: Some(StatusCode::Good),
                    ..Default::default()
                })
            } else {
                None
            },
            array_dimensions: masked_or_default!(AttributeId::ArrayDimensions, a, array_dimensions),
        })),
        AddNodeAttributes::ReferenceType(a) => NodeType::ReferenceType(Box::new(ReferenceType {
            base: base!(a, node_id, node_class, browse_name),
            symmetric: masked_or_default!(AttributeId::Symmetric, a, symmetric),
            is_abstract: masked_or_default!(AttributeId::IsAbstract, a, is_abstract),
            inverse_name: masked_or_default_opt!(AttributeId::InverseName, a, inverse_name),
        })),
        AddNodeAttributes::DataType(a) => NodeType::DataType(Box::new(DataType {
            base: base!(a, node_id, node_class, browse_name),
            is_abstract: masked_or_default!(AttributeId::IsAbstract, a, is_abstract),
        })),
        AddNodeAttributes::View(a) => NodeType::View(Box::new(View {
            base: base!(a, node_id, node_class, browse_name),
            event_notifier: if (1 << mask(AttributeId::EventNotifier)) & a.specified_attributes != 0
            {
                EventNotifier::from_bits(a.event_notifier)
                    .ok_or_else(|| StatusCode::BadNodeAttributesInvalid)?
            } else {
                EventNotifier::empty()
            },
            contains_no_loops: masked_or_default!(
                AttributeId::ContainsNoLoops,
                a,
                contains_no_loops
            ),
        })),
        AddNodeAttributes::Generic(a) => {
            let base = base!(a, node_id, node_class, browse_name);
            let mut node = match node_class {
                NodeClass::Unspecified => return Err(StatusCode::BadNodeClassInvalid),
                NodeClass::Object => NodeType::Object(Box::new(Object {
                    base,
                    ..Default::default()
                })),
                NodeClass::Variable => NodeType::Variable(Box::new(Variable {
                    base,
                    ..Default::default()
                })),
                NodeClass::Method => NodeType::Method(Box::new(Method {
                    base,
                    ..Default::default()
                })),
                NodeClass::ObjectType => NodeType::ObjectType(Box::new(ObjectType {
                    base,
                    ..Default::default()
                })),
                NodeClass::VariableType => NodeType::VariableType(Box::new(VariableType {
                    base,
                    ..Default::default()
                })),
                NodeClass::ReferenceType => NodeType::ReferenceType(Box::new(ReferenceType {
                    base,
                    ..Default::default()
                })),
                NodeClass::DataType => NodeType::DataType(Box::new(DataType {
                    base,
                    ..Default::default()
                })),
                NodeClass::View => NodeType::View(Box::new(View {
                    base,
                    ..Default::default()
                })),
            };
            let node_mut = node.as_mut_node();
            for attr in a.attribute_values.into_iter().flatten() {
                let id = AttributeId::from_u32(attr.attribute_id)
                    .map_err(|_| StatusCode::BadAttributeIdInvalid)?;
                node_mut.set_attribute(id, attr.value)?;
            }
            node
        }
        AddNodeAttributes::None => return Err(StatusCode::BadNodeAttributesInvalid),
    };
    Ok(r)
}
