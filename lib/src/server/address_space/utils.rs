use crate::{
    server::node_manager::{ParsedReadValueId, RequestContext, TypeTree},
    types::{
        AttributeId, DataTypeId, DataValue, NumericRange, QualifiedName, StatusCode,
        TimestampsToReturn, Variant, WriteMask, WriteValue,
    },
};

use super::{HasNodeId, NodeType, UserAccessLevel, Variable};

pub fn is_readable(
    context: &RequestContext,
    node: &NodeType,
    attribute_id: AttributeId,
) -> Result<(), StatusCode> {
    if !user_access_level(context, node, attribute_id).contains(UserAccessLevel::CURRENT_READ) {
        Err(StatusCode::BadUserAccessDenied)
    } else {
        Ok(())
    }
}

pub fn is_writable(
    context: &RequestContext,
    node: &NodeType,
    attribute_id: AttributeId,
) -> Result<(), StatusCode> {
    if let (NodeType::Variable(_), AttributeId::Value) = (node, attribute_id) {
        if !user_access_level(context, node, attribute_id).contains(UserAccessLevel::CURRENT_WRITE)
        {
            return Err(StatusCode::BadUserAccessDenied);
        }

        Ok(())
    } else {
        let mask_value = match attribute_id {
            // The default address space does not support modifying node class or node id,
            // Custom node managers are allowed to.
            AttributeId::BrowseName => WriteMask::BROWSE_NAME,
            AttributeId::DisplayName => WriteMask::DISPLAY_NAME,
            AttributeId::Description => WriteMask::DESCRIPTION,
            AttributeId::WriteMask => WriteMask::WRITE_MASK,
            AttributeId::UserWriteMask => WriteMask::USER_WRITE_MASK,
            AttributeId::IsAbstract => WriteMask::IS_ABSTRACT,
            AttributeId::Symmetric => WriteMask::SYMMETRIC,
            AttributeId::InverseName => WriteMask::INVERSE_NAME,
            AttributeId::ContainsNoLoops => WriteMask::CONTAINS_NO_LOOPS,
            AttributeId::EventNotifier => WriteMask::EVENT_NOTIFIER,
            AttributeId::Value => WriteMask::VALUE_FOR_VARIABLE_TYPE,
            AttributeId::DataType => WriteMask::DATA_TYPE,
            AttributeId::ValueRank => WriteMask::VALUE_RANK,
            AttributeId::ArrayDimensions => WriteMask::ARRAY_DIMENSIONS,
            AttributeId::AccessLevel => WriteMask::ACCESS_LEVEL,
            AttributeId::UserAccessLevel => WriteMask::USER_ACCESS_LEVEL,
            AttributeId::MinimumSamplingInterval => WriteMask::MINIMUM_SAMPLING_INTERVAL,
            AttributeId::Historizing => WriteMask::HISTORIZING,
            AttributeId::Executable => WriteMask::EXECUTABLE,
            AttributeId::UserExecutable => WriteMask::USER_EXECUTABLE,
            AttributeId::DataTypeDefinition => WriteMask::DATA_TYPE_DEFINITION,
            AttributeId::RolePermissions => WriteMask::ROLE_PERMISSIONS,
            AttributeId::AccessRestrictions => WriteMask::ACCESS_RESTRICTIONS,
            AttributeId::AccessLevelEx => WriteMask::ACCESS_LEVEL_EX,
            _ => return Err(StatusCode::BadNotWritable),
        };

        let write_mask = node.as_node().write_mask();
        if write_mask.is_none() || write_mask.is_some_and(|wm| !wm.contains(mask_value)) {
            return Err(StatusCode::BadNotWritable);
        }
        Ok(())
    }
}

pub fn user_access_level(
    context: &RequestContext,
    node: &NodeType,
    attribute_id: AttributeId,
) -> UserAccessLevel {
    let user_access_level = if let NodeType::Variable(ref node) = node {
        node.user_access_level()
    } else {
        UserAccessLevel::CURRENT_READ
    };
    context.authenticator.effective_user_access_level(
        &context.token,
        user_access_level,
        &node.node_id(),
        attribute_id,
    )
}

pub fn validate_node_read(
    node: &NodeType,
    context: &RequestContext,
    node_to_read: &ParsedReadValueId,
) -> Result<(), StatusCode> {
    is_readable(context, node, node_to_read.attribute_id)?;

    if node_to_read.attribute_id != AttributeId::Value
        && node_to_read.index_range != NumericRange::None
    {
        return Err(StatusCode::BadIndexRangeDataMismatch);
    }

    if !is_supported_data_encoding(&node_to_read.data_encoding) {
        debug!(
            "read_node_value result for read node id {}, attribute {:?} is invalid data encoding",
            node_to_read.node_id, node_to_read.attribute_id
        );
        return Err(StatusCode::BadDataEncodingInvalid);
    }

    Ok(())
}

pub fn validate_value_to_write(
    variable: &Variable,
    value: &Variant,
    type_tree: &TypeTree,
) -> Result<(), StatusCode> {
    let value_rank = variable.value_rank();
    let node_data_type = variable.data_type();

    if matches!(value, Variant::Empty) {
        return Ok(());
    }

    if let Some(value_data_type) = value.scalar_data_type() {
        // Value is scalar, check if the data type matches
        let data_type_matches = type_tree.is_subtype_of(&value_data_type, &node_data_type);
        if !data_type_matches {
            // Check if the value to write is a byte string and the receiving node type a byte array.
            // This code is a mess just for some weird edge case in the spec that a write from
            // a byte string to a byte array should succeed
            match value {
                Variant::ByteString(_) => {
                    if node_data_type == DataTypeId::Byte.into() {
                        match value_rank {
                            -2 | -3 | 1 => Ok(()),
                            _ => Err(StatusCode::BadTypeMismatch),
                        }
                    } else {
                        Err(StatusCode::BadTypeMismatch)
                    }
                }
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    } else if let Some(value_data_type) = value.array_data_type() {
        // TODO check that value is array of same dimensions
        if !type_tree.is_subtype_of(&value_data_type, &node_data_type) {
            return Err(StatusCode::BadTypeMismatch);
        }
        Ok(())
    } else {
        Err(StatusCode::BadTypeMismatch)
    }
}

pub fn validate_node_write(
    node: &NodeType,
    context: &RequestContext,
    node_to_write: &WriteValue,
    type_tree: &TypeTree,
) -> Result<(AttributeId, NumericRange), StatusCode> {
    let Ok(attribute_id) = AttributeId::from_u32(node_to_write.attribute_id) else {
        debug!(
            "read_node_value result for write node id {}, attribute {} is invalid",
            node_to_write.node_id, node_to_write.attribute_id
        );
        return Err(StatusCode::BadAttributeIdInvalid);
    };

    let Ok(index_range) = node_to_write.index_range.as_ref().parse::<NumericRange>() else {
        return Err(StatusCode::BadIndexRangeInvalid);
    };

    is_writable(context, node, attribute_id)?;

    if attribute_id != AttributeId::Value && index_range.has_range() {
        return Err(StatusCode::BadWriteNotSupported);
    }

    let Some(value) = node_to_write.value.value.as_ref() else {
        return Err(StatusCode::BadTypeMismatch);
    };

    // TODO: We should do type validation for every attribute, not just value.
    if let (NodeType::Variable(var), AttributeId::Value) = (node, attribute_id) {
        validate_value_to_write(var, &value, type_tree)?;
    }

    Ok((attribute_id, index_range))
}

pub fn is_supported_data_encoding(data_encoding: &QualifiedName) -> bool {
    if data_encoding.is_null() {
        true
    } else {
        data_encoding.namespace_index == 0 && data_encoding.name.eq("Default Binary")
    }
}

pub fn read_node_value(
    node: &NodeType,
    context: &RequestContext,
    node_to_read: &ParsedReadValueId,
    max_age: f64,
    timestamps_to_return: TimestampsToReturn,
) -> DataValue {
    let mut result_value = DataValue::null();

    let Some(attribute) = node.as_node().get_attribute_max_age(
        timestamps_to_return,
        node_to_read.attribute_id,
        node_to_read.index_range.clone(),
        &node_to_read.data_encoding,
        max_age,
    ) else {
        result_value.status = Some(StatusCode::BadAttributeIdInvalid);
        return result_value;
    };

    let value = if node_to_read.attribute_id == AttributeId::UserAccessLevel {
        match attribute.value {
            Some(Variant::Byte(val)) => {
                let access_level = UserAccessLevel::from_bits_truncate(val);
                let access_level = context.authenticator.effective_user_access_level(
                    &context.token,
                    access_level,
                    &node.node_id(),
                    node_to_read.attribute_id,
                );
                Some(Variant::from(access_level.bits()))
            }
            Some(v) => Some(v),
            _ => None,
        }
    } else {
        attribute.value
    };

    let value = if node_to_read.attribute_id == AttributeId::UserExecutable {
        match value {
            Some(Variant::Boolean(val)) => Some(Variant::from(
                val && context
                    .authenticator
                    .is_user_executable(&context.token, &node.node_id()),
            )),
            r => r,
        }
    } else {
        value
    };

    result_value.value = value;
    result_value.status = attribute.status;
    if matches!(node, NodeType::Variable(_)) && node_to_read.attribute_id == AttributeId::Value {
        match timestamps_to_return {
            TimestampsToReturn::Source => {
                result_value.source_timestamp = attribute.source_timestamp;
                result_value.source_picoseconds = attribute.source_picoseconds;
            }
            TimestampsToReturn::Server => {
                result_value.server_timestamp = attribute.server_timestamp;
                result_value.server_picoseconds = attribute.server_picoseconds;
            }
            TimestampsToReturn::Both => {
                result_value.source_timestamp = attribute.source_timestamp;
                result_value.source_picoseconds = attribute.source_picoseconds;
                result_value.server_timestamp = attribute.server_timestamp;
                result_value.server_picoseconds = attribute.server_picoseconds;
            }
            TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                // Nothing needs to change
            }
        }
    }
    result_value
}
