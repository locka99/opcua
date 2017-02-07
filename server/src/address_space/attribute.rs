use opcua_core::types::*;
use opcua_core::services::*;

// Attributes as defined in Part 4, Figure B.7

// Attributes sometimes required and sometimes optional

// Write mask bits

/// Indicates if the AccessLevel Attribute is writable.
pub const WRITE_MASK_ACCESS_LEVEL: UInt32 = 1 << 0;
/// Indicates if the ArrayDimensions Attribute is writable.
pub const WRITE_MASK_ARRAY_DIMENSTIONS: UInt32 = 1 << 1;
///Indicates if the BrowseName Attribute is writable.
pub const WRITE_MASK_BROWSE_NAME: UInt32 = 1 << 2;
/// Indicates if the ContainsNoLoops Attribute is writable.
pub const WRITE_MASK_CONTAINS_NO_LOOPS: UInt32 = 1 << 3;
/// Indicates if the DataType Attribute is writable.
pub const WRITE_MASK_DATA_TYPE: UInt32 = 1 << 4;
/// Indicates if the Description Attribute is writable.
pub const WRITE_MASK_DESCRIPTION: UInt32 = 1 << 5;
/// Indicates if the DisplayName Attribute is writable.
pub const WRITE_MASK_DISPLAY_NAME: UInt32 = 1 << 6;
/// Indicates if the EventNotifier Attribute is writable.
pub const WRITE_MASK_EVENT_NOTIFIER: UInt32 = 1 << 7;
/// Indicates if the Executable Attribute is writable.
pub const WRITE_MASK_EXECUTABLE: UInt32 = 1 << 8;
/// Indicates if the Historizing Attribute is writable.
pub const WRITE_MASK_HISTORIZING: UInt32 = 1 << 9;
/// Indicates if the InverseName Attribute is writable.
pub const WRITE_MASK_INVERSE_NAME: UInt32 = 1 << 10;
/// Indicates if the IsAbstract Attribute is writable.
pub const WRITE_MASK_IS_ABSTRACT: UInt32 = 1 << 11;
/// Indicates if the MinimumSamplingInterval Attribute is writable.
pub const WRITE_MASK_MINIMUM_SAMPLING_INTERVAL: UInt32 = 1 << 12;
/// Indicates if the NodeClass Attribute is writable.
pub const WRITE_MASK_NODE_CLASS: UInt32 = 1 << 13;
/// Indicates if the NodeId Attribute is writable.
pub const WRITE_MASK_NODE_ID: UInt32 = 1 << 14;
/// Indicates if the Symmetric Attribute is writable.
pub const WRITE_MASK_SYMMETRIC: UInt32 = 1 << 15;
/// Indicates if the UserAccessLevel Attribute is writable.
pub const WRITE_MASK_USER_ACCESS_LEVEL: UInt32 = 1 << 16;
/// Indicates if the UserExecutable Attribute is writable.
pub const WRITE_MASK_USER_EXECUTABLE: UInt32 = 1 << 17;
/// Indicates if the UserWriteMask Attribute is writable.
pub const WRITE_MASK_USER_WRITE_MASK: UInt32 = 1 << 18;
/// Indicates if the ValueRank Attribute is writable.
pub const WRITE_MASK_VALUE_RANK: UInt32 = 1 << 19;
/// Indicates if the WriteMask Attribute is writable.
pub const WRITE_MASK_WRITE_MASK: UInt32 = 1 << 20;
/// Indicates if the Value Attribute is writable for a VariableType. It does not apply for Variables
/// since this is handled by the AccessLevel and UserAccessLevel Attributes for the Variable.
/// For Variables this bit shall be set to 0.
pub const WRITE_MASK_VALUE_FOR_VARIABLE_TYPE: UInt32 = 1 << 21;

#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    NodeId(NodeId),
    NodeClass(NodeClass),
    BrowseName(QualifiedName),
    DisplayName(LocalizedText),
    Description(LocalizedText),
    WriteMask(UInt32),
    UserWriteMask(UInt32),
    IsAbstract(Boolean),
    Symmetric(Boolean),
    InverseName(LocalizedText),
    ContainsNoLoops(Boolean),
    EventNotifier(Boolean),
    Value(DataValue),
    DataType(NodeId),
    ValueRank(Int32),
    ArrayDimensions(Vec<Int32>),
    AccessLevel(Byte),
    UserAccessLevel(Byte),
    MinimumSamplingInterval(Int32),
    Historizing(Boolean),
    Executable(Boolean),
    UserExecutable(Boolean),
}

impl AttributeValue {
    pub fn attribute_id(&self) -> AttributeId {
        match self {
            &AttributeValue::NodeId(_) => AttributeId::NodeId,
            &AttributeValue::NodeClass(_) => AttributeId::NodeClass,
            &AttributeValue::BrowseName(_) => AttributeId::BrowseName,
            &AttributeValue::DisplayName(_) => AttributeId::DisplayName,
            &AttributeValue::Description(_) => AttributeId::Description,
            &AttributeValue::WriteMask(_) => AttributeId::WriteMask,
            &AttributeValue::UserWriteMask(_) => AttributeId::UserWriteMask,
            &AttributeValue::IsAbstract(_) => AttributeId::IsAbstract,
            &AttributeValue::Symmetric(_) => AttributeId::Symmetric,
            &AttributeValue::InverseName(_) => AttributeId::InverseName,
            &AttributeValue::ContainsNoLoops(_) => AttributeId::ContainsNoLoops,
            &AttributeValue::EventNotifier(_) => AttributeId::EventNotifier,
            &AttributeValue::Value(_) => AttributeId::Value,
            &AttributeValue::DataType(_) => AttributeId::DataType,
            &AttributeValue::ValueRank(_) => AttributeId::ValueRank,
            &AttributeValue::ArrayDimensions(_) => AttributeId::ArrayDimensions,
            &AttributeValue::AccessLevel(_) => AttributeId::AccessLevel,
            &AttributeValue::UserAccessLevel(_) => AttributeId::UserAccessLevel,
            &AttributeValue::MinimumSamplingInterval(_) => AttributeId::MinimumSamplingInterval,
            &AttributeValue::Historizing(_) => AttributeId::Historizing,
            &AttributeValue::Executable(_) => AttributeId::Executable,
            &AttributeValue::UserExecutable(_) => AttributeId::UserExecutable,
        }
    }

    pub fn to_variant(&self) -> Variant {
        match self {
            &AttributeValue::NodeId(ref value) => Variant::NodeId(value.clone()),
            &AttributeValue::NodeClass(ref value) => Variant::Int32(*value as Int32),
            &AttributeValue::BrowseName(ref value) => Variant::QualifiedName(value.clone()),
            &AttributeValue::DisplayName(ref value) => Variant::LocalizedText(value.clone()),
            &AttributeValue::Description(ref value) => Variant::LocalizedText(value.clone()),
            &AttributeValue::WriteMask(ref value) => Variant::UInt32(*value),
            &AttributeValue::UserWriteMask(ref value) => Variant::UInt32(*value),
            &AttributeValue::IsAbstract(ref value) => Variant::Boolean(*value),
            &AttributeValue::Symmetric(ref value) => Variant::Boolean(*value),
            &AttributeValue::InverseName(ref value) => Variant::LocalizedText(value.clone()),
            &AttributeValue::ContainsNoLoops(ref value) => Variant::Boolean(*value),
            &AttributeValue::EventNotifier(ref value) => Variant::Boolean(*value),
            &AttributeValue::Value(ref value) => Variant::DataValue(value.clone()),
            &AttributeValue::DataType(ref value) => Variant::NodeId(value.clone()),
            &AttributeValue::ValueRank(ref value) => Variant::Int32(*value),
            &AttributeValue::ArrayDimensions(ref value) => {
                let mut dimensions = Vec::with_capacity(value.len());
                for d in value {
                    dimensions.push(Variant::Int32(*d));
                }
                Variant::Array(dimensions)
            }
            &AttributeValue::AccessLevel(ref value) => Variant::Byte(*value),
            &AttributeValue::UserAccessLevel(ref value) => Variant::Byte(*value),
            &AttributeValue::MinimumSamplingInterval(ref value) => Variant::Int32(*value),
            &AttributeValue::Historizing(ref value) => Variant::Boolean(*value),
            &AttributeValue::Executable(ref value) => Variant::Boolean(*value),
            &AttributeValue::UserExecutable(ref value) => Variant::Boolean(*value),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AttributeId {
    NodeId = 1,
    NodeClass = 2,
    BrowseName = 3,
    DisplayName = 4,
    Description = 5,
    WriteMask = 6,
    UserWriteMask = 7,
    IsAbstract = 8,
    Symmetric = 9,
    InverseName = 10,
    ContainsNoLoops = 11,
    EventNotifier = 12,
    Value = 13,
    DataType = 14,
    ValueRank = 15,
    ArrayDimensions = 16,
    AccessLevel = 17,
    UserAccessLevel = 18,
    MinimumSamplingInterval = 19,
    Historizing = 20,
    Executable = 21,
    UserExecutable = 22,
}

impl AttributeId {
    pub fn from_u32(attribute_id: UInt32) -> Result<AttributeId, ()> {
        let attribute_id = match attribute_id {
            1 => AttributeId::NodeId,
            2 => AttributeId::NodeClass,
            3 => AttributeId::BrowseName,
            4 => AttributeId::DisplayName,
            5 => AttributeId::Description,
            6 => AttributeId::WriteMask,
            7 => AttributeId::UserWriteMask,
            8 => AttributeId::IsAbstract,
            9 => AttributeId::Symmetric,
            10 => AttributeId::InverseName,
            11 => AttributeId::ContainsNoLoops,
            12 => AttributeId::EventNotifier,
            13 => AttributeId::Value,
            14 => AttributeId::DataType,
            15 => AttributeId::ValueRank,
            16 => AttributeId::ArrayDimensions,
            17 => AttributeId::AccessLevel,
            18 => AttributeId::UserAccessLevel,
            19 => AttributeId::MinimumSamplingInterval,
            20 => AttributeId::Historizing,
            21 => AttributeId::Executable,
            22 => AttributeId::UserExecutable,
            _ => {
                debug!("Invalid attribute id {}", attribute_id);
                return Err(());
            }
        };
        Ok(attribute_id)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub id: AttributeId,
    pub value: AttributeValue,
    pub server_timestamp: DateTime,
    pub server_picoseconds: Int16,
    pub source_timestamp: DateTime,
    pub source_picoseconds: Int16,
}
