// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use crate::types::{DataTypeId, Identifier, NodeId, StatusCode};

/// The variant type id is the type of the variant but without its payload.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum VariantTypeId {
    // Null / Empty
    Empty,
    // Scalar types
    Boolean,
    SByte,
    Byte,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    String,
    DateTime,
    Guid,
    StatusCode,
    ByteString,
    XmlElement,
    QualifiedName,
    LocalizedText,
    NodeId,
    ExpandedNodeId,
    ExtensionObject,
    Variant,
    DataValue,
    DiagnosticInfo,
    Array,
}

impl TryFrom<&NodeId> for VariantTypeId {
    type Error = ();
    fn try_from(value: &NodeId) -> Result<Self, Self::Error> {
        if value.namespace == 0 {
            if let Identifier::Numeric(type_id) = value.identifier {
                match type_id {
                    type_id if type_id == DataTypeId::Boolean as u32 => Ok(VariantTypeId::Boolean),
                    type_id if type_id == DataTypeId::Byte as u32 => Ok(VariantTypeId::Byte),
                    type_id if type_id == DataTypeId::Int16 as u32 => Ok(VariantTypeId::Int16),
                    type_id if type_id == DataTypeId::UInt16 as u32 => Ok(VariantTypeId::UInt16),
                    type_id if type_id == DataTypeId::Int32 as u32 => Ok(VariantTypeId::Int32),
                    type_id if type_id == DataTypeId::UInt32 as u32 => Ok(VariantTypeId::UInt32),
                    type_id if type_id == DataTypeId::Int64 as u32 => Ok(VariantTypeId::Int64),
                    type_id if type_id == DataTypeId::UInt64 as u32 => Ok(VariantTypeId::UInt64),
                    type_id if type_id == DataTypeId::Float as u32 => Ok(VariantTypeId::Float),
                    type_id if type_id == DataTypeId::Double as u32 => Ok(VariantTypeId::Double),
                    type_id if type_id == DataTypeId::String as u32 => Ok(VariantTypeId::String),
                    type_id if type_id == DataTypeId::DateTime as u32 => {
                        Ok(VariantTypeId::DateTime)
                    }
                    type_id if type_id == DataTypeId::Guid as u32 => Ok(VariantTypeId::Guid),
                    type_id if type_id == DataTypeId::ByteString as u32 => {
                        Ok(VariantTypeId::ByteString)
                    }
                    type_id if type_id == DataTypeId::XmlElement as u32 => {
                        Ok(VariantTypeId::XmlElement)
                    }
                    type_id if type_id == DataTypeId::NodeId as u32 => Ok(VariantTypeId::NodeId),
                    type_id if type_id == DataTypeId::ExpandedNodeId as u32 => {
                        Ok(VariantTypeId::ExpandedNodeId)
                    }
                    type_id if type_id == DataTypeId::XmlElement as u32 => {
                        Ok(VariantTypeId::XmlElement)
                    }
                    type_id if type_id == DataTypeId::StatusCode as u32 => {
                        Ok(VariantTypeId::StatusCode)
                    }
                    type_id if type_id == DataTypeId::QualifiedName as u32 => {
                        Ok(VariantTypeId::QualifiedName)
                    }
                    type_id if type_id == DataTypeId::LocalizedText as u32 => {
                        Ok(VariantTypeId::LocalizedText)
                    }
                    type_id if type_id == DataTypeId::DataValue as u32 => {
                        Ok(VariantTypeId::DataValue)
                    }
                    type_id if type_id == DataTypeId::BaseDataType as u32 => {
                        Ok(VariantTypeId::Variant)
                    }
                    type_id if type_id == DataTypeId::DiagnosticInfo as u32 => {
                        Ok(VariantTypeId::DiagnosticInfo)
                    }
                    _ => Err(()),
                }
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }
}

impl VariantTypeId {
    pub fn encoding_mask(&self) -> u8 {
        match self {
            // Null / Empty
            VariantTypeId::Empty => 0u8,
            // Scalar types
            VariantTypeId::Boolean => EncodingMask::BOOLEAN,
            VariantTypeId::SByte => EncodingMask::SBYTE,
            VariantTypeId::Byte => EncodingMask::BYTE,
            VariantTypeId::Int16 => EncodingMask::INT16,
            VariantTypeId::UInt16 => EncodingMask::UINT16,
            VariantTypeId::Int32 => EncodingMask::INT32,
            VariantTypeId::UInt32 => EncodingMask::UINT32,
            VariantTypeId::Int64 => EncodingMask::INT64,
            VariantTypeId::UInt64 => EncodingMask::UINT64,
            VariantTypeId::Float => EncodingMask::FLOAT,
            VariantTypeId::Double => EncodingMask::DOUBLE,
            VariantTypeId::String => EncodingMask::STRING,
            VariantTypeId::DateTime => EncodingMask::DATE_TIME,
            VariantTypeId::Guid => EncodingMask::GUID,
            VariantTypeId::StatusCode => EncodingMask::STATUS_CODE,
            VariantTypeId::ByteString => EncodingMask::BYTE_STRING,
            VariantTypeId::XmlElement => EncodingMask::XML_ELEMENT,
            VariantTypeId::QualifiedName => EncodingMask::QUALIFIED_NAME,
            VariantTypeId::LocalizedText => EncodingMask::LOCALIZED_TEXT,
            VariantTypeId::NodeId => EncodingMask::NODE_ID,
            VariantTypeId::ExpandedNodeId => EncodingMask::EXPANDED_NODE_ID,
            VariantTypeId::ExtensionObject => EncodingMask::EXTENSION_OBJECT,
            VariantTypeId::Variant => EncodingMask::VARIANT,
            VariantTypeId::DataValue => EncodingMask::DATA_VALUE,
            VariantTypeId::DiagnosticInfo => EncodingMask::DIAGNOSTIC_INFO,
            VariantTypeId::Array => panic!("Type of array is unknown"),
        }
    }

    pub fn from_encoding_mask(encoding_mask: u8) -> Result<Self, StatusCode> {
        match encoding_mask & !EncodingMask::ARRAY_MASK {
            0u8 => Ok(VariantTypeId::Empty),
            EncodingMask::BOOLEAN => Ok(VariantTypeId::Boolean),
            EncodingMask::SBYTE => Ok(VariantTypeId::SByte),
            EncodingMask::BYTE => Ok(VariantTypeId::Byte),
            EncodingMask::INT16 => Ok(VariantTypeId::Int16),
            EncodingMask::UINT16 => Ok(VariantTypeId::UInt16),
            EncodingMask::INT32 => Ok(VariantTypeId::Int32),
            EncodingMask::UINT32 => Ok(VariantTypeId::UInt32),
            EncodingMask::INT64 => Ok(VariantTypeId::Int64),
            EncodingMask::UINT64 => Ok(VariantTypeId::UInt64),
            EncodingMask::FLOAT => Ok(VariantTypeId::Float),
            EncodingMask::DOUBLE => Ok(VariantTypeId::Double),
            EncodingMask::STRING => Ok(VariantTypeId::String),
            EncodingMask::DATE_TIME => Ok(VariantTypeId::DateTime),
            EncodingMask::GUID => Ok(VariantTypeId::Guid),
            EncodingMask::STATUS_CODE => Ok(VariantTypeId::StatusCode),
            EncodingMask::BYTE_STRING => Ok(VariantTypeId::ByteString),
            EncodingMask::XML_ELEMENT => Ok(VariantTypeId::XmlElement),
            EncodingMask::QUALIFIED_NAME => Ok(VariantTypeId::QualifiedName),
            EncodingMask::LOCALIZED_TEXT => Ok(VariantTypeId::LocalizedText),
            EncodingMask::NODE_ID => Ok(VariantTypeId::NodeId),
            EncodingMask::EXPANDED_NODE_ID => Ok(VariantTypeId::ExpandedNodeId),
            EncodingMask::EXTENSION_OBJECT => Ok(VariantTypeId::ExtensionObject),
            EncodingMask::VARIANT => Ok(VariantTypeId::Variant),
            EncodingMask::DATA_VALUE => Ok(VariantTypeId::DataValue),
            EncodingMask::DIAGNOSTIC_INFO => Ok(VariantTypeId::DiagnosticInfo),
            _ => {
                error!("Unrecognized encoding mask");
                Err(StatusCode::BadDecodingError)
            }
        }
    }

    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            VariantTypeId::SByte
                | VariantTypeId::Byte
                | VariantTypeId::Int16
                | VariantTypeId::UInt16
                | VariantTypeId::Int32
                | VariantTypeId::UInt32
                | VariantTypeId::Int64
                | VariantTypeId::UInt64
                | VariantTypeId::Float
                | VariantTypeId::Double
        )
    }

    /// Returns a data precedence rank for scalar types, OPC UA part 4 table 119. This is used
    /// when operators are comparing values of differing types. The type with
    /// the highest precedence dictates how values are converted in order to be compared.
    pub fn precedence(&self) -> u8 {
        match self {
            VariantTypeId::Double => 1,
            VariantTypeId::Float => 2,
            VariantTypeId::Int64 => 3,
            VariantTypeId::UInt64 => 4,
            VariantTypeId::Int32 => 5,
            VariantTypeId::UInt32 => 6,
            VariantTypeId::StatusCode => 7,
            VariantTypeId::Int16 => 8,
            VariantTypeId::UInt16 => 9,
            VariantTypeId::SByte => 10,
            VariantTypeId::Byte => 11,
            VariantTypeId::Boolean => 12,
            VariantTypeId::Guid => 13,
            VariantTypeId::String => 14,
            VariantTypeId::ExpandedNodeId => 15,
            VariantTypeId::NodeId => 16,
            VariantTypeId::LocalizedText => 17,
            VariantTypeId::QualifiedName => 18,
            _ => 100,
        }
    }
}

pub(crate) struct EncodingMask;

impl EncodingMask {
    // These are values, not bits
    pub const BOOLEAN: u8 = DataTypeId::Boolean as u8;
    pub const SBYTE: u8 = DataTypeId::SByte as u8;
    pub const BYTE: u8 = DataTypeId::Byte as u8;
    pub const INT16: u8 = DataTypeId::Int16 as u8;
    pub const UINT16: u8 = DataTypeId::UInt16 as u8;
    pub const INT32: u8 = DataTypeId::Int32 as u8;
    pub const UINT32: u8 = DataTypeId::UInt32 as u8;
    pub const INT64: u8 = DataTypeId::Int64 as u8;
    pub const UINT64: u8 = DataTypeId::UInt64 as u8;
    pub const FLOAT: u8 = DataTypeId::Float as u8;
    pub const DOUBLE: u8 = DataTypeId::Double as u8;
    pub const STRING: u8 = DataTypeId::String as u8;
    pub const DATE_TIME: u8 = DataTypeId::DateTime as u8;
    pub const GUID: u8 = DataTypeId::Guid as u8;
    pub const BYTE_STRING: u8 = DataTypeId::ByteString as u8;
    pub const XML_ELEMENT: u8 = DataTypeId::XmlElement as u8;
    pub const NODE_ID: u8 = DataTypeId::NodeId as u8;
    pub const EXPANDED_NODE_ID: u8 = DataTypeId::ExpandedNodeId as u8;
    pub const STATUS_CODE: u8 = DataTypeId::StatusCode as u8;
    pub const QUALIFIED_NAME: u8 = DataTypeId::QualifiedName as u8;
    pub const LOCALIZED_TEXT: u8 = DataTypeId::LocalizedText as u8;
    pub const EXTENSION_OBJECT: u8 = 22; // DataTypeId::ExtensionObject as u8;
    pub const DATA_VALUE: u8 = DataTypeId::DataValue as u8;
    pub const VARIANT: u8 = 24;
    pub const DIAGNOSTIC_INFO: u8 = DataTypeId::DiagnosticInfo as u8;
    /// Bit indicates an array with dimensions
    pub const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;
    /// Bit indicates an array with values
    pub const ARRAY_VALUES_BIT: u8 = 1 << 7;

    pub const ARRAY_MASK: u8 = EncodingMask::ARRAY_DIMENSIONS_BIT | EncodingMask::ARRAY_VALUES_BIT;
}
