use std::io::{Read, Write, Result};

use super::encodable_types::*;
use super::data_value::*;
use super::date_time::*;
use super::helpers::*;
use super::node_id::*;
use super::status_codes::*;
use super::node_ids::{DataTypeId};

const ARRAY_BIT: u8 = 1 << 7;
const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;

#[derive(PartialEq, Debug, Clone)]
pub enum VariantValue {
    /// Empty type has no value
    Empty,
    /// Boolean
    Boolean(Boolean),
    /// Signed byte
    SByte(SByte),
    /// Unsigned byte
    Byte(Byte),
    /// Signed 16-bit int
    Int16(Int16),
    /// Unsigned 16-bit int
    UInt16(UInt16),
    /// Signed 32-bit int
    Int32(Int32),
    /// Unsigned 32-bit int
    UInt32(UInt32),
    /// Signed 64-bit int
    Int64(Int64),
    /// Unsigned 64-bit int
    UInt64(UInt64),
    /// Float
    Float(Float),
    /// Double
    Double(Double),
    /// String
    String(UAString),
    /// DateTime
    DateTime(DateTime),
    /// Guid
    Guid(Guid),
    /// ByteString
    ByteString(ByteString),
    /// XmlElement
    XmlElement(XmlElement),
    /// NodeId
    NodeId(NodeId),
    /// ExpandedNodeId
    ExpandedNodeId(ExpandedNodeId),
    /// StatusCode
    StatusCode(StatusCode),
    /// QualifiedName
    QualifiedName(QualifiedName),
    /// LocalizedText
    LocalizedText(LocalizedText),
    /// ExtensionObject
    ExtensionObject(ExtensionObject),
    /// DataValue
    DataValue(DataValue),
    /// A variant can be an array of other kinds, second argument is the dimensions of the
    /// array which should match the array length, otherwise BAD_DECODING_ERROR
    Array(Vec<Variant>, Vec<UInt32>),
}

/// Data type ID 24 (super-unwieldy mega holder of anything)
#[derive(PartialEq, Debug, Clone)]
pub struct Variant {
    /// The value of the variant
    value: VariantValue,
}

impl BinaryEncoder<Variant> for Variant {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;

        // Encoding mask
        size += 1;

        match self.value {
            VariantValue::Empty => {},
            VariantValue::Boolean(ref value) => {
                size += value.byte_len();
            },
            /// Signed byte
            VariantValue::SByte(ref value) => {
                size += value.byte_len();
            },
            /// Unsigned byte
            VariantValue::Byte(ref value) => {
                size += value.byte_len();
            },
            /// Signed 16-bit int
            VariantValue::Int16(ref value) => {
                size += value.byte_len();
            },
            /// Unsigned 16-bit int
            VariantValue::UInt16(ref value) => {
                size += value.byte_len();
            },
            /// Signed 32-bit int
            VariantValue::Int32(ref value) => {
                size += value.byte_len();
            },
            /// Unsigned 32-bit int
            VariantValue::UInt32(ref value) => {
                size += value.byte_len();
            },
            /// Signed 64-bit int
            VariantValue::Int64(ref value) => {
                size += value.byte_len();
            },
            /// Unsigned 64-bit int
            VariantValue::UInt64(ref value) => {
                size += value.byte_len();
            },
            /// Float
            VariantValue::Float(ref value) => {
                size += value.byte_len();
            },
            /// Double
            VariantValue::Double(ref value) => {
                size += value.byte_len();
            },
            /// String
            VariantValue::String(ref value) => {
                size += value.byte_len();
            },
            /// DateTime
            VariantValue::DateTime(ref value) => {
                size += value.byte_len();
            },
            /// Guid
            VariantValue::Guid(ref value) => {
                size += value.byte_len();
            },
            /// ByteString
            VariantValue::ByteString(ref value) => {
                size += value.byte_len();
            },
            /// XmlElement
            VariantValue::XmlElement(ref value) => {
                size += value.byte_len();
            },
            /// NodeId
            VariantValue::NodeId(ref value) => {
                size += value.byte_len();
            },
            /// ExpandedNodeId
            VariantValue::ExpandedNodeId(ref value) => {
                size += value.byte_len();
            },
            /// StatusCode
            VariantValue::StatusCode(ref value) => {
                size += value.byte_len();
            },
            /// QualifiedName
            VariantValue::QualifiedName(ref value) => {
                size += value.byte_len();
            },
            /// LocalizedText
            VariantValue::LocalizedText(ref value) => {
                size += value.byte_len();
            },
            /// ExtensionObject
            VariantValue::ExtensionObject(ref value) => {
                size += value.byte_len();
            },
            /// DataValue
            VariantValue::DataValue(ref value) => {
                size += value.byte_len();
            },
            /// A variant can be an array of other kinds
            VariantValue::Array(ref values, ref dimensions) => {
                size += 4;
                for value in values {
                    size += value.byte_len();
                }
                for d in dimensions {
                    size += d.byte_len();
                }
            },
        }
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;

        let encoding_mask = self.get_encoding_mask();
        size += write_u8(stream, encoding_mask)?;

        match self.value {
            VariantValue::Empty => {},
            /// Empty type has no value
            /// Boolean
            VariantValue::Boolean(ref value) => {
                size += value.encode(stream)?;
            },
            /// Signed byte
            VariantValue::SByte(ref value) => {
                size += value.encode(stream)?;
            },
            /// Unsigned byte
            VariantValue::Byte(ref value) => {
                size += value.encode(stream)?;
            },
            /// Signed 16-bit int
            VariantValue::Int16(ref value) => {
                size += value.encode(stream)?;
            },
            /// Unsigned 16-bit int
            VariantValue::UInt16(ref value) => {
                size += value.encode(stream)?;
            },
            /// Signed 32-bit int
            VariantValue::Int32(ref value) => {
                size += value.encode(stream)?;
            },
            /// Unsigned 32-bit int
            VariantValue::UInt32(ref value) => {
                size += value.encode(stream)?;
            },
            /// Signed 64-bit int
            VariantValue::Int64(ref value) => {
                size += value.encode(stream)?;
            },
            /// Unsigned 64-bit int
            VariantValue::UInt64(ref value) => {
                size += value.encode(stream)?;
            },
            /// Float
            VariantValue::Float(ref value) => {
                size += value.encode(stream)?;
            },
            /// Double
            VariantValue::Double(ref value) => {
                size += value.encode(stream)?;
            },
            /// String
            VariantValue::String(ref value) => {
                size += value.encode(stream)?;
            },
            /// DateTime
            VariantValue::DateTime(ref value) => {
                size += value.encode(stream)?;
            },
            /// Guid
            VariantValue::Guid(ref value) => {
                size += value.encode(stream)?;
            },
            /// ByteString
            VariantValue::ByteString(ref value) => {
                size += value.encode(stream)?;
            },
            /// XmlElement
            VariantValue::XmlElement(ref value) => {
                size += value.encode(stream)?;
            },
            /// NodeId
            VariantValue::NodeId(ref value) => {
                size += value.encode(stream)?;
            },
            /// ExpandedNodeId
            VariantValue::ExpandedNodeId(ref value) => {
                size += value.encode(stream)?;
            },
            /// StatusCode
            VariantValue::StatusCode(ref value) => {
                size += value.encode(stream)?;
            },
            /// QualifiedName
            VariantValue::QualifiedName(ref value) => {
                size += value.encode(stream)?;
            },
            /// LocalizedText
            VariantValue::LocalizedText(ref value) => {
                size += value.encode(stream)?;
            },
            /// ExtensionObject
            VariantValue::ExtensionObject(ref value) => {
                size += value.encode(stream)?;
            },
            /// DataValue
            VariantValue::DataValue(ref value) => {
                size += value.encode(stream)?;
            },
            /// A variant can be an array of other kinds
            VariantValue::Array(ref values, ref dimensions) => {
                size += write_u32(stream, values.len() as u32)?;
                for value in values {
                    size += value.encode(stream)?;
                }
                for d in dimensions {
                    size += d.encode(stream)?;
                }
            },
        }
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<Variant> {
        let encoding_mask = read_u8(stream)?;
        if encoding_mask == 0 {
            Ok(Variant::new(VariantValue::Empty))
        } else if encoding_mask & ARRAY_BIT != 0 {
            // TODO Array of values -
            if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
                // TODO Array dimensions are encoded
            }
            debug!("Unimplemented decode of array");
            Ok(Variant::new(VariantValue::Empty))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Boolean) {
            Ok(Variant::new(VariantValue::Boolean(Boolean::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::SByte) {
            Ok(Variant::new(VariantValue::SByte(SByte::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Byte) {
            Ok(Variant::new(VariantValue::Byte(Byte::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int16) {
            Ok(Variant::new(VariantValue::Int16(Int16::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt16) {
            Ok(Variant::new(VariantValue::UInt16(UInt16::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int32) {
            Ok(Variant::new(VariantValue::Int32(Int32::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt32) {
            Ok(Variant::new(VariantValue::UInt32(UInt32::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int64) {
            Ok(Variant::new(VariantValue::Int64(Int64::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt64) {
            Ok(Variant::new(VariantValue::UInt64(UInt64::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Float) {
            Ok(Variant::new(VariantValue::Float(Float::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Double) {
            Ok(Variant::new(VariantValue::Double(Double::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::String) {
            Ok(Variant::new(VariantValue::String(UAString::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DateTime) {
            Ok(Variant::new(VariantValue::DateTime(DateTime::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Guid) {
            Ok(Variant::new(VariantValue::Guid(Guid::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ByteString) {
            Ok(Variant::new(VariantValue::ByteString(ByteString::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::XmlElement) {
            Ok(Variant::new(VariantValue::XmlElement(XmlElement::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::NodeId) {
            Ok(Variant::new(VariantValue::NodeId(NodeId::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ExpandedNodeId) {
            Ok(Variant::new(VariantValue::ExpandedNodeId(ExpandedNodeId::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::StatusCode) {
            Ok(Variant::new(VariantValue::StatusCode(StatusCode::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::QualifiedName) {
            Ok(Variant::new(VariantValue::QualifiedName(QualifiedName::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::LocalizedText) {
            Ok(Variant::new(VariantValue::LocalizedText(LocalizedText::decode(stream)?)))
        } else if encoding_mask == 22 {
            Ok(Variant::new(VariantValue::ExtensionObject(ExtensionObject::decode(stream)?)))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DataValue) {
            Ok(Variant::new(VariantValue::DataValue(DataValue::decode(stream)?)))
        } else {
            Ok(Variant::new(VariantValue::Empty))
        }
    }
}

impl Variant {
    /// Creates a Variant from the value (which is moved)
    pub fn new(value: VariantValue) -> Variant {
        Variant { value: value, }
    }

    /// Test the flag (convenience method)
    pub fn test_encoding_flag(encoding_mask: u8, data_type_id: DataTypeId) -> bool {
        encoding_mask == data_type_id as u8
    }

    pub fn get_encoding_mask(&self) -> u8 {
        let mut encoding_mask;
        match self.value {
            VariantValue::Empty => {
                encoding_mask = 0;
            },
            /// Empty type has no value
            /// Boolean
            VariantValue::Boolean(_) => {
                encoding_mask = DataTypeId::Boolean as u8;
            },
            /// Signed byte
            VariantValue::SByte(_) => {
                encoding_mask = DataTypeId::SByte as u8;
            },
            /// Unsigned byte
            VariantValue::Byte(_) => {
                encoding_mask = DataTypeId::Byte as u8;
            },
            /// Signed 16-bit int
            VariantValue::Int16(_) => {
                encoding_mask = DataTypeId::Int16 as u8;
            },
            /// Unsigned 16-bit int
            VariantValue::UInt16(_) => {
                encoding_mask = DataTypeId::UInt16 as u8;
            },
            /// Signed 32-bit int
            VariantValue::Int32(_) => {
                encoding_mask = DataTypeId::Int32 as u8;
            },
            /// Unsigned 32-bit int
            VariantValue::UInt32(_) => {
                encoding_mask = DataTypeId::UInt32 as u8;
            },
            /// Signed 64-bit int
            VariantValue::Int64(_) => {
                encoding_mask = DataTypeId::Int64 as u8;
            },
            /// Unsigned 64-bit int
            VariantValue::UInt64(_) => {
                encoding_mask = DataTypeId::UInt64 as u8;
            },
            /// Float
            VariantValue::Float(_) => {
                encoding_mask = DataTypeId::Float as u8;
            },
            /// Double
            VariantValue::Double(_) => {
                encoding_mask = DataTypeId::Double as u8;
            },
            /// String
            VariantValue::String(_) => {
                encoding_mask = DataTypeId::String as u8;
            },
            /// DateTime
            VariantValue::DateTime(_) => {
                encoding_mask = DataTypeId::DateTime as u8;
            },
            /// Guid
            VariantValue::Guid(_) => {
                encoding_mask = DataTypeId::Guid as u8;
            },
            /// ByteString
            VariantValue::ByteString(_) => {
                encoding_mask = DataTypeId::ByteString as u8;
            },
            /// XmlElement
            VariantValue::XmlElement(_) => {
                encoding_mask = DataTypeId::XmlElement as u8;
            },
            /// NodeId
            VariantValue::NodeId(_) => {
                encoding_mask = DataTypeId::NodeId as u8;
            },
            /// ExpandedNodeId
            VariantValue::ExpandedNodeId(_) => {
                encoding_mask = DataTypeId::ExpandedNodeId as u8;
            },
            /// StatusCode
            VariantValue::StatusCode(_) => {
                encoding_mask = DataTypeId::StatusCode as u8;
            },
            /// QualifiedName
            VariantValue::QualifiedName(_) => {
                encoding_mask = DataTypeId::QualifiedName as u8;
            },
            /// LocalizedText
            VariantValue::LocalizedText(_) => {
                encoding_mask = DataTypeId::LocalizedText as u8;
            },
            /// ExtensionObject
            VariantValue::ExtensionObject(_) => {
                encoding_mask = 22; // DataTypeId::ExtensionObject as u8;
            },
            /// DataValue
            VariantValue::DataValue(_) => {
                encoding_mask = DataTypeId::DataValue as u8;
            },
            /// A variant can be an array of other kinds
            VariantValue::Array(ref values, _) => {
                if values.is_empty() {
                    encoding_mask = 0;
                } else {
                    encoding_mask = values[0].get_encoding_mask();
                }
                encoding_mask |= ARRAY_BIT; // True if the array dimensions field is encoded
                encoding_mask |= ARRAY_DIMENSIONS_BIT; // True if an array of values is encoded
            },
        }
        encoding_mask
    }
}
