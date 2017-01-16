use std::io::{Read, Write, Result};

use types::*;

const ARRAY_BIT: u8 = 1 << 7;
const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;

/// Data type ID 24 (super-unwieldy mega holder of anything)
#[derive(PartialEq, Debug, Clone)]
pub enum Variant {
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

impl BinaryEncoder<Variant> for Variant {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;

        // Encoding mask
        size += 1;

        // Value itself
        size += match *self {
            Variant::Empty => 0,
            Variant::Boolean(ref value) => value.byte_len(),
            Variant::SByte(ref value) => value.byte_len(),
            Variant::Byte(ref value) => value.byte_len(),
            Variant::Int16(ref value) => value.byte_len(),
            Variant::UInt16(ref value) => value.byte_len(),
            Variant::Int32(ref value) => value.byte_len(),
            Variant::UInt32(ref value) => value.byte_len(),
            Variant::Int64(ref value) => value.byte_len(),
            Variant::UInt64(ref value) => value.byte_len(),
            Variant::Float(ref value) => value.byte_len(),
            Variant::Double(ref value) => value.byte_len(),
            Variant::String(ref value) => value.byte_len(),
            Variant::DateTime(ref value) => value.byte_len(),
            Variant::Guid(ref value) => value.byte_len(),
            Variant::ByteString(ref value) => value.byte_len(),
            Variant::XmlElement(ref value) => value.byte_len(),
            Variant::NodeId(ref value) => value.byte_len(),
            Variant::ExpandedNodeId(ref value) => value.byte_len(),
            Variant::StatusCode(ref value) => value.byte_len(),
            Variant::QualifiedName(ref value) => value.byte_len(),
            Variant::LocalizedText(ref value) => value.byte_len(),
            Variant::ExtensionObject(ref value) => value.byte_len(),
            Variant::DataValue(ref value) => value.byte_len(),
            /// A variant can be an array of other kinds
            Variant::Array(ref values, ref dimensions) => {
                let mut size = 4;
                for value in values {
                    size += value.byte_len();
                }
                for d in dimensions {
                    size += d.byte_len();
                }
                size
            },
        };
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        let mut size: usize = 0;

        let encoding_mask = self.get_encoding_mask();
        size += write_u8(stream, encoding_mask)?;

        size += match *self {
            Variant::Empty => 0,
            Variant::Boolean(ref value) => value.encode(stream)?,
            Variant::SByte(ref value) => value.encode(stream)?,
            Variant::Byte(ref value) => value.encode(stream)?,
            Variant::Int16(ref value) => value.encode(stream)?,
            Variant::UInt16(ref value) => value.encode(stream)?,
            Variant::Int32(ref value) => value.encode(stream)?,
            Variant::UInt32(ref value) => value.encode(stream)?,
            Variant::Int64(ref value) => value.encode(stream)?,
            Variant::UInt64(ref value) => value.encode(stream)?,
            Variant::Float(ref value) => value.encode(stream)?,
            Variant::Double(ref value) => value.encode(stream)?,
            Variant::String(ref value) => value.encode(stream)?,
            Variant::DateTime(ref value) => value.encode(stream)?,
            Variant::Guid(ref value) => value.encode(stream)?,
            Variant::ByteString(ref value) => value.encode(stream)?,
            Variant::XmlElement(ref value) => value.encode(stream)?,
            Variant::NodeId(ref value) => value.encode(stream)?,
            Variant::ExpandedNodeId(ref value) => value.encode(stream)?,
            Variant::StatusCode(ref value) => value.encode(stream)?,
            Variant::QualifiedName(ref value) => value.encode(stream)?,
            Variant::LocalizedText(ref value) => value.encode(stream)?,
            Variant::ExtensionObject(ref value) => value.encode(stream)?,
            Variant::DataValue(ref value) => value.encode(stream)?,
            /// A variant can be an array of other kinds
            Variant::Array(ref values, ref dimensions) => {
                let mut size = write_u32(stream, values.len() as u32)?;
                for value in values {
                    size += value.encode(stream)?;
                }
                for d in dimensions {
                    size += d.encode(stream)?;
                }
                size
            },
        };
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        let encoding_mask = Byte::decode(stream)?;
        if encoding_mask == 0 {
            Ok(Variant::Empty)
        } else if encoding_mask & ARRAY_BIT != 0 {
            // TODO Array of values -
            if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
                // TODO Array dimensions are encoded
            }
            debug!("Unimplemented decode of array");
            Ok(Variant::Empty)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Boolean) {
            Ok(Variant::Boolean(Boolean::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::SByte) {
            Ok(Variant::SByte(SByte::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Byte) {
            Ok(Variant::Byte(Byte::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int16) {
            Ok(Variant::Int16(Int16::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt16) {
            Ok(Variant::UInt16(UInt16::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int32) {
            Ok(Variant::Int32(Int32::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt32) {
            Ok(Variant::UInt32(UInt32::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int64) {
            Ok(Variant::Int64(Int64::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt64) {
            Ok(Variant::UInt64(UInt64::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Float) {
            Ok(Variant::Float(Float::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Double) {
            Ok(Variant::Double(Double::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::String) {
            Ok(Variant::String(UAString::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DateTime) {
            Ok(Variant::DateTime(DateTime::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Guid) {
            Ok(Variant::Guid(Guid::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ByteString) {
            Ok(Variant::ByteString(ByteString::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::XmlElement) {
            Ok(Variant::XmlElement(XmlElement::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::NodeId) {
            Ok(Variant::NodeId(NodeId::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ExpandedNodeId) {
            Ok(Variant::ExpandedNodeId(ExpandedNodeId::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::StatusCode) {
            Ok(Variant::StatusCode(StatusCode::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::QualifiedName) {
            Ok(Variant::QualifiedName(QualifiedName::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::LocalizedText) {
            Ok(Variant::LocalizedText(LocalizedText::decode(stream)?))
        } else if encoding_mask == 22 {
            Ok(Variant::ExtensionObject(ExtensionObject::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DataValue) {
            Ok(Variant::DataValue(DataValue::decode(stream)?))
        } else {
            Ok(Variant::Empty)
        }
    }
}

impl Variant {
    /// Test the flag (convenience method)
    pub fn test_encoding_flag(encoding_mask: u8, data_type_id: DataTypeId) -> bool {
        encoding_mask == data_type_id as u8
    }

    pub fn get_encoding_mask(&self) -> u8 {
        let encoding_mask = match *self {
            Variant::Empty => 0,
            Variant::Boolean(_) => DataTypeId::Boolean as u8,
            Variant::SByte(_) => DataTypeId::SByte as u8,
            Variant::Byte(_) => DataTypeId::Byte as u8,
            Variant::Int16(_) => DataTypeId::Int16 as u8,
            Variant::UInt16(_) => DataTypeId::UInt16 as u8,
            Variant::Int32(_) => DataTypeId::Int32 as u8,
            Variant::UInt32(_) => DataTypeId::UInt32 as u8,
            Variant::Int64(_) => DataTypeId::Int64 as u8,
            Variant::UInt64(_) => DataTypeId::UInt64 as u8,
            Variant::Float(_) => DataTypeId::Float as u8,
            Variant::Double(_) => DataTypeId::Double as u8,
            Variant::String(_) => DataTypeId::String as u8,
            Variant::DateTime(_) => DataTypeId::DateTime as u8,
            Variant::Guid(_) => DataTypeId::Guid as u8,
            Variant::ByteString(_) => DataTypeId::ByteString as u8,
            Variant::XmlElement(_) => DataTypeId::XmlElement as u8,
            Variant::NodeId(_) => DataTypeId::NodeId as u8,
            Variant::ExpandedNodeId(_) => DataTypeId::ExpandedNodeId as u8,
            Variant::StatusCode(_) => DataTypeId::StatusCode as u8,
            Variant::QualifiedName(_) => DataTypeId::QualifiedName as u8,
            Variant::LocalizedText(_) => DataTypeId::LocalizedText as u8,
            Variant::ExtensionObject(_) => 22, // DataTypeId::ExtensionObject as u8,
            Variant::DataValue(_) => DataTypeId::DataValue as u8,
            /// A variant can be an array of other kinds
            Variant::Array(ref values, _) => {
                let mut encoding_mask = if values.is_empty() {
                    0u8
                } else {
                    values[0].get_encoding_mask()
                };
                encoding_mask |= ARRAY_BIT; // True if the array dimensions field is encoded
                encoding_mask |= ARRAY_DIMENSIONS_BIT; // True if an array of values is encoded
                encoding_mask
            },
        };
        encoding_mask
    }
}
