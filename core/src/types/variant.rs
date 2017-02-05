use std::io::{Read, Write};

use types::*;

const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;
const ARRAY_VALUES_BIT: u8 = 1 << 7;

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
    /// Single dimension array
    /// A variant can be an array of other kinds (all of which must be the same type), second argument is the dimensions of the
    /// array which should match the array length, otherwise BAD_DECODING_ERROR
    Array(Vec<Variant>),
    /// Multi dimension array
    /// A variant can be an array of other kinds (all of which must be the same type), second argument is the dimensions of the
    /// array which should match the array length, otherwise BAD_DECODING_ERROR
    /// Higher rank dimensions are serialized first. For example an array with dimensions [2,2,2] is written in this order:
    /// [0,0,0], [0,0,1], [0,1,0], [0,1,1], [1,0,0], [1,0,1], [1,1,0], [1,1,1]
    MultiDimensionArray(Vec<Variant>, Vec<Int32>),
}

impl BinaryEncoder<Variant> for Variant {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;

        // Encoding mask
        size += 1;

        // Value itself
        size += match self {
            &Variant::Empty => 0,
            &Variant::Boolean(ref value) => value.byte_len(),
            &Variant::SByte(ref value) => value.byte_len(),
            &Variant::Byte(ref value) => value.byte_len(),
            &Variant::Int16(ref value) => value.byte_len(),
            &Variant::UInt16(ref value) => value.byte_len(),
            &Variant::Int32(ref value) => value.byte_len(),
            &Variant::UInt32(ref value) => value.byte_len(),
            &Variant::Int64(ref value) => value.byte_len(),
            &Variant::UInt64(ref value) => value.byte_len(),
            &Variant::Float(ref value) => value.byte_len(),
            &Variant::Double(ref value) => value.byte_len(),
            &Variant::String(ref value) => value.byte_len(),
            &Variant::DateTime(ref value) => value.byte_len(),
            &Variant::Guid(ref value) => value.byte_len(),
            &Variant::ByteString(ref value) => value.byte_len(),
            &Variant::XmlElement(ref value) => value.byte_len(),
            &Variant::NodeId(ref value) => value.byte_len(),
            &Variant::ExpandedNodeId(ref value) => value.byte_len(),
            &Variant::StatusCode(ref value) => value.byte_len(),
            &Variant::QualifiedName(ref value) => value.byte_len(),
            &Variant::LocalizedText(ref value) => value.byte_len(),
            &Variant::ExtensionObject(ref value) => value.byte_len(),
            &Variant::DataValue(ref value) => value.byte_len(),
            /// A variant can be an array of other kinds
            &Variant::Array(ref values) => {
                // Array length
                let mut size = 4;
                // Values
                for value in values {
                    size += Variant::byte_len_variant_value(value);
                }
                size
            },
            &Variant::MultiDimensionArray(ref values, ref dimensions) => {
                // Array length
                let mut size = 4;
                // Values
                for value in values {
                    size += Variant::byte_len_variant_value(value);
                }
                // Dimensions (size + num elements)
                size += 4 + dimensions.len() * 4;
                size
            }
        };
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;

        // Encoding mask will include the array bits if applicable for the type
        let encoding_mask = self.get_encoding_mask();
        size += write_u8(stream, encoding_mask)?;

        size += match self {
            &Variant::Empty => 0,
            &Variant::Boolean(ref value) => value.encode(stream)?,
            &Variant::SByte(ref value) => value.encode(stream)?,
            &Variant::Byte(ref value) => value.encode(stream)?,
            &Variant::Int16(ref value) => value.encode(stream)?,
            &Variant::UInt16(ref value) => value.encode(stream)?,
            &Variant::Int32(ref value) => value.encode(stream)?,
            &Variant::UInt32(ref value) => value.encode(stream)?,
            &Variant::Int64(ref value) => value.encode(stream)?,
            &Variant::UInt64(ref value) => value.encode(stream)?,
            &Variant::Float(ref value) => value.encode(stream)?,
            &Variant::Double(ref value) => value.encode(stream)?,
            &Variant::String(ref value) => value.encode(stream)?,
            &Variant::DateTime(ref value) => value.encode(stream)?,
            &Variant::Guid(ref value) => value.encode(stream)?,
            &Variant::ByteString(ref value) => value.encode(stream)?,
            &Variant::XmlElement(ref value) => value.encode(stream)?,
            &Variant::NodeId(ref value) => value.encode(stream)?,
            &Variant::ExpandedNodeId(ref value) => value.encode(stream)?,
            &Variant::StatusCode(ref value) => value.encode(stream)?,
            &Variant::QualifiedName(ref value) => value.encode(stream)?,
            &Variant::LocalizedText(ref value) => value.encode(stream)?,
            &Variant::ExtensionObject(ref value) => value.encode(stream)?,
            &Variant::DataValue(ref value) => value.encode(stream)?,
            &Variant::Array(ref values) => {
                let mut size = write_i32(stream, values.len() as i32)?;
                for value in values {
                    size += Variant::encode_variant_value(stream, value)?;
                }
                size
            },
            &Variant::MultiDimensionArray(ref values, ref dimensions) => {
                // Encode array length
                let mut size = write_i32(stream, values.len() as i32)?;
                // Encode values
                for value in values {
                    size += Variant::encode_variant_value(stream, value)?;
                }
                // Encode dimensions length
                size += write_i32(stream, dimensions.len() as i32)?;
                // Encode dimensions
                for d in dimensions {
                    size += write_i32(stream, *d)?;
                }
                size
            }
        };
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let encoding_mask = Byte::decode(stream)?;
        let element_encoding_mask = encoding_mask & !(ARRAY_DIMENSIONS_BIT | ARRAY_VALUES_BIT);

        // Read array length
        let array_length = if encoding_mask & ARRAY_VALUES_BIT != 0 {
            let array_length = Int32::decode(stream)?;
            if array_length <= 0 {
                debug!("Invalid array_length {}", array_length);
                return Err(&BAD_DECODING_ERROR);
            }
            array_length
        } else {
            -1
        };

        // Read the value(s). If array length was specified, we assume a single or multi dimension array
        let result = if array_length > 0 {
            let mut result: Vec<Variant> = Vec::with_capacity(array_length as usize);
            for _ in 0..array_length {
                result.push(Variant::decode_variant_value(stream, element_encoding_mask)?);
            }
            if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
                let dimensions: Option<Vec<Int32>> = read_array(stream)?;
                if dimensions.is_none() {
                    debug!("No array dimensions despite the bit flag being set");
                    return Err(&BAD_DECODING_ERROR);
                }
                let dimensions = dimensions.unwrap();
                let mut array_dimensions_length = 1;
                for d in &dimensions {
                    if *d <= 0 {
                        debug!("Invalid array dimension {}", *d);
                        return Err(&BAD_DECODING_ERROR);
                    }
                    array_dimensions_length *= *d;
                }
                if array_dimensions_length != array_length {
                    debug!("Array dimensions does not match array length {}", array_length);
                    Err(&BAD_DECODING_ERROR)
                } else {
                    Ok(Variant::MultiDimensionArray(result, dimensions))
                }
            } else {
                Ok(Variant::Array(result))
            }
        } else if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
            debug!("Array dimensions bit specified without any values");
            Err(&BAD_DECODING_ERROR)
        } else {
            // Read a single variant
            Variant::decode_variant_value(stream, element_encoding_mask)
        };
        result
    }
}

impl Variant {
    /// Test the flag (convenience method)
    pub fn test_encoding_flag(encoding_mask: u8, data_type_id: DataTypeId) -> bool {
        encoding_mask == data_type_id as u8
    }

    /// Returns the length of just the value, not the encoding flag
    fn byte_len_variant_value(value: &Variant) -> usize {
        let size = match value {
            &Variant::Empty => 0,
            &Variant::Boolean(ref value) => value.byte_len(),
            &Variant::SByte(ref value) => value.byte_len(),
            &Variant::Byte(ref value) => value.byte_len(),
            &Variant::Int16(ref value) => value.byte_len(),
            &Variant::UInt16(ref value) => value.byte_len(),
            &Variant::Int32(ref value) => value.byte_len(),
            &Variant::UInt32(ref value) => value.byte_len(),
            &Variant::Int64(ref value) => value.byte_len(),
            &Variant::UInt64(ref value) => value.byte_len(),
            &Variant::Float(ref value) => value.byte_len(),
            &Variant::Double(ref value) => value.byte_len(),
            &Variant::String(ref value) => value.byte_len(),
            &Variant::DateTime(ref value) => value.byte_len(),
            &Variant::Guid(ref value) => value.byte_len(),
            &Variant::ByteString(ref value) => value.byte_len(),
            &Variant::XmlElement(ref value) => value.byte_len(),
            &Variant::NodeId(ref value) => value.byte_len(),
            &Variant::ExpandedNodeId(ref value) => value.byte_len(),
            &Variant::StatusCode(ref value) => value.byte_len(),
            &Variant::QualifiedName(ref value) => value.byte_len(),
            &Variant::LocalizedText(ref value) => value.byte_len(),
            &Variant::ExtensionObject(ref value) => value.byte_len(),
            &Variant::DataValue(ref value) => value.byte_len(),
            _ => {
                error!("Cannot compute length of this type (probably nested array)");
                0
            }
        };
        size
    }

    /// Encodes just the value, not the encoding flag
    fn encode_variant_value<S: Write>(stream: &mut S, value: &Variant) -> EncodingResult<usize> {
        let result = match value {
            &Variant::Empty => 0,
            &Variant::Boolean(ref value) => value.encode(stream)?,
            &Variant::SByte(ref value) => value.encode(stream)?,
            &Variant::Byte(ref value) => value.encode(stream)?,
            &Variant::Int16(ref value) => value.encode(stream)?,
            &Variant::UInt16(ref value) => value.encode(stream)?,
            &Variant::Int32(ref value) => value.encode(stream)?,
            &Variant::UInt32(ref value) => value.encode(stream)?,
            &Variant::Int64(ref value) => value.encode(stream)?,
            &Variant::UInt64(ref value) => value.encode(stream)?,
            &Variant::Float(ref value) => value.encode(stream)?,
            &Variant::Double(ref value) => value.encode(stream)?,
            &Variant::String(ref value) => value.encode(stream)?,
            &Variant::DateTime(ref value) => value.encode(stream)?,
            &Variant::Guid(ref value) => value.encode(stream)?,
            &Variant::ByteString(ref value) => value.encode(stream)?,
            &Variant::XmlElement(ref value) => value.encode(stream)?,
            &Variant::NodeId(ref value) => value.encode(stream)?,
            &Variant::ExpandedNodeId(ref value) => value.encode(stream)?,
            &Variant::StatusCode(ref value) => value.encode(stream)?,
            &Variant::QualifiedName(ref value) => value.encode(stream)?,
            &Variant::LocalizedText(ref value) => value.encode(stream)?,
            &Variant::ExtensionObject(ref value) => value.encode(stream)?,
            &Variant::DataValue(ref value) => value.encode(stream)?,
            _ => {
                debug!("Cannot encode this variant value type (probably nested array)");
                return Err(&BAD_ENCODING_ERROR)
            }
        };
        Ok(result)
    }

    /// Reads just the variant value from the stream
    fn decode_variant_value<S: Read>(stream: &mut S, encoding_mask: Byte) -> EncodingResult<Self> {
        let result = if encoding_mask == 0 {
            Variant::Empty
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Boolean) {
            Variant::Boolean(Boolean::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::SByte) {
            Variant::SByte(SByte::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Byte) {
            Variant::Byte(Byte::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int16) {
            Variant::Int16(Int16::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt16) {
            Variant::UInt16(UInt16::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int32) {
            Variant::Int32(Int32::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt32) {
            Variant::UInt32(UInt32::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Int64) {
            Variant::Int64(Int64::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::UInt64) {
            Variant::UInt64(UInt64::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Float) {
            Variant::Float(Float::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Double) {
            Variant::Double(Double::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::String) {
            Variant::String(UAString::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DateTime) {
            Variant::DateTime(DateTime::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::Guid) {
            Variant::Guid(Guid::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ByteString) {
            Variant::ByteString(ByteString::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::XmlElement) {
            Variant::XmlElement(XmlElement::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::NodeId) {
            Variant::NodeId(NodeId::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ExpandedNodeId) {
            Variant::ExpandedNodeId(ExpandedNodeId::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::StatusCode) {
            Variant::StatusCode(StatusCode::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::QualifiedName) {
            Variant::QualifiedName(QualifiedName::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::LocalizedText) {
            Variant::LocalizedText(LocalizedText::decode(stream)?)
        } else if encoding_mask == 22 {
            Variant::ExtensionObject(ExtensionObject::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DataValue) {
            Variant::DataValue(DataValue::decode(stream)?)
        } else {
            Variant::Empty
        };
        Ok(result)
    }

    pub fn from_str_array(in_values: &[&str]) -> Variant {
        let mut values = Vec::with_capacity(in_values.len());
        for v in in_values {
            values.push(Variant::String(UAString::from_str(v)));
        }
        Variant::Array(values)
    }

    // Gets the encoding mask to write the variant to disk
    fn get_encoding_mask(&self) -> u8 {
        let encoding_mask = match self {
            &Variant::Empty => 0,
            &Variant::Boolean(_) => DataTypeId::Boolean as u8,
            &Variant::SByte(_) => DataTypeId::SByte as u8,
            &Variant::Byte(_) => DataTypeId::Byte as u8,
            &Variant::Int16(_) => DataTypeId::Int16 as u8,
            &Variant::UInt16(_) => DataTypeId::UInt16 as u8,
            &Variant::Int32(_) => DataTypeId::Int32 as u8,
            &Variant::UInt32(_) => DataTypeId::UInt32 as u8,
            &Variant::Int64(_) => DataTypeId::Int64 as u8,
            &Variant::UInt64(_) => DataTypeId::UInt64 as u8,
            &Variant::Float(_) => DataTypeId::Float as u8,
            &Variant::Double(_) => DataTypeId::Double as u8,
            &Variant::String(_) => DataTypeId::String as u8,
            &Variant::DateTime(_) => DataTypeId::DateTime as u8,
            &Variant::Guid(_) => DataTypeId::Guid as u8,
            &Variant::ByteString(_) => DataTypeId::ByteString as u8,
            &Variant::XmlElement(_) => DataTypeId::XmlElement as u8,
            &Variant::NodeId(_) => DataTypeId::NodeId as u8,
            &Variant::ExpandedNodeId(_) => DataTypeId::ExpandedNodeId as u8,
            &Variant::StatusCode(_) => DataTypeId::StatusCode as u8,
            &Variant::QualifiedName(_) => DataTypeId::QualifiedName as u8,
            &Variant::LocalizedText(_) => DataTypeId::LocalizedText as u8,
            &Variant::ExtensionObject(_) => 22, // DataTypeId::ExtensionObject as u8,
            &Variant::DataValue(_) => DataTypeId::DataValue as u8,
            /// A variant can be an array of other kinds
            &Variant::Array(ref values) => {
                let mut encoding_mask = if values.is_empty() {
                    0u8
                } else {
                    values[0].get_encoding_mask()
                };
                encoding_mask |= ARRAY_VALUES_BIT;
                encoding_mask
            },
            &Variant::MultiDimensionArray(ref values, _) => {
                let mut encoding_mask = if values.is_empty() {
                    0u8
                } else {
                    values[0].get_encoding_mask()
                };
                encoding_mask |= ARRAY_VALUES_BIT | ARRAY_DIMENSIONS_BIT;
                encoding_mask
            }
        };
        encoding_mask
    }
}
