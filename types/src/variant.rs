use std::io::{Read, Write};

use encoding::*;
use constants;
use basic_types::*;
use date_time::DateTime;
use data_value::DataValue;
use node_id::{NodeId, ExpandedNodeId};
use generated::StatusCode;
use generated::StatusCode::*;
use generated::DataTypeId;

const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;
const ARRAY_VALUES_BIT: u8 = 1 << 7;

#[derive(Debug, Clone, PartialEq)]
pub struct MultiDimensionArray {
    pub values: Vec<Variant>,
    pub dimensions: Vec<Int32>
}

/// A Variant holds all primitive types, including single and multi dimensional arrays and
/// data values. Boxes are used for more complex types to keep the size of this enum down a bit.
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
    /// StatusCode
    StatusCode(StatusCode),
    /// ByteString
    ByteString(ByteString),
    /// XmlElement
    XmlElement(XmlElement),
    /// QualifiedName
    QualifiedName(Box<QualifiedName>),
    /// LocalizedText
    LocalizedText(Box<LocalizedText>),
    /// NodeId
    NodeId(Box<NodeId>),
    /// ExpandedNodeId
    ExpandedNodeId(Box<ExpandedNodeId>),
    /// ExtensionObject
    ExtensionObject(Box<ExtensionObject>),
    /// DataValue (boxed because a DataValue itself holds a Variant)
    DataValue(Box<DataValue>),
    /// Single dimension array
    /// A variant can be an array of other kinds (all of which must be the same type), second argument is the dimensions of the
    /// array which should match the array length, otherwise BAD_DECODING_ERROR
    Array(Box<Vec<Variant>>),
    /// Multi dimension array
    /// A variant can be an array of other kinds (all of which must be the same type), second argument is the dimensions of the
    /// array which should match the array length, otherwise BAD_DECODING_ERROR
    /// Higher rank dimensions are serialized first. For example an array with dimensions [2,2,2] is written in this order:
    /// [0,0,0], [0,0,1], [0,1,0], [0,1,1], [1,0,0], [1,0,1], [1,1,0], [1,1,1]
    MultiDimensionArray(Box<MultiDimensionArray>),
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
            &Variant::Array(ref values) => {
                // Array length
                let mut size = 4;
                // Values
                for value in values.iter() {
                    size += Variant::byte_len_variant_value(value);
                }
                size
            }
            &Variant::MultiDimensionArray(ref mda) => {
                // Array length
                let mut size = 4;
                // Values
                for value in mda.values.iter() {
                    size += Variant::byte_len_variant_value(value);
                }
                // Dimensions (size + num elements)
                size += 4 + mda.dimensions.len() * 4;
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
                for value in values.iter() {
                    size += Variant::encode_variant_value(stream, value)?;
                }
                size
            }
            &Variant::MultiDimensionArray(ref mda) => {
                // Encode array length
                let mut size = write_i32(stream, mda.values.len() as i32)?;
                // Encode values
                for value in mda.values.iter() {
                    size += Variant::encode_variant_value(stream, value)?;
                }
                // Encode dimensions length
                size += write_i32(stream, mda.dimensions.len() as i32)?;
                // Encode dimensions
                for d in mda.dimensions.iter() {
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
                error!("Invalid array_length {}", array_length);
                return Err(BAD_DECODING_ERROR);
            }
            array_length
        } else {
            -1
        };

        // Read the value(s). If array length was specified, we assume a single or multi dimension array
        let result = if array_length > 0 {
            // Array length in total cannot exceed max array length
            if array_length > constants::MAX_ARRAY_LENGTH as i32 {
                return Err(BAD_ENCODING_LIMITS_EXCEEDED);
            }

            let mut result: Vec<Variant> = Vec::with_capacity(array_length as usize);
            for _ in 0..array_length {
                result.push(Variant::decode_variant_value(stream, element_encoding_mask)?);
            }
            if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
                let dimensions: Option<Vec<Int32>> = read_array(stream)?;
                if dimensions.is_none() {
                    error!("No array dimensions despite the bit flag being set");
                    return Err(BAD_DECODING_ERROR);
                }
                let dimensions = dimensions.unwrap();
                let mut array_dimensions_length = 1;
                for d in &dimensions {
                    if *d <= 0 {
                        error!("Invalid array dimension {}", *d);
                        return Err(BAD_DECODING_ERROR);
                    }
                    array_dimensions_length *= *d;
                }
                if array_dimensions_length != array_length {
                    error!("Array dimensions does not match array length {}", array_length);
                    Err(BAD_DECODING_ERROR)
                } else {
                    Ok(Variant::new_multi_dimension_array(result, dimensions))
                }
            } else {
                Ok(Variant::Array(Box::new(result)))
            }
        } else if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
            error!("Array dimensions bit specified without any values");
            Err(BAD_DECODING_ERROR)
        } else {
            // Read a single variant
            Variant::decode_variant_value(stream, element_encoding_mask)
        };
        result
    }
}

impl Variant {
    pub fn new_node_id(node_id: NodeId) -> Variant {
        Variant::NodeId(Box::new(node_id))
    }

    pub fn new_expanded_node_id(expanded_node_id: ExpandedNodeId) -> Variant {
        Variant::ExpandedNodeId(Box::new(expanded_node_id))
    }

    pub fn new_qualified_name(qualified_name: QualifiedName) -> Variant {
        Variant::QualifiedName(Box::new(qualified_name))
    }

    pub fn new_localized_text(localized_text: LocalizedText) -> Variant {
        Variant::LocalizedText(Box::new(localized_text))
    }

    pub fn new_extension_object(extension_object: ExtensionObject) -> Variant {
        Variant::ExtensionObject(Box::new(extension_object))
    }

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
        match value {
            &Variant::Empty => Ok(0),
            &Variant::Boolean(ref value) => value.encode(stream),
            &Variant::SByte(ref value) => value.encode(stream),
            &Variant::Byte(ref value) => value.encode(stream),
            &Variant::Int16(ref value) => value.encode(stream),
            &Variant::UInt16(ref value) => value.encode(stream),
            &Variant::Int32(ref value) => value.encode(stream),
            &Variant::UInt32(ref value) => value.encode(stream),
            &Variant::Int64(ref value) => value.encode(stream),
            &Variant::UInt64(ref value) => value.encode(stream),
            &Variant::Float(ref value) => value.encode(stream),
            &Variant::Double(ref value) => value.encode(stream),
            &Variant::String(ref value) => value.encode(stream),
            &Variant::DateTime(ref value) => value.encode(stream),
            &Variant::Guid(ref value) => value.encode(stream),
            &Variant::ByteString(ref value) => value.encode(stream),
            &Variant::XmlElement(ref value) => value.encode(stream),
            &Variant::NodeId(ref value) => value.encode(stream),
            &Variant::ExpandedNodeId(ref value) => value.encode(stream),
            &Variant::StatusCode(ref value) => value.encode(stream),
            &Variant::QualifiedName(ref value) => value.encode(stream),
            &Variant::LocalizedText(ref value) => value.encode(stream),
            &Variant::ExtensionObject(ref value) => value.encode(stream),
            &Variant::DataValue(ref value) => value.encode(stream),
            _ => {
                warn!("Cannot encode this variant value type (probably nested array)");
                Err(BAD_ENCODING_ERROR)
            }
        }
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
            Variant::new_node_id(NodeId::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::ExpandedNodeId) {
            Variant::new_expanded_node_id(ExpandedNodeId::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::StatusCode) {
            Variant::StatusCode(StatusCode::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::QualifiedName) {
            Variant::new_qualified_name(QualifiedName::decode(stream)?)
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::LocalizedText) {
            Variant::new_localized_text(LocalizedText::decode(stream)?)
        } else if encoding_mask == 22 {
            Variant::ExtensionObject(Box::new(ExtensionObject::decode(stream)?))
        } else if Variant::test_encoding_flag(encoding_mask, DataTypeId::DataValue) {
            Variant::DataValue(Box::new(DataValue::decode(stream)?))
        } else {
            Variant::Empty
        };
        Ok(result)
    }

    pub fn new_multi_dimension_array(values: Vec<Variant>, dimensions: Vec<Int32>) -> Variant {
        Variant::MultiDimensionArray(Box::new(MultiDimensionArray { values: values, dimensions: dimensions }))
    }

    pub fn new_i32_array(in_values: &[Int32]) -> Variant {
        let mut values = Vec::with_capacity(in_values.len());
        for v in in_values {
            values.push(Variant::Int32(*v));
        }
        Variant::Array(Box::new(values))
    }

    pub fn new_u32_array(in_values: &[UInt32]) -> Variant {
        let mut values = Vec::with_capacity(in_values.len());
        for v in in_values {
            values.push(Variant::UInt32(*v));
        }
        Variant::Array(Box::new(values))
    }

    pub fn new_string_array(in_values: &[String]) -> Variant {
        let mut values = Vec::with_capacity(in_values.len());
        for v in in_values {
            values.push(Variant::String(UAString::from_str(&v)));
        }
        Variant::Array(Box::new(values))
    }

    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        match self {
            &Variant::SByte(_) | &Variant::Byte(_) |
            &Variant::Int16(_) | &Variant::UInt16(_) |
            &Variant::Int32(_) | &Variant::UInt32(_) |
            &Variant::Int64(_) | &Variant::UInt64(_) |
            &Variant::Float(_) | &Variant::Double(_) => true,
            _ => false
        }
    }

    /// Converts the numeric type to a double or returns None
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            &Variant::SByte(value) => Some(value as f64),
            &Variant::Byte(value) => Some(value as f64),
            &Variant::Int16(value) => Some(value as f64),
            &Variant::UInt16(value) => Some(value as f64),
            &Variant::Int32(value) => Some(value as f64),
            &Variant::UInt32(value) => Some(value as f64),
            &Variant::Int64(value) => {
                // NOTE: Int64 could overflow
                Some(value as f64)
            }
            &Variant::UInt64(value) => {
                // NOTE: UInt64 could overflow
                Some(value as f64)
            }
            &Variant::Float(value) => Some(value as f64),
            &Variant::Double(value) => Some(value),
            _ => {
                None
            }
        }
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
            &Variant::Array(ref values) => {
                let mut encoding_mask = if values.is_empty() {
                    0u8
                } else {
                    values[0].get_encoding_mask()
                };
                encoding_mask |= ARRAY_VALUES_BIT;
                encoding_mask
            }
            &Variant::MultiDimensionArray(ref mda) => {
                let mut encoding_mask = if mda.values.is_empty() {
                    0u8
                } else {
                    mda.values[0].get_encoding_mask()
                };
                encoding_mask |= ARRAY_VALUES_BIT | ARRAY_DIMENSIONS_BIT;
                encoding_mask
            }
        };
        encoding_mask
    }
}
