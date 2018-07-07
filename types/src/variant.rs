use std::io::{Read, Write};

use basic_types::*;
use extension_object::ExtensionObject;
use byte_string::ByteString;
use constants;
use data_value::DataValue;
use date_time::DateTime;
use encoding::*;
use guid::Guid;
use node_id::{ExpandedNodeId, NodeId};
use node_ids::DataTypeId;
use status_codes::StatusCode;
use string::{UAString, XmlElement};

const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;
const ARRAY_VALUES_BIT: u8 = 1 << 7;

/// The variant type id is the type of the variant without its payload.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VariantTypeId {
    Empty,
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
    DataValue,
    Array,
    MultiDimensionArray,
}

impl VariantTypeId {
    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        match *self {
            VariantTypeId::SByte | VariantTypeId::Byte |
            VariantTypeId::Int16 | VariantTypeId::UInt16 |
            VariantTypeId::Int32 | VariantTypeId::UInt32 |
            VariantTypeId::Int64 | VariantTypeId::UInt64 |
            VariantTypeId::Float | VariantTypeId::Double => true,
            _ => false
        }
    }
}

impl From<Boolean> for Variant {
    fn from(v: Boolean) -> Self {
        Variant::Boolean(v)
    }
}

impl From<Byte> for Variant {
    fn from(v: Byte) -> Self {
        Variant::Byte(v)
    }
}

impl From<SByte> for Variant {
    fn from(v: SByte) -> Self {
        Variant::SByte(v)
    }
}

impl From<Int16> for Variant {
    fn from(v: Int16) -> Self {
        Variant::Int16(v)
    }
}

impl From<UInt16> for Variant {
    fn from(v: UInt16) -> Self {
        Variant::UInt16(v)
    }
}

impl From<Int32> for Variant {
    fn from(v: Int32) -> Self {
        Variant::Int32(v)
    }
}

impl From<UInt32> for Variant {
    fn from(v: UInt32) -> Self {
        Variant::UInt32(v)
    }
}

impl From<Int64> for Variant {
    fn from(v: Int64) -> Self {
        Variant::Int64(v)
    }
}

impl From<UInt64> for Variant {
    fn from(v: UInt64) -> Self {
        Variant::UInt64(v)
    }
}

impl From<Float> for Variant {
    fn from(v: Float) -> Self {
        Variant::Float(v)
    }
}

impl From<Double> for Variant {
    fn from(v: Double) -> Self {
        Variant::Double(v)
    }
}

impl<'a> From<&'a str> for Variant {
    fn from(value: &'a str) -> Self {
        Variant::String(UAString::from(value))
    }
}

impl From<String> for Variant {
    fn from(value: String) -> Self {
        Variant::String(UAString::from(value))
    }
}

impl From<UAString> for Variant {
    fn from(v: UAString) -> Self {
        Variant::String(v)
    }
}

impl From<DateTime> for Variant {
    fn from(v: DateTime) -> Self {
        Variant::DateTime(v)
    }
}

impl From<Guid> for Variant {
    fn from(v: Guid) -> Self {
        Variant::Guid(v)
    }
}

impl From<StatusCode> for Variant {
    fn from(v: StatusCode) -> Self {
        Variant::StatusCode(v)
    }
}

impl From<ByteString> for Variant {
    fn from(v: ByteString) -> Self {
        Variant::ByteString(v)
    }
}

impl From<QualifiedName> for Variant {
    fn from(v: QualifiedName) -> Self {
        Variant::QualifiedName(Box::new(v))
    }
}

impl From<LocalizedText> for Variant {
    fn from(v: LocalizedText) -> Self {
        Variant::LocalizedText(Box::new(v))
    }
}

impl From<NodeId> for Variant {
    fn from(v: NodeId) -> Self {
        Variant::NodeId(Box::new(v))
    }
}

impl From<ExpandedNodeId> for Variant {
    fn from(v: ExpandedNodeId) -> Self {
        Variant::ExpandedNodeId(Box::new(v))
    }
}

impl From<ExtensionObject> for Variant {
    fn from(v: ExtensionObject) -> Self {
        Variant::ExtensionObject(Box::new(v))
    }
}

impl From<DataValue> for Variant {
    fn from(v: DataValue) -> Self {
        Variant::DataValue(Box::new(v))
    }
}

impl From<Vec<UInt32>> for Variant {
    fn from(v: Vec<UInt32>) -> Self {
        let array: Vec<Variant> = v.iter().map(|v| Variant::from(*v)).collect();
        Variant::Array(array)
    }
}

impl From<Vec<Variant>> for Variant {
    fn from(v: Vec<Variant>) -> Self {
        Variant::Array(v)
    }
}

impl From<MultiDimensionArray> for Variant {
    fn from(v: MultiDimensionArray) -> Self {
        Variant::MultiDimensionArray(Box::new(v))
    }
}

/// A Variant holds all primitive types, including single and multi dimensional arrays and
/// data values.
///
/// Boxes are used for more complex types to keep the size of this enum down a bit.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
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
    /// array which should match the array length, otherwise BadDecodingError
    Array(Vec<Variant>),
    /// Multi dimension array
    /// A variant can be an array of other kinds (all of which must be the same type), second argument is the dimensions of the
    /// array which should match the array length, otherwise BadDecodingError
    /// Higher rank dimensions are serialized first. For example an array with dimensions [2,2,2] is written in this order:
    /// [0,0,0], [0,0,1], [0,1,0], [0,1,1], [1,0,0], [1,0,1], [1,1,0], [1,1,1]
    MultiDimensionArray(Box<MultiDimensionArray>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiDimensionArray {
    pub values: Vec<Variant>,
    pub dimensions: Vec<Int32>,
}

impl MultiDimensionArray {
    pub fn new(values: Vec<Variant>, dimensions: Vec<Int32>) -> MultiDimensionArray {
        MultiDimensionArray { values, dimensions }
    }

    pub fn is_valid_dimensions(&self) -> bool {
        // Check that the array dimensions match the length of the array
        let mut length: usize = 1;
        for d in &self.dimensions {
            // Check for invalid dimensions
            if *d <= 0 {
                return false;
            }
            length *= *d as usize;
        }
        length == self.values.len()
    }
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
            Variant::Array(ref values) => {
                // Array length
                let mut size = 4;
                // Size of each value
                size += values.iter().map(|v| Variant::byte_len_variant_value(v)).sum::<usize>();
                size
            }
            Variant::MultiDimensionArray(ref mda) => {
                // Array length
                let mut size = 4;
                // Size of each value
                size += mda.values.iter().map(|v| Variant::byte_len_variant_value(v)).sum::<usize>();
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
            Variant::Array(ref values) => {
                let mut size = write_i32(stream, values.len() as i32)?;
                for value in values.iter() {
                    size += Variant::encode_variant_value(stream, value)?;
                }
                size
            }
            Variant::MultiDimensionArray(ref mda) => {
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
                return Err(StatusCode::BadDecodingError);
            }
            array_length
        } else {
            -1
        };

        // Read the value(s). If array length was specified, we assume a single or multi dimension array
        let result = if array_length > 0 {
            // Array length in total cannot exceed max array length
            if array_length > constants::MAX_ARRAY_LENGTH as i32 {
                return Err(StatusCode::BadEncodingLimitsExceeded);
            }

            let mut result: Vec<Variant> = Vec::with_capacity(array_length as usize);
            for _ in 0..array_length {
                result.push(Variant::decode_variant_value(stream, element_encoding_mask)?);
            }
            if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
                let dimensions: Option<Vec<Int32>> = read_array(stream)?;
                if dimensions.is_none() {
                    error!("No array dimensions despite the bit flag being set");
                    return Err(StatusCode::BadDecodingError);
                }
                let dimensions = dimensions.unwrap();
                let mut array_dimensions_length = 1;
                for d in &dimensions {
                    if *d <= 0 {
                        error!("Invalid array dimension {}", *d);
                        return Err(StatusCode::BadDecodingError);
                    }
                    array_dimensions_length *= *d;
                }
                if array_dimensions_length != array_length {
                    error!("Array dimensions does not match array length {}", array_length);
                    Err(StatusCode::BadDecodingError)
                } else {
                    Ok(Variant::new_multi_dimension_array(result, dimensions))
                }
            } else {
                Ok(Variant::Array(result))
            }
        } else if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
            error!("Array dimensions bit specified without any values");
            Err(StatusCode::BadDecodingError)
        } else {
            // Read a single variant
            Variant::decode_variant_value(stream, element_encoding_mask)
        };
        result
    }
}

impl Default for Variant {
    fn default() -> Self {
        Variant::Empty
    }
}

/// This implementation is mainly for debugging / convenience purposes, to eliminate some of the
/// noise in common types from using the Debug trait.
impl ToString for Variant {
    fn to_string(&self) -> String {
        match self {
            &Variant::SByte(v) => format!("{}", v),
            &Variant::Byte(v) => format!("{}", v),
            &Variant::Int16(v) => format!("{}", v),
            &Variant::UInt16(v) => format!("{}", v),
            &Variant::Int32(v) => format!("{}", v),
            &Variant::UInt32(v) => format!("{}", v),
            &Variant::Int64(v) => format!("{}", v),
            &Variant::UInt64(v) => format!("{}", v),
            &Variant::Float(v) => format!("{}", v),
            &Variant::Double(v) => format!("{}", v),
            &Variant::Boolean(v) => format!("{}", v),
            &Variant::String(ref v) => v.to_string(),
            &Variant::Guid(ref v) => v.to_string(),
            &Variant::DateTime(ref v) => v.to_string(),
            value => format!("{:?}", value)
        }
    }
}

impl Variant {
    pub fn new<T>(value: T) -> Variant where T: 'static + Into<Variant> {
        value.into()
    }

    /// Test the flag (convenience method)
    pub fn test_encoding_flag(encoding_mask: u8, data_type_id: DataTypeId) -> bool {
        encoding_mask == data_type_id as u8
    }

    /// Returns the length of just the value, not the encoding flag
    fn byte_len_variant_value(value: &Variant) -> usize {
        let size = match *value {
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
            _ => {
                error!("Cannot compute length of this type (probably nested array)");
                0
            }
        };
        size
    }

    /// Encodes just the value, not the encoding flag
    fn encode_variant_value<S: Write>(stream: &mut S, value: &Variant) -> EncodingResult<usize> {
        match *value {
            Variant::Empty => Ok(0),
            Variant::Boolean(ref value) => value.encode(stream),
            Variant::SByte(ref value) => value.encode(stream),
            Variant::Byte(ref value) => value.encode(stream),
            Variant::Int16(ref value) => value.encode(stream),
            Variant::UInt16(ref value) => value.encode(stream),
            Variant::Int32(ref value) => value.encode(stream),
            Variant::UInt32(ref value) => value.encode(stream),
            Variant::Int64(ref value) => value.encode(stream),
            Variant::UInt64(ref value) => value.encode(stream),
            Variant::Float(ref value) => value.encode(stream),
            Variant::Double(ref value) => value.encode(stream),
            Variant::String(ref value) => value.encode(stream),
            Variant::DateTime(ref value) => value.encode(stream),
            Variant::Guid(ref value) => value.encode(stream),
            Variant::ByteString(ref value) => value.encode(stream),
            Variant::XmlElement(ref value) => value.encode(stream),
            Variant::NodeId(ref value) => value.encode(stream),
            Variant::ExpandedNodeId(ref value) => value.encode(stream),
            Variant::StatusCode(ref value) => value.encode(stream),
            Variant::QualifiedName(ref value) => value.encode(stream),
            Variant::LocalizedText(ref value) => value.encode(stream),
            Variant::ExtensionObject(ref value) => value.encode(stream),
            Variant::DataValue(ref value) => value.encode(stream),
            _ => {
                warn!("Cannot encode this variant value type (probably nested array)");
                Err(StatusCode::BadEncodingError)
            }
        }
    }

    /// Reads just the variant value from the stream
    fn decode_variant_value<S: Read>(stream: &mut S, encoding_mask: Byte) -> EncodingResult<Self> {
        let result = if encoding_mask == 0 {
            Variant::Empty
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Boolean) {
            Self::new(Boolean::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::SByte) {
            Self::new(SByte::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Byte) {
            Self::new(Byte::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Int16) {
            Self::new(Int16::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::UInt16) {
            Self::new(UInt16::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Int32) {
            Self::new(Int32::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::UInt32) {
            Self::new(UInt32::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Int64) {
            Self::new(Int64::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::UInt64) {
            Self::new(UInt64::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Float) {
            Self::new(Float::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Double) {
            Self::new(Double::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::String) {
            Self::new(UAString::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::DateTime) {
            Self::new(DateTime::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Guid) {
            Self::new(Guid::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::ByteString) {
            Self::new(ByteString::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::XmlElement) {
            Variant::XmlElement(XmlElement::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::NodeId) {
            Self::new(NodeId::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::ExpandedNodeId) {
            Self::new(ExpandedNodeId::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::StatusCode) {
            Self::new(StatusCode::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::QualifiedName) {
            Self::new(QualifiedName::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::LocalizedText) {
            Self::new(LocalizedText::decode(stream)?)
        } else if encoding_mask == 22 {
            Self::new(ExtensionObject::decode(stream)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::DataValue) {
            Self::new(DataValue::decode(stream)?)
        } else {
            Variant::Empty
        };
        Ok(result)
    }

    pub fn type_id(&self) -> VariantTypeId {
        match *self {
            Variant::Empty => VariantTypeId::Empty,
            Variant::Boolean(_) => VariantTypeId::Boolean,
            Variant::SByte(_) => VariantTypeId::SByte,
            Variant::Byte(_) => VariantTypeId::Byte,
            Variant::Int16(_) => VariantTypeId::Int16,
            Variant::UInt16(_) => VariantTypeId::UInt16,
            Variant::Int32(_) => VariantTypeId::Int32,
            Variant::UInt32(_) => VariantTypeId::UInt32,
            Variant::Int64(_) => VariantTypeId::Int64,
            Variant::UInt64(_) => VariantTypeId::UInt64,
            Variant::Float(_) => VariantTypeId::Float,
            Variant::Double(_) => VariantTypeId::Double,
            Variant::String(_) => VariantTypeId::String,
            Variant::DateTime(_) => VariantTypeId::DateTime,
            Variant::Guid(_) => VariantTypeId::Guid,
            Variant::ByteString(_) => VariantTypeId::ByteString,
            Variant::XmlElement(_) => VariantTypeId::XmlElement,
            Variant::NodeId(_) => VariantTypeId::NodeId,
            Variant::ExpandedNodeId(_) => VariantTypeId::ExpandedNodeId,
            Variant::StatusCode(_) => VariantTypeId::StatusCode,
            Variant::QualifiedName(_) => VariantTypeId::QualifiedName,
            Variant::LocalizedText(_) => VariantTypeId::LocalizedText,
            Variant::ExtensionObject(_) => VariantTypeId::ExtensionObject,
            Variant::DataValue(_) => VariantTypeId::DataValue,
            Variant::Array(_) => VariantTypeId::Array,
            Variant::MultiDimensionArray(_) => VariantTypeId::MultiDimensionArray,
        }
    }

    pub fn new_multi_dimension_array(values: Vec<Variant>, dimensions: Vec<Int32>) -> Variant {
        Variant::MultiDimensionArray(Box::new(MultiDimensionArray { values, dimensions }))
    }

    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        match *self {
            Variant::SByte(_) | Variant::Byte(_) |
            Variant::Int16(_) | Variant::UInt16(_) |
            Variant::Int32(_) | Variant::UInt32(_) |
            Variant::Int64(_) | Variant::UInt64(_) |
            Variant::Float(_) | Variant::Double(_) => true,
            _ => false
        }
    }

    /// Test if the variant holds an array
    pub fn is_array(&self) -> bool {
        match *self {
            Variant::Array(_) | Variant::MultiDimensionArray(_) => true,
            _ => false
        }
    }

    /// Tests and returns true if the variant is an array containing numeric values
    pub fn is_numeric_array(&self) -> bool {
        // A non-numeric value in the array means it is not numeric
        match *self {
            Variant::Array(ref values) => {
                Self::array_is_same_type(values, true)
            }
            Variant::MultiDimensionArray(ref mda) => {
                Self::array_is_same_type(&mda.values, true)
            }
            _ => {
                false
            }
        }
    }

    fn array_is_expected_type(values: &[Variant], expected_type_id: VariantTypeId) -> bool {
        if values.is_empty() {
            true
        } else {
            // Ensure all elements are the expected type
            values.iter().find(|v| {
                if v.type_id() != expected_type_id {
                    error!("Variant array's type is expected to be {:?} but found another type {:?} in it too", expected_type_id, v.type_id());
                    true
                } else {
                    false
                }
            }).is_none()
        }
    }

    /// Test that the vector of variants are all of the same type
    fn array_is_same_type(values: &[Variant], numeric_only: bool) -> bool {
        if values.is_empty() {
            true
        } else {
            let expected_type_id = values.get(0).unwrap().type_id();
            if numeric_only && !expected_type_id.is_numeric() {
                // Caller only wants numeric types
                false
            } else if expected_type_id == VariantTypeId::Array || expected_type_id == VariantTypeId::MultiDimensionArray {
                // Nested arrays are explicitly NOT allowed
                error!("Variant array contains nested array {:?}", expected_type_id);
                false
            } else {
                Self::array_is_expected_type(&values[1..], expected_type_id)
            }
        }
    }

    /// Tests that the variant is in a valid state. In particular for arrays ensuring that the
    /// values are all acceptable and for a multi dimensional array that the dimensions equal
    /// the actual values.
    pub fn is_valid(&self) -> bool {
        match *self {
            Variant::Array(ref values) => {
                Self::array_is_same_type(values, false)
            }
            Variant::MultiDimensionArray(ref mda) => {
                if mda.values.is_empty() && mda.dimensions.is_empty() {
                    // Check values all the same type
                    true
                } else {
                    // Check that the array dimensions match the length of the array
                    if !mda.is_valid_dimensions() {
                        false
                    } else {
                        // Check values are all the same type
                        Self::array_is_same_type(&mda.values, false)
                    }
                }
            }
            _ => {
                true
            }
        }
    }

    /// Converts the numeric type to a double or returns None
    pub fn as_f64(&self) -> Option<f64> {
        match *self {
            Variant::SByte(value) => Some(value as f64),
            Variant::Byte(value) => Some(value as f64),
            Variant::Int16(value) => Some(value as f64),
            Variant::UInt16(value) => Some(value as f64),
            Variant::Int32(value) => Some(value as f64),
            Variant::UInt32(value) => Some(value as f64),
            Variant::Int64(value) => {
                // NOTE: Int64 could overflow
                Some(value as f64)
            }
            Variant::UInt64(value) => {
                // NOTE: UInt64 could overflow
                Some(value as f64)
            }
            Variant::Float(value) => Some(value as f64),
            Variant::Double(value) => Some(value),
            _ => {
                None
            }
        }
    }

    pub fn from_i32_array(in_values: &[Int32]) -> Variant {
        let values = in_values.iter().map(|v| Variant::from(*v)).collect();
        Variant::Array(values)
    }

    pub fn from_u32_array(in_values: &[UInt32]) -> Variant {
        let values = in_values.iter().map(|v| Variant::from(*v)).collect();
        Variant::Array(values)
    }

    pub fn from_string_array(in_values: &[String]) -> Variant {
        let values = in_values.iter().map(|v| Variant::from(v.as_ref())).collect();
        Variant::Array(values)
    }

    /// Returns an array of UInt32s
    pub fn into_u32_array(&self) -> Result<Vec<UInt32>, StatusCode> {
        if self.is_numeric_array() {
            match *self {
                Variant::Array(ref values) => {
                    Ok(values.iter().map(|v| {
                        match *v {
                            Variant::UInt32(ref value) => *value,
                            Variant::SByte(ref value) => *value as u32,
                            Variant::Byte(ref value) => *value as u32,
                            Variant::Int16(ref value) => *value as u32,
                            Variant::UInt16(ref value) => *value as u32,
                            Variant::Int32(ref value) => *value as u32,
                            Variant::Int64(ref value) => *value as u32,
                            Variant::UInt64(ref value) => *value as u32,
                            Variant::Float(ref value) => *value as u32,
                            Variant::Double(ref value) => *value as u32,
                            _ => {
                                panic!("Expecting a numeric value in the numeric array");
                            }
                        }
                    }).collect::<Vec<UInt32>>())
                }
                _ => {
                    panic!("Not a numeric array");
                }
            }
        } else {
            error!("Variant is either not an array or does not hold numeric values");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    pub fn data_type(&self) -> Option<DataTypeId> {
        Some(match *self {
            Variant::Boolean(_) => DataTypeId::Boolean,
            Variant::SByte(_) => DataTypeId::SByte,
            Variant::Byte(_) => DataTypeId::Byte,
            Variant::Int16(_) => DataTypeId::Int16,
            Variant::UInt16(_) => DataTypeId::UInt16,
            Variant::Int32(_) => DataTypeId::Int32,
            Variant::UInt32(_) => DataTypeId::UInt32,
            Variant::Int64(_) => DataTypeId::Int64,
            Variant::UInt64(_) => DataTypeId::UInt64,
            Variant::Float(_) => DataTypeId::Float,
            Variant::Double(_) => DataTypeId::Double,
            Variant::String(_) => DataTypeId::String,
            Variant::DateTime(_) => DataTypeId::DateTime,
            Variant::Guid(_) => DataTypeId::Guid,
            Variant::ByteString(_) => DataTypeId::ByteString,
            Variant::XmlElement(_) => DataTypeId::XmlElement,
            Variant::NodeId(_) => DataTypeId::NodeId,
            Variant::ExpandedNodeId(_) => DataTypeId::ExpandedNodeId,
            Variant::StatusCode(_) => DataTypeId::StatusCode,
            Variant::QualifiedName(_) => DataTypeId::QualifiedName,
            Variant::LocalizedText(_) => DataTypeId::LocalizedText,
            Variant::DataValue(_) => DataTypeId::DataValue,
            _ => {
                return None;
            }
        })
    }

    // Gets the encoding mask to write the variant to disk
    fn get_encoding_mask(&self) -> u8 {
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
            Variant::Array(ref values) => {
                let mut encoding_mask = if values.is_empty() {
                    0u8
                } else {
                    values[0].get_encoding_mask()
                };
                encoding_mask |= ARRAY_VALUES_BIT;
                encoding_mask
            }
            Variant::MultiDimensionArray(ref mda) => {
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
