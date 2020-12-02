// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! Contains the implementation of `Variant`.

use std::convert::TryFrom;
use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;
use std::{i16, i32, i64, i8, u16, u32, u64, u8};

use crate::{
    array::*,
    byte_string::ByteString,
    date_time::DateTime,
    encoding::*,
    extension_object::ExtensionObject,
    guid::Guid,
    localized_text::LocalizedText,
    node_id::{ExpandedNodeId, Identifier, NodeId},
    node_ids::DataTypeId,
    numeric_range::NumericRange,
    qualified_name::QualifiedName,
    status_codes::StatusCode,
    string::{UAString, XmlElement},
};

/// A `Variant` holds built-in OPC UA data types, including single and multi dimensional arrays,
/// data values and extension objects.
///
/// As variants may be passed around a lot on the stack, Boxes are used for more complex types to
/// keep the size of this type down a bit, especially when used in arrays.
///
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Variant {
    /// Empty type has no value. It is equivalent to a Null value (part 6 5.1.6)
    Empty,
    /// Boolean
    Boolean(bool),
    /// Signed byte
    SByte(i8),
    /// Unsigned byte
    Byte(u8),
    /// Signed 16-bit int
    Int16(i16),
    /// Unsigned 16-bit int
    UInt16(u16),
    /// Signed 32-bit int
    Int32(i32),
    /// Unsigned 32-bit int
    UInt32(u32),
    /// Signed 64-bit int
    Int64(i64),
    /// Unsigned 64-bit int
    UInt64(u64),
    /// Float
    Float(f32),
    /// Double
    Double(f64),
    /// String
    String(UAString),
    /// DateTime
    DateTime(Box<DateTime>),
    /// Guid
    Guid(Box<Guid>),
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
    /// Single dimension array which can contain any scalar type, all the same type. Nested
    /// arrays will be rejected.
    Array(Box<Array>),
}

/// The variant type id is the type of the variant but without its payload.
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        match self {
            VariantTypeId::SByte
            | VariantTypeId::Byte
            | VariantTypeId::Int16
            | VariantTypeId::UInt16
            | VariantTypeId::Int32
            | VariantTypeId::UInt32
            | VariantTypeId::Int64
            | VariantTypeId::UInt64
            | VariantTypeId::Float
            | VariantTypeId::Double => true,
            _ => false,
        }
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

impl From<()> for Variant {
    fn from(_: ()) -> Self {
        Variant::Empty
    }
}

impl From<bool> for Variant {
    fn from(v: bool) -> Self {
        Variant::Boolean(v)
    }
}

impl From<u8> for Variant {
    fn from(v: u8) -> Self {
        Variant::Byte(v)
    }
}

impl From<i8> for Variant {
    fn from(v: i8) -> Self {
        Variant::SByte(v)
    }
}

impl From<i16> for Variant {
    fn from(v: i16) -> Self {
        Variant::Int16(v)
    }
}

impl From<u16> for Variant {
    fn from(v: u16) -> Self {
        Variant::UInt16(v)
    }
}

impl From<i32> for Variant {
    fn from(v: i32) -> Self {
        Variant::Int32(v)
    }
}

impl From<u32> for Variant {
    fn from(v: u32) -> Self {
        Variant::UInt32(v)
    }
}

impl From<i64> for Variant {
    fn from(v: i64) -> Self {
        Variant::Int64(v)
    }
}

impl From<u64> for Variant {
    fn from(v: u64) -> Self {
        Variant::UInt64(v)
    }
}

impl From<f32> for Variant {
    fn from(v: f32) -> Self {
        Variant::Float(v)
    }
}

impl From<f64> for Variant {
    fn from(v: f64) -> Self {
        Variant::Double(v)
    }
}

impl<'a> From<&'a str> for Variant {
    fn from(v: &'a str) -> Self {
        Variant::String(UAString::from(v))
    }
}

impl From<String> for Variant {
    fn from(v: String) -> Self {
        Variant::String(UAString::from(v))
    }
}

impl From<UAString> for Variant {
    fn from(v: UAString) -> Self {
        Variant::String(v)
    }
}

impl From<DateTime> for Variant {
    fn from(v: DateTime) -> Self {
        Variant::DateTime(Box::new(v))
    }
}

impl From<Guid> for Variant {
    fn from(v: Guid) -> Self {
        Variant::Guid(Box::new(v))
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

impl<'a, 'b> From<&'a [&'b str]> for Variant {
    fn from(v: &'a [&'b str]) -> Self {
        let values: Vec<Variant> = v.iter().map(|v| Variant::from(*v)).collect();
        Variant::from(Array::new_single(values))
    }
}

impl From<Vec<Variant>> for Variant {
    fn from(v: Vec<Variant>) -> Self {
        Variant::from(Array::new_single(v))
    }
}

impl From<(Vec<Variant>, Vec<u32>)> for Variant {
    fn from(v: (Vec<Variant>, Vec<u32>)) -> Self {
        Variant::from(Array::new_multi(v.0, v.1))
    }
}

impl From<Array> for Variant {
    fn from(v: Array) -> Self {
        Variant::Array(Box::new(v))
    }
}

macro_rules! cast_to_bool {
    ($value: expr) => {
        if $value == 1 {
            true.into()
        } else if $value == 0 {
            false.into()
        } else {
            Variant::Empty
        }
    };
}

macro_rules! cast_to_integer {
    ($value: expr, $from: ident, $to: ident) => {
        {
            // 64-bit values are the highest supported by OPC UA, so this code will cast
            // and compare values using signed / unsigned types to determine if they're in range.
            let valid = if $value < 0 as $from {
                // Negative values can only go into a signed type and only when the value is greater
                // or equal to the MIN
                $to::MIN != 0 && $value as i64 >= $to::MIN as i64
            } else {
                // Positive values can only go into the type only when the value is less than or equal
                // to the MAX.
                $value as u64 <= $to::MAX as u64
            };
            if !valid {
                // Value is out of range
                // error!("Value {} is outside of the range of receiving in type {}..{}", $value, $to::MIN, $to::MAX);
                Variant::Empty
            } else {
                ($value as $to).into()
            }
        }
    }
}

macro_rules! from_array_to_variant_impl {
    ($rtype: ident) => {
        impl<'a> From<&'a Vec<$rtype>> for Variant {
            fn from(v: &'a Vec<$rtype>) -> Self {
                Variant::from(v.as_slice())
            }
        }

        impl From<Vec<$rtype>> for Variant {
            fn from(v: Vec<$rtype>) -> Self {
                Variant::from(v.as_slice())
            }
        }

        impl<'a> From<&'a [$rtype]> for Variant {
            fn from(v: &'a [$rtype]) -> Self {
                let array: Vec<Variant> = v.iter().map(|v| Variant::from(v.clone())).collect();
                Variant::from(array)
            }
        }
    };
}

from_array_to_variant_impl!(String);
from_array_to_variant_impl!(bool);
from_array_to_variant_impl!(i8);
from_array_to_variant_impl!(u8);
from_array_to_variant_impl!(i16);
from_array_to_variant_impl!(u16);
from_array_to_variant_impl!(i32);
from_array_to_variant_impl!(u32);
from_array_to_variant_impl!(f32);
from_array_to_variant_impl!(f64);

/// This macro tries to return a `Vec<foo>` from a `Variant::Array<Variant::Foo>>`, e.g.
/// If the Variant holds
macro_rules! try_from_variant_to_array_impl {
    ($rtype: ident, $vtype: ident) => {
        impl TryFrom<&Variant> for Vec<$rtype> {
            type Error = ();

            fn try_from(value: &Variant) -> Result<Self, Self::Error> {
                match value {
                    Variant::Array(ref array) => {
                        let values = &array.values;
                        if !values_are_of_type(values, VariantTypeId::$vtype) {
                            Err(())
                        } else {
                            Ok(values
                                .iter()
                                .map(|v| {
                                    if let Variant::$vtype(v) = v {
                                        *v
                                    } else {
                                        panic!()
                                    }
                                })
                                .collect())
                        }
                    }
                    _ => Err(()),
                }
            }
        }
    };
}

// These are implementations of TryFrom which will attempt to transform a single dimension array
// in a Variant to the respective Vec<T> defined in the macro. All the variants must be of the correct
// type or the impl will return with an error.

try_from_variant_to_array_impl!(bool, Boolean);
try_from_variant_to_array_impl!(i8, SByte);
try_from_variant_to_array_impl!(u8, Byte);
try_from_variant_to_array_impl!(i16, Int16);
try_from_variant_to_array_impl!(u16, UInt16);
try_from_variant_to_array_impl!(i32, Int32);
try_from_variant_to_array_impl!(u32, UInt32);
try_from_variant_to_array_impl!(f32, Float);
try_from_variant_to_array_impl!(f64, Double);

impl BinaryEncoder<Variant> for Variant {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;

        // Encoding mask
        size += 1;

        // Value itself
        size += match self {
            Variant::Empty => 0,
            Variant::Boolean(value) => value.byte_len(),
            Variant::SByte(value) => value.byte_len(),
            Variant::Byte(value) => value.byte_len(),
            Variant::Int16(value) => value.byte_len(),
            Variant::UInt16(value) => value.byte_len(),
            Variant::Int32(value) => value.byte_len(),
            Variant::UInt32(value) => value.byte_len(),
            Variant::Int64(value) => value.byte_len(),
            Variant::UInt64(value) => value.byte_len(),
            Variant::Float(value) => value.byte_len(),
            Variant::Double(value) => value.byte_len(),
            Variant::String(value) => value.byte_len(),
            Variant::DateTime(value) => value.byte_len(),
            Variant::Guid(value) => value.byte_len(),
            Variant::ByteString(value) => value.byte_len(),
            Variant::XmlElement(value) => value.byte_len(),
            Variant::NodeId(value) => value.byte_len(),
            Variant::ExpandedNodeId(value) => value.byte_len(),
            Variant::StatusCode(value) => value.byte_len(),
            Variant::QualifiedName(value) => value.byte_len(),
            Variant::LocalizedText(value) => value.byte_len(),
            Variant::ExtensionObject(value) => value.byte_len(),
            Variant::Array(array) => {
                // Array length
                let mut size = 4;
                // Size of each value
                size += array
                    .values
                    .iter()
                    .map(|v| Variant::byte_len_variant_value(v))
                    .sum::<usize>();
                if array.has_dimensions() {
                    // Dimensions (size + num elements)
                    size += 4 + array.dimensions.len() * 4;
                }
                size
            }
        };
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;

        // Encoding mask will include the array bits if applicable for the type
        let encoding_mask = self.encoding_mask();
        size += write_u8(stream, encoding_mask)?;

        size += match self {
            Variant::Empty => 0,
            Variant::Boolean(value) => value.encode(stream)?,
            Variant::SByte(value) => value.encode(stream)?,
            Variant::Byte(value) => value.encode(stream)?,
            Variant::Int16(value) => value.encode(stream)?,
            Variant::UInt16(value) => value.encode(stream)?,
            Variant::Int32(value) => value.encode(stream)?,
            Variant::UInt32(value) => value.encode(stream)?,
            Variant::Int64(value) => value.encode(stream)?,
            Variant::UInt64(value) => value.encode(stream)?,
            Variant::Float(value) => value.encode(stream)?,
            Variant::Double(value) => value.encode(stream)?,
            Variant::String(value) => value.encode(stream)?,
            Variant::DateTime(value) => value.encode(stream)?,
            Variant::Guid(value) => value.encode(stream)?,
            Variant::ByteString(value) => value.encode(stream)?,
            Variant::XmlElement(value) => value.encode(stream)?,
            Variant::NodeId(value) => value.encode(stream)?,
            Variant::ExpandedNodeId(value) => value.encode(stream)?,
            Variant::StatusCode(value) => value.encode(stream)?,
            Variant::QualifiedName(value) => value.encode(stream)?,
            Variant::LocalizedText(value) => value.encode(stream)?,
            Variant::ExtensionObject(value) => value.encode(stream)?,
            Variant::Array(array) => {
                let mut size = write_i32(stream, array.values.len() as i32)?;
                for value in array.values.iter() {
                    size += Variant::encode_variant_value(stream, value)?;
                }
                if array.has_dimensions() {
                    // Note array dimensions are encoded as Int32 even though they are presented
                    // as UInt32 through attribute.

                    // Encode dimensions length
                    size += write_i32(stream, array.dimensions.len() as i32)?;
                    // Encode dimensions
                    for dimension in &array.dimensions {
                        size += write_i32(stream, *dimension as i32)?;
                    }
                }
                size
            }
        };
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let encoding_mask = u8::decode(stream, decoding_limits)?;
        let element_encoding_mask = encoding_mask & !(ARRAY_DIMENSIONS_BIT | ARRAY_VALUES_BIT);

        // Read array length
        let array_length = if encoding_mask & ARRAY_VALUES_BIT != 0 {
            let array_length = i32::decode(stream, decoding_limits)?;
            if array_length <= 0 {
                error!("Invalid array_length {}", array_length);
                return Err(StatusCode::BadDecodingError);
            }
            array_length
        } else {
            -1
        };

        // Read the value(s). If array length was specified, we assume a single or multi dimension array
        if array_length > 0 {
            // Array length in total cannot exceed max array length
            if array_length > decoding_limits.max_array_length as i32 {
                return Err(StatusCode::BadEncodingLimitsExceeded);
            }

            let mut values: Vec<Variant> = Vec::with_capacity(array_length as usize);
            for _ in 0..array_length {
                values.push(Variant::decode_variant_value(
                    stream,
                    element_encoding_mask,
                    decoding_limits,
                )?);
            }
            if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
                if let Some(dimensions) = read_array(stream, decoding_limits)? {
                    if let Some(_) = dimensions.iter().find(|d| **d <= 0) {
                        error!("Invalid array dimensions");
                        Err(StatusCode::BadDecodingError)
                    } else {
                        let array_dimensions_length =
                            dimensions.iter().fold(1u32, |sum, d| sum * *d);
                        if array_dimensions_length != array_length as u32 {
                            error!(
                                "Array dimensions does not match array length {}",
                                array_length
                            );
                            Err(StatusCode::BadDecodingError)
                        } else {
                            Ok(Variant::from((values, dimensions)))
                        }
                    }
                } else {
                    error!("No array dimensions despite the bit flag being set");
                    Err(StatusCode::BadDecodingError)
                }
            } else {
                Ok(Variant::from(values))
            }
        } else if encoding_mask & ARRAY_DIMENSIONS_BIT != 0 {
            error!("Array dimensions bit specified without any values");
            Err(StatusCode::BadDecodingError)
        } else {
            // Read a single variant
            Variant::decode_variant_value(stream, element_encoding_mask, decoding_limits)
        }
    }
}

impl Default for Variant {
    fn default() -> Self {
        Variant::Empty
    }
}

/// This implementation is mainly for debugging / convenience purposes, to eliminate some of the
/// noise in common types from using the Debug trait.
impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Variant::SByte(v) => write!(f, "{}", v),
            Variant::Byte(v) => write!(f, "{}", v),
            Variant::Int16(v) => write!(f, "{}", v),
            Variant::UInt16(v) => write!(f, "{}", v),
            Variant::Int32(v) => write!(f, "{}", v),
            Variant::UInt32(v) => write!(f, "{}", v),
            Variant::Int64(v) => write!(f, "{}", v),
            Variant::UInt64(v) => write!(f, "{}", v),
            Variant::Float(v) => write!(f, "{}", v),
            Variant::Double(v) => write!(f, "{}", v),
            Variant::Boolean(v) => write!(f, "{}", v),
            Variant::String(ref v) => write!(f, "{}", v.to_string()),
            Variant::Guid(ref v) => write!(f, "{}", v.to_string()),
            Variant::DateTime(ref v) => write!(f, "{}", v.to_string()),
            value => write!(f, "{:?}", value),
        }
    }
}

impl Variant {
    /// Test the flag (convenience method)
    pub fn test_encoding_flag(encoding_mask: u8, data_type_id: DataTypeId) -> bool {
        encoding_mask == data_type_id as u8
    }

    /// Returns the length of just the value, not the encoding flag
    fn byte_len_variant_value(value: &Variant) -> usize {
        match value {
            Variant::Empty => 0,
            Variant::Boolean(value) => value.byte_len(),
            Variant::SByte(value) => value.byte_len(),
            Variant::Byte(value) => value.byte_len(),
            Variant::Int16(value) => value.byte_len(),
            Variant::UInt16(value) => value.byte_len(),
            Variant::Int32(value) => value.byte_len(),
            Variant::UInt32(value) => value.byte_len(),
            Variant::Int64(value) => value.byte_len(),
            Variant::UInt64(value) => value.byte_len(),
            Variant::Float(value) => value.byte_len(),
            Variant::Double(value) => value.byte_len(),
            Variant::String(value) => value.byte_len(),
            Variant::DateTime(value) => value.byte_len(),
            Variant::Guid(value) => value.byte_len(),
            Variant::ByteString(value) => value.byte_len(),
            Variant::XmlElement(value) => value.byte_len(),
            Variant::NodeId(value) => value.byte_len(),
            Variant::ExpandedNodeId(value) => value.byte_len(),
            Variant::StatusCode(value) => value.byte_len(),
            Variant::QualifiedName(value) => value.byte_len(),
            Variant::LocalizedText(value) => value.byte_len(),
            Variant::ExtensionObject(value) => value.byte_len(),
            _ => {
                error!("Cannot compute length of this type (probably nested array)");
                0
            }
        }
    }

    /// Encodes just the value, not the encoding flag
    fn encode_variant_value<S: Write>(stream: &mut S, value: &Variant) -> EncodingResult<usize> {
        match value {
            Variant::Empty => Ok(0),
            Variant::Boolean(value) => value.encode(stream),
            Variant::SByte(value) => value.encode(stream),
            Variant::Byte(value) => value.encode(stream),
            Variant::Int16(value) => value.encode(stream),
            Variant::UInt16(value) => value.encode(stream),
            Variant::Int32(value) => value.encode(stream),
            Variant::UInt32(value) => value.encode(stream),
            Variant::Int64(value) => value.encode(stream),
            Variant::UInt64(value) => value.encode(stream),
            Variant::Float(value) => value.encode(stream),
            Variant::Double(value) => value.encode(stream),
            Variant::String(value) => value.encode(stream),
            Variant::DateTime(value) => value.encode(stream),
            Variant::Guid(value) => value.encode(stream),
            Variant::ByteString(value) => value.encode(stream),
            Variant::XmlElement(value) => value.encode(stream),
            Variant::NodeId(value) => value.encode(stream),
            Variant::ExpandedNodeId(value) => value.encode(stream),
            Variant::StatusCode(value) => value.encode(stream),
            Variant::QualifiedName(value) => value.encode(stream),
            Variant::LocalizedText(value) => value.encode(stream),
            Variant::ExtensionObject(value) => value.encode(stream),
            _ => {
                warn!("Cannot encode this variant value type (probably nested array)");
                Err(StatusCode::BadEncodingError)
            }
        }
    }

    /// Reads just the variant value from the stream
    fn decode_variant_value<S: Read>(
        stream: &mut S,
        encoding_mask: u8,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let result = if encoding_mask == 0 {
            Variant::Empty
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Boolean) {
            Self::from(bool::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::SByte) {
            Self::from(i8::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Byte) {
            Self::from(u8::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Int16) {
            Self::from(i16::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::UInt16) {
            Self::from(u16::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Int32) {
            Self::from(i32::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::UInt32) {
            Self::from(u32::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Int64) {
            Self::from(i64::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::UInt64) {
            Self::from(u64::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Float) {
            Self::from(f32::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Double) {
            Self::from(f64::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::String) {
            Self::from(UAString::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::DateTime) {
            Self::from(DateTime::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::Guid) {
            Self::from(Guid::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::ByteString) {
            Self::from(ByteString::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::XmlElement) {
            // Force the type to be XmlElement since its typedef'd to UAString
            Variant::XmlElement(XmlElement::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::NodeId) {
            Self::from(NodeId::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::ExpandedNodeId) {
            Self::from(ExpandedNodeId::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::StatusCode) {
            Self::from(StatusCode::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::QualifiedName) {
            Self::from(QualifiedName::decode(stream, decoding_limits)?)
        } else if Self::test_encoding_flag(encoding_mask, DataTypeId::LocalizedText) {
            Self::from(LocalizedText::decode(stream, decoding_limits)?)
        } else if encoding_mask == 22 {
            Self::from(ExtensionObject::decode(stream, decoding_limits)?)
        } else {
            Variant::Empty
        };
        Ok(result)
    }

    /// Performs an EXPLICIT cast from one type to another. This will first attempt an implicit
    /// conversion and only then attempt to cast. Casting is potentially lossy.
    pub fn cast(&self, target_type: VariantTypeId) -> Variant {
        let result = self.convert(target_type);
        if result == Variant::Empty {
            match *self {
                Variant::Boolean(v) => match target_type {
                    VariantTypeId::String => {
                        UAString::from(if v { "true" } else { "false" }).into()
                    }
                    _ => Variant::Empty,
                },
                Variant::Byte(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                },
                Variant::Double(v) => {
                    // Truncated value used in integer conversions
                    let vt = f64::trunc(v + 0.5);
                    match target_type {
                        VariantTypeId::Boolean => cast_to_bool!(v as i64),
                        VariantTypeId::Byte => cast_to_integer!(vt, f64, u8),
                        VariantTypeId::Float => (v as f32).into(),
                        VariantTypeId::Int16 => cast_to_integer!(vt, f64, i16),
                        VariantTypeId::Int32 => cast_to_integer!(vt, f64, i32),
                        VariantTypeId::Int64 => cast_to_integer!(vt, f64, i64),
                        VariantTypeId::SByte => cast_to_integer!(vt, f64, i8),
                        VariantTypeId::String => format!("{}", v).into(),
                        VariantTypeId::UInt16 => cast_to_integer!(vt, f64, u16),
                        VariantTypeId::UInt32 => cast_to_integer!(vt, f64, u32),
                        VariantTypeId::UInt64 => cast_to_integer!(vt, f64, u64),
                        _ => Variant::Empty,
                    }
                }
                Variant::ByteString(ref v) => match target_type {
                    VariantTypeId::Guid => Guid::try_from(v)
                        .map(|v| v.into())
                        .unwrap_or(Variant::Empty),
                    _ => Variant::Empty,
                },
                Variant::DateTime(ref v) => match target_type {
                    VariantTypeId::String => format!("{}", *v).into(),
                    _ => Variant::Empty,
                },
                Variant::ExpandedNodeId(ref v) => match target_type {
                    VariantTypeId::NodeId => v.node_id.clone().into(),
                    _ => Variant::Empty,
                },
                Variant::Float(v) => {
                    let vt = f32::trunc(v + 0.5);
                    match target_type {
                        VariantTypeId::Boolean => cast_to_bool!(v as i64),
                        VariantTypeId::Byte => cast_to_integer!(vt, f32, u8),
                        VariantTypeId::Int16 => cast_to_integer!(vt, f32, i16),
                        VariantTypeId::Int32 => cast_to_integer!(vt, f32, i32),
                        VariantTypeId::Int64 => cast_to_integer!(vt, f32, i64),
                        VariantTypeId::SByte => cast_to_integer!(vt, f32, i8),
                        VariantTypeId::String => format!("{}", v).into(),
                        VariantTypeId::UInt16 => cast_to_integer!(vt, f32, u16),
                        VariantTypeId::UInt32 => cast_to_integer!(vt, f32, u32),
                        VariantTypeId::UInt64 => cast_to_integer!(vt, f32, u64),
                        _ => Variant::Empty,
                    }
                }
                Variant::Guid(ref v) => match target_type {
                    VariantTypeId::String => format!("{}", *v).into(),
                    VariantTypeId::ByteString => ByteString::from(v.as_ref().clone()).into(),
                    _ => Variant::Empty,
                },
                Variant::Int16(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, i16, u8),
                    VariantTypeId::SByte => cast_to_integer!(v, i16, i8),
                    VariantTypeId::String => format!("{}", v).into(),
                    VariantTypeId::UInt16 => cast_to_integer!(v, i16, u16),
                    _ => Variant::Empty,
                },
                Variant::Int32(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, i32, u8),
                    VariantTypeId::Int16 => cast_to_integer!(v, i32, i16),
                    VariantTypeId::SByte => cast_to_integer!(v, i32, i8),
                    VariantTypeId::StatusCode => (StatusCode::from_bits_truncate(v as u32)).into(),
                    VariantTypeId::String => format!("{}", v).into(),
                    VariantTypeId::UInt16 => cast_to_integer!(v, i32, u16),
                    VariantTypeId::UInt32 => cast_to_integer!(v, i32, u32),
                    _ => Variant::Empty,
                },
                Variant::Int64(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, i64, u8),
                    VariantTypeId::Int16 => cast_to_integer!(v, i64, i16),
                    VariantTypeId::Int32 => cast_to_integer!(v, i64, i32),
                    VariantTypeId::SByte => cast_to_integer!(v, i64, i8),
                    VariantTypeId::StatusCode => StatusCode::from_bits_truncate(v as u32).into(),
                    VariantTypeId::String => format!("{}", v).into(),
                    VariantTypeId::UInt16 => cast_to_integer!(v, i64, u16),
                    VariantTypeId::UInt32 => cast_to_integer!(v, i64, u32),
                    VariantTypeId::UInt64 => cast_to_integer!(v, i64, u64),
                    _ => Variant::Empty,
                },
                Variant::SByte(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, i8, u8),
                    VariantTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                },
                Variant::StatusCode(v) => match target_type {
                    VariantTypeId::UInt16 => (((v.bits() & 0xffff_0000) >> 16) as u16).into(),
                    _ => Variant::Empty,
                },
                Variant::String(ref v) => match target_type {
                    VariantTypeId::NodeId => {
                        if v.is_null() {
                            Variant::Empty
                        } else {
                            NodeId::from_str(v.as_ref())
                                .map(|v| v.into())
                                .unwrap_or(Variant::Empty)
                        }
                    }
                    VariantTypeId::ExpandedNodeId => {
                        if v.is_null() {
                            Variant::Empty
                        } else {
                            ExpandedNodeId::from_str(v.as_ref())
                                .map(|v| v.into())
                                .unwrap_or(Variant::Empty)
                        }
                    }
                    VariantTypeId::DateTime => {
                        if v.is_null() {
                            Variant::Empty
                        } else {
                            DateTime::from_str(v.as_ref())
                                .map(|v| v.into())
                                .unwrap_or(Variant::Empty)
                        }
                    }
                    VariantTypeId::LocalizedText => {
                        if v.is_null() {
                            LocalizedText::null().into()
                        } else {
                            LocalizedText::new("", v.as_ref()).into()
                        }
                    }
                    VariantTypeId::QualifiedName => {
                        if v.is_null() {
                            QualifiedName::null().into()
                        } else {
                            QualifiedName::new(0, v.as_ref()).into()
                        }
                    }
                    _ => Variant::Empty,
                },
                Variant::UInt16(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, u16, u8),
                    VariantTypeId::SByte => cast_to_integer!(v, u16, i8),
                    VariantTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                },
                Variant::UInt32(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, u32, u8),
                    VariantTypeId::Int16 => cast_to_integer!(v, u32, i16),
                    VariantTypeId::SByte => cast_to_integer!(v, u32, i8),
                    VariantTypeId::StatusCode => StatusCode::from_bits_truncate(v).into(),
                    VariantTypeId::String => format!("{}", v).into(),
                    VariantTypeId::UInt16 => cast_to_integer!(v, u32, u16),
                    _ => Variant::Empty,
                },
                Variant::UInt64(v) => match target_type {
                    VariantTypeId::Boolean => cast_to_bool!(v),
                    VariantTypeId::Byte => cast_to_integer!(v, u64, u8),
                    VariantTypeId::Int16 => cast_to_integer!(v, u64, i16),
                    VariantTypeId::SByte => cast_to_integer!(v, u64, i8),
                    VariantTypeId::StatusCode => {
                        StatusCode::from_bits_truncate((v & 0x0000_0000_ffff_ffff) as u32).into()
                    }
                    VariantTypeId::String => format!("{}", v).into(),
                    VariantTypeId::UInt16 => cast_to_integer!(v, u64, u16),
                    VariantTypeId::UInt32 => cast_to_integer!(v, u64, u32),
                    _ => Variant::Empty,
                },

                // NodeId, LocalizedText, QualifiedName, XmlElement have no explicit cast
                _ => Variant::Empty,
            }
        } else {
            result
        }
    }

    /// Performs an IMPLICIT conversion from one type to another
    pub fn convert(&self, target_type: VariantTypeId) -> Variant {
        if self.type_id() == target_type {
            return self.clone();
        }

        // See OPC UA Part 4 table 118
        match *self {
            Variant::Boolean(v) => {
                // true == 1, false == 0
                match target_type {
                    VariantTypeId::Byte => (v as u8).into(),
                    VariantTypeId::Double => ((v as u8) as f64).into(),
                    VariantTypeId::Float => ((v as u8) as f32).into(),
                    VariantTypeId::Int16 => (v as i16).into(),
                    VariantTypeId::Int32 => (v as i32).into(),
                    VariantTypeId::Int64 => (v as i64).into(),
                    VariantTypeId::SByte => (v as i8).into(),
                    VariantTypeId::UInt16 => (v as u16).into(),
                    VariantTypeId::UInt32 => (v as u32).into(),
                    VariantTypeId::UInt64 => (v as u64).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::Byte(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                VariantTypeId::Int16 => (v as i16).into(),
                VariantTypeId::Int32 => (v as i32).into(),
                VariantTypeId::Int64 => (v as i64).into(),
                VariantTypeId::SByte => (v as i8).into(),
                VariantTypeId::UInt16 => (v as u16).into(),
                VariantTypeId::UInt32 => (v as u32).into(),
                VariantTypeId::UInt64 => (v as u64).into(),
                _ => Variant::Empty,
            },

            // ByteString - everything is X or E except to itself
            // DateTime - everything is X or E except to itself
            // Double - everything is X or E except to itself
            Variant::ExpandedNodeId(ref v) => {
                // Everything is X or E except to String
                match target_type {
                    VariantTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::Float(v) => {
                // Everything is X or E except to Double
                match target_type {
                    VariantTypeId::Double => (v as f64).into(),
                    _ => Variant::Empty,
                }
            }

            // Guid - everything is X or E except to itself
            Variant::Int16(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                VariantTypeId::Int32 => (v as i32).into(),
                VariantTypeId::Int64 => (v as i64).into(),
                VariantTypeId::UInt32 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u32).into()
                    }
                }
                VariantTypeId::UInt64 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u64).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::Int32(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                VariantTypeId::Int64 => (v as i64).into(),
                VariantTypeId::UInt64 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u64).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::Int64(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                _ => Variant::Empty,
            },
            Variant::NodeId(ref v) => {
                // Guid - everything is X or E except to ExpandedNodeId and String
                match target_type {
                    VariantTypeId::ExpandedNodeId => ExpandedNodeId::from(*v.clone()).into(),
                    VariantTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::SByte(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                VariantTypeId::Int16 => (v as i16).into(),
                VariantTypeId::Int32 => (v as i32).into(),
                VariantTypeId::Int64 => (v as i64).into(),
                VariantTypeId::UInt16 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u16).into()
                    }
                }
                VariantTypeId::UInt32 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u32).into()
                    }
                }
                VariantTypeId::UInt64 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u64).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::StatusCode(v) => match target_type {
                VariantTypeId::Int32 => (v.bits() as i32).into(),
                VariantTypeId::Int64 => (v.bits() as i64).into(),
                VariantTypeId::UInt32 => (v.bits() as u32).into(),
                VariantTypeId::UInt64 => (v.bits() as u64).into(),
                _ => Variant::Empty,
            },
            Variant::String(ref v) => {
                if v.is_empty() {
                    Variant::Empty
                } else {
                    let v = v.as_ref();
                    match target_type {
                        VariantTypeId::Boolean => {
                            // String values containing “true”, “false”, “1” or “0” can be converted
                            // to Boolean values. Other string values cause a conversion error. In
                            // this case Strings are case-insensitive.
                            if v == "true" || v == "1" {
                                true.into()
                            } else if v == "false" || v == "0" {
                                false.into()
                            } else {
                                Variant::Empty
                            }
                        }
                        VariantTypeId::Byte => {
                            u8::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::Double => {
                            f64::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::Float => {
                            f32::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::Guid => Guid::from_str(v)
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty),
                        VariantTypeId::Int16 => {
                            i16::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::Int32 => {
                            i32::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::Int64 => {
                            i64::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::NodeId => NodeId::from_str(v)
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty),
                        VariantTypeId::SByte => {
                            i8::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::UInt16 => {
                            u16::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::UInt32 => {
                            u32::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantTypeId::UInt64 => {
                            u64::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        _ => Variant::Empty,
                    }
                }
            }
            Variant::LocalizedText(ref v) => match target_type {
                VariantTypeId::String => v.text.clone().into(),
                _ => Variant::Empty,
            },
            Variant::QualifiedName(ref v) => {
                match target_type {
                    VariantTypeId::String => {
                        if v.is_null() {
                            UAString::null().into()
                        } else {
                            // drop the namespace index
                            v.name.clone().into()
                        }
                    }
                    VariantTypeId::LocalizedText => {
                        if v.is_null() {
                            LocalizedText::null().into()
                        } else {
                            // empty locale, drop namespace index
                            LocalizedText::new("", v.name.as_ref()).into()
                        }
                    }
                    _ => Variant::Empty,
                }
            }
            Variant::UInt16(v) => {
                match target_type {
                    VariantTypeId::Double => (v as f64).into(),
                    VariantTypeId::Float => (v as f32).into(),
                    VariantTypeId::Int16 => (v as i16).into(),
                    VariantTypeId::Int32 => (v as i32).into(),
                    VariantTypeId::Int64 => (v as i64).into(),
                    VariantTypeId::StatusCode => {
                        // The 16-bit value is treated as the top 16 bits of the status code
                        StatusCode::from_bits_truncate((v as u32) << 16).into()
                    }
                    VariantTypeId::UInt32 => (v as u32).into(),
                    VariantTypeId::UInt64 => (v as u64).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::UInt32(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                VariantTypeId::Int32 => (v as i32).into(),
                VariantTypeId::Int64 => (v as i64).into(),
                VariantTypeId::UInt64 => (v as u64).into(),
                _ => Variant::Empty,
            },
            Variant::UInt64(v) => match target_type {
                VariantTypeId::Double => (v as f64).into(),
                VariantTypeId::Float => (v as f32).into(),
                VariantTypeId::Int64 => (v as i64).into(),
                _ => Variant::Empty,
            },
            Variant::Array(_) => {
                // TODO Arrays including converting array of length 1 to scalar of same type
                Variant::Empty
            }
            // XmlElement everything is X
            _ => Variant::Empty,
        }
    }

    pub fn type_id(&self) -> VariantTypeId {
        match self {
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
            Variant::Array(_) => VariantTypeId::Array,
        }
    }

    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        match self {
            Variant::SByte(_)
            | Variant::Byte(_)
            | Variant::Int16(_)
            | Variant::UInt16(_)
            | Variant::Int32(_)
            | Variant::UInt32(_)
            | Variant::Int64(_)
            | Variant::UInt64(_)
            | Variant::Float(_)
            | Variant::Double(_) => true,
            _ => false,
        }
    }

    /// Test if the variant holds an array
    pub fn is_array(&self) -> bool {
        match self {
            Variant::Array(_) => true,
            _ => false,
        }
    }

    pub fn is_array_of_type(&self, variant_type: VariantTypeId) -> bool {
        // A non-numeric value in the array means it is not numeric
        match self {
            Variant::Array(array) => values_are_of_type(array.values.as_slice(), variant_type),
            _ => false,
        }
    }

    /// Tests that the variant is in a valid state. In particular for arrays ensuring that the
    /// values are all acceptable and for a multi dimensional array that the dimensions equal
    /// the actual values.
    pub fn is_valid(&self) -> bool {
        match self {
            Variant::Array(array) => array.is_valid(),
            _ => true,
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
            _ => None,
        }
    }

    // Returns the data type of elements in array. Returns None if this is not an array or type
    // cannot be determined
    pub fn array_data_type(&self) -> Option<NodeId> {
        match self {
            Variant::Array(array) => {
                if array.values.is_empty() {
                    error!("Cannot get the data type of an empty array");
                    None
                } else {
                    array.values[0].scalar_data_type()
                }
            }
            _ => None,
        }
    }

    // Returns the scalar data type. Returns None for arrays
    pub fn scalar_data_type(&self) -> Option<NodeId> {
        match self {
            Variant::Boolean(_) => Some(DataTypeId::Boolean.into()),
            Variant::SByte(_) => Some(DataTypeId::SByte.into()),
            Variant::Byte(_) => Some(DataTypeId::Byte.into()),
            Variant::Int16(_) => Some(DataTypeId::Int16.into()),
            Variant::UInt16(_) => Some(DataTypeId::UInt16.into()),
            Variant::Int32(_) => Some(DataTypeId::Int32.into()),
            Variant::UInt32(_) => Some(DataTypeId::UInt32.into()),
            Variant::Int64(_) => Some(DataTypeId::Int64.into()),
            Variant::UInt64(_) => Some(DataTypeId::UInt64.into()),
            Variant::Float(_) => Some(DataTypeId::Float.into()),
            Variant::Double(_) => Some(DataTypeId::Double.into()),
            Variant::String(_) => Some(DataTypeId::String.into()),
            Variant::DateTime(_) => Some(DataTypeId::DateTime.into()),
            Variant::Guid(_) => Some(DataTypeId::Guid.into()),
            Variant::ByteString(_) => Some(DataTypeId::ByteString.into()),
            Variant::XmlElement(_) => Some(DataTypeId::XmlElement.into()),
            Variant::NodeId(_) => Some(DataTypeId::NodeId.into()),
            Variant::ExpandedNodeId(_) => Some(DataTypeId::ExpandedNodeId.into()),
            Variant::StatusCode(_) => Some(DataTypeId::StatusCode.into()),
            Variant::QualifiedName(_) => Some(DataTypeId::QualifiedName.into()),
            Variant::LocalizedText(_) => Some(DataTypeId::LocalizedText.into()),
            _ => None,
        }
    }

    // Gets the encoding mask to write the variant to disk
    pub(crate) fn encoding_mask(&self) -> u8 {
        match self {
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
            Variant::Array(array) => {
                let mut encoding_mask = if array.values.is_empty() {
                    0u8
                } else {
                    array.values[0].encoding_mask()
                };
                encoding_mask |= ARRAY_VALUES_BIT;
                if array.has_dimensions() {
                    encoding_mask |= ARRAY_DIMENSIONS_BIT;
                }
                encoding_mask
            }
        }
    }

    /// This function is for a special edge case of converting a byte string to a
    /// single array of bytes
    pub fn to_byte_array(&self) -> Self {
        match self {
            Variant::ByteString(values) => match &values.value {
                None => Variant::from(Array::new_single(vec![])),
                Some(values) => {
                    let values: Vec<Variant> = values.iter().map(|v| Variant::Byte(*v)).collect();
                    Variant::from(Array::new_single(values))
                }
            },
            _ => panic!(),
        }
    }

    /// This function returns a substring of a ByteString or a UAString
    fn substring(&self, min: usize, max: usize) -> Result<Variant, StatusCode> {
        match self {
            Variant::ByteString(v) => v
                .substring(min, max)
                .map(|v| v.into())
                .map_err(|_| StatusCode::BadIndexRangeNoData),
            Variant::String(v) => v
                .substring(min, max)
                .map(|v| v.into())
                .map_err(|_| StatusCode::BadIndexRangeNoData),
            _ => panic!("Should not be calling substring on other types"),
        }
    }

    pub fn eq_scalar_type(&self, other: &Variant) -> bool {
        let self_data_type = self.scalar_data_type();
        let other_data_type = other.scalar_data_type();
        if self_data_type.is_none() || other_data_type.is_none() {
            false
        } else {
            self_data_type == other_data_type
        }
    }

    pub fn eq_array_type(&self, other: &Variant) -> bool {
        // array
        let self_data_type = self.array_data_type();
        let other_data_type = other.array_data_type();
        if self_data_type.is_none() || other_data_type.is_none() {
            false
        } else {
            self_data_type == other_data_type
        }
    }

    pub fn set_range_of(&mut self, range: NumericRange, other: &Variant) -> Result<(), StatusCode> {
        // Types need to be the same
        if !self.eq_array_type(other) {
            return Err(StatusCode::BadIndexRangeNoData);
        }

        let other_array = if let Variant::Array(other) = other {
            other
        } else {
            return Err(StatusCode::BadIndexRangeNoData);
        };
        let other_values = &other_array.values;

        // Check value is same type as our array
        match self {
            Variant::Array(ref mut array) => {
                let values = &mut array.values;
                match range {
                    NumericRange::None => Err(StatusCode::BadIndexRangeNoData),
                    NumericRange::Index(idx) => {
                        let idx = idx as usize;
                        if idx >= values.len() {
                            Err(StatusCode::BadIndexRangeNoData)
                        } else if other_values.is_empty() {
                            Err(StatusCode::BadIndexRangeNoData)
                        } else {
                            values[idx] = other_values[0].clone();
                            Ok(())
                        }
                    }
                    NumericRange::Range(min, max) => {
                        let (min, max) = (min as usize, max as usize);
                        if min >= values.len() {
                            Err(StatusCode::BadIndexRangeNoData)
                        } else {
                            // Possibly this could splice or something but it's trying to copy elements
                            // until either the source or destination array is finished.
                            let mut idx = min;
                            while idx < values.len() && idx <= max && idx - min < other_values.len()
                            {
                                values[idx] = other_values[idx - min].clone();
                                idx += 1;
                            }
                            Ok(())
                        }
                    }
                    NumericRange::MultipleRanges(_ranges) => {
                        // Not yet supported
                        error!("Multiple ranges not supported");
                        Err(StatusCode::BadIndexRangeNoData)
                    }
                }
            }
            _ => {
                error!("Writing a range is not supported when the recipient is not an array");
                Err(StatusCode::BadWriteNotSupported)
            }
        }
    }

    /// This function gets a range of values from the variant if it is an array, or returns a clone
    /// of the variant itself.
    pub fn range_of(&self, range: NumericRange) -> Result<Variant, StatusCode> {
        match range {
            NumericRange::None => Ok(self.clone()),
            NumericRange::Index(idx) => {
                let idx = idx as usize;
                match self {
                    Variant::String(_) | Variant::ByteString(_) => self.substring(idx, idx),
                    Variant::Array(array) => {
                        // Get value at the index (or not)
                        let values = &array.values;
                        if let Some(v) = values.get(idx) {
                            let values = vec![v.clone()];
                            Ok(Variant::from(values))
                        } else {
                            Err(StatusCode::BadIndexRangeNoData)
                        }
                    }
                    _ => Err(StatusCode::BadIndexRangeNoData),
                }
            }
            NumericRange::Range(min, max) => {
                let (min, max) = (min as usize, max as usize);
                match self {
                    Variant::String(_) | Variant::ByteString(_) => self.substring(min, max),
                    Variant::Array(array) => {
                        let values = &array.values;
                        if min >= values.len() {
                            // Min must be in range
                            Err(StatusCode::BadIndexRangeNoData)
                        } else {
                            let max = if max >= values.len() {
                                values.len() - 1
                            } else {
                                max
                            };
                            let vals = &values[min as usize..=max];
                            let vals: Vec<Variant> = vals.iter().map(|v| v.clone()).collect();
                            Ok(Variant::from(vals))
                        }
                    }
                    _ => Err(StatusCode::BadIndexRangeNoData),
                }
            }
            NumericRange::MultipleRanges(_ranges) => {
                // Not yet supported
                error!("Multiple ranges not supported");
                Err(StatusCode::BadIndexRangeNoData)
            }
        }
    }
}
