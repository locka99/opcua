// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Implements the JSON serialization functionality for Variant. OPC UA serialization over JSON is
//! described by Part 6 of the spec in not a whole lot of detail, so this implementation tries its best to implement
//! it as described. In some places there may be ambiguity, e.g. whether a null field corresponds to
//! null in one of the types. In addition, serialization of JSON is so different than the binary form
//! that it doesn't share any code with OPC UA binary.
//!
//! Serialization is implemented as REVERSIBLE, i.e. the format written out can be used to deserialize back
//! to the original type. In addition, reversible means some data such as `StatusCode`, `NodeId` and
//! `ExpandedNodeId` is written a certain way.
//!
//! To distinguish between binary and JSON, the built-in types implement Serde's `Serialize`/`Deserialize`
//! traits for JSON serialization.

use std::{fmt, i32};

use serde::{
    de, de::DeserializeOwned, de::Error, Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::json;

use crate::types::{
    data_value::DataValue, date_time::DateTime, diagnostic_info::DiagnosticInfo,
    expanded_node_id::ExpandedNodeId, extension_object::ExtensionObject, guid::Guid,
    localized_text::LocalizedText, node_id::NodeId, qualified_name::QualifiedName,
    string::UAString, variant::Variant, ByteString, StatusCode,
};

/// This enum represents the scalar "Type" used for JSON serializing of variants as defined in Part 6 5.1.2.
///
/// It is almost but it not the same as the DataTypeId
///
/// 1 	Boolean 	A two-state logical value (true or false).
/// 2 	SByte 	An integer value between −128 and 127 inclusive.
/// 3 	Byte 	An integer value between 0 and 255 inclusive.
/// 4 	Int16 	An integer value between −32 768 and 32 767 inclusive.
/// 5 	UInt16 	An integer value between 0 and 65 535 inclusive.
/// 6 	Int32 	An integer value between −2 147 483 648 and 2 147 483 647 inclusive.
/// 7 	UInt32 	An integer value between 0 and 4 294 967 295 inclusive.
/// 8 	Int64 	An integer value between −9 223 372 036 854 775 808 and 9 223 372 036 854 775 807 inclusive.
/// 9 	UInt64 	An integer value between 0 and 18 446 744 073 709 551 615 inclusive.
/// 10 	Float 	An IEEE single precision (32 bit) floating point value.
/// 11 	Double 	An IEEE double precision (64 bit) floating point value.
/// 12 	String 	A sequence of Unicode characters.
/// 13 	DateTime 	An instance in time.
/// 14 	Guid 	A 16-byte value that can be used as a globally unique identifier.
/// 15 	ByteString 	A sequence of octets.
/// 16 	XmlElement 	An XML element.
/// 17 	NodeId 	An identifier for a node in the address space of an OPC UA Server.
/// 18 	ExpandedNodeId 	A NodeId that allows the namespace URI to be specified instead of an index.
/// 19 	StatusCode 	A numeric identifier for an error or condition that is associated with a value or an operation.
/// 20 	QualifiedName 	A name qualified by a namespace.
/// 21 	LocalizedText 	Human readable text with an optional locale identifier.
/// 22 	ExtensionObject 	A structure that contains an application specific data type that may not be recognized by the receiver.
/// 23 	DataValue 	A data value with an associated status code and timestamps.
/// 24 	Variant 	A union of all of the types specified above.
/// 25 	DiagnosticInfo 	A structure that contains detailed error and diagnostic information associated with a StatusCode.
///
pub(crate) enum VariantJsonId {
    Empty = 0,
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
    ByteString,
    XmlElement,
    NodeId,
    ExpandedNodeId,
    StatusCode,
    QualifiedName,
    LocalizedText,
    ExtensionObject,
    DataValue,
    Variant,
    DiagnosticInfo,
}

/// This is the JSON representation of the Variant. We use the struct to benefit from the derived implementations of
/// Serialize / Deserialize that cut out a lot of manually written code. There is an outer Serialize/Deserialize on
/// Variant that is responsible for preparing the struct for writing and validating it after reading.
#[derive(Serialize, Deserialize)]
struct JsonVariant {
    #[serde(rename = "Type")]
    variant_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Body")]
    body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Dimensions")]
    dimensions: Option<Vec<u32>>,
}

const VALUE_INFINITY: &str = "Infinity";
const VALUE_NEG_INFINITY: &str = "-Infinity";
const VALUE_NAN: &str = "NaN";

/// Turns a float or double to json, including special case values
macro_rules! float_to_json {
    ( $v: expr, $t: ty) => {
        if $v == <$t>::INFINITY {
            json!(VALUE_INFINITY)
        } else if $v == <$t>::NEG_INFINITY {
            json!(VALUE_NEG_INFINITY)
        } else if $v.is_nan() {
            json!(VALUE_NAN)
        } else {
            json!($v)
        }
    };
}

/// Turns a serializable struct into JSON
macro_rules! serializable_to_json {
    ( $v: expr ) => {
        serde_json::value::to_value($v).unwrap()
    };
}

/// Deserialize the json as the value type
fn json_as_value<T, E>(v: Option<serde_json::Value>, typename: &str) -> Result<T, E>
where
    T: DeserializeOwned,
    E: Error,
{
    if let Some(v) = v {
        let v = serde_json::from_value::<T>(v)
            .map_err(|_| Error::custom(format!("Invalid value, cannot parse {}", typename)))?;
        Ok(v)
    } else {
        Err(Error::custom(format!(
            "Invalid value, cannot parse {}",
            typename
        )))
    }
}

// Implement Serialize / Deserialize as per https://reference.opcfoundation.org/v104/Core/docs/Part6/5.4.2/
//
// Reversible json requires this info
//
// {
//   "Type": 0 for NULL, or other enum
//   "Body": scalar, object or array according to type
//   "Dimensions": dimensions of array for multi-dimensional arrays only
// }
//
// Non reversible requires just the body value.
impl Serialize for Variant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Write body
        let (body, dimensions) = if *self == Variant::Empty {
            (None, None)
        } else {
            let body = match self {
                // Boolean as json true or false
                Variant::Boolean(v) => json!(*v),
                // Integers except 64-bit variants as json numbers
                Variant::SByte(v) => json!(*v),
                Variant::Byte(v) => json!(*v),
                Variant::Int16(v) => json!(*v),
                Variant::UInt16(v) => json!(*v),
                Variant::Int32(v) => json!(*v),
                Variant::UInt32(v) => json!(*v),
                // Integers 64-bit as strings
                Variant::Int64(v) => json!(v.to_string()),
                Variant::UInt64(v) => json!(v.to_string()),
                // Float/double as json numbers. Strings used for special cases. Note that v is not matched to
                // f32/f64::NAN since IEE754 docs says various bit patterns can be NaN.
                Variant::Float(v) => float_to_json!(*v, f32),
                Variant::Double(v) => float_to_json!(*v, f64),
                // String as json strings - does not say what to do for null
                Variant::String(v) => serializable_to_json!(v),
                // XmlElement as string
                Variant::XmlElement(v) => serializable_to_json!(v),
                // Datetime as ISO 8601:2004 string, limited and trimmed within “0001-01-01T00:00:00Z” or “9999-12-31T23:59:59Z” range
                Variant::DateTime(v) => serializable_to_json!(v),
                // Guid as string in format C496578A-0DFE-4B8F-870A-745238C6AEAE
                Variant::Guid(v) => serializable_to_json!(v),
                // Bytestring as base64 encoded string
                Variant::ByteString(v) => serializable_to_json!(v),
                // NodeId as object - { IdType=[0123], Id=value, Namespace=3 }
                Variant::NodeId(v) => serializable_to_json!(v),
                // ExpandedNodeId
                Variant::ExpandedNodeId(v) => serializable_to_json!(v),
                // StatusCode as a number
                Variant::StatusCode(v) => serializable_to_json!(v),
                // QualifiedName as object { Name="name", Uri="uri" }. See 5.4.2.14
                Variant::QualifiedName(v) => serializable_to_json!(v),
                // LocalizedText as object { Locale="locale", Text="text" }
                Variant::LocalizedText(v) => serializable_to_json!(v),
                // ExtensionObject as object { TypeId=nodeid, Encoding=[012], Body="data"}, see 5.4.2.16
                Variant::ExtensionObject(v) => serializable_to_json!(v),
                // DataValue as object { Value=variant, Status=statuscode, SourceTimestamp=DateTime, SourcePicoSeconds=Uint16 etc.}
                Variant::DataValue(v) => serializable_to_json!(v),
                // DiagnosticInfo - see 5.4.2.13
                Variant::DiagnosticInfo(v) => serializable_to_json!(v),
                // Variant
                Variant::Variant(v) => serializable_to_json!(v),
                /*
                Variant::Array(_array) => {
                    // TODO serialize the values in an array
                    // TODO get array dimensions and serialize in an array
                    // json_variant.dimensions = Some(dimensions)
                    todo!();
                }
                */
                _ => panic!("Unsupported variant type"),
            };
            (Some(body), None)
        };

        let json_variant = JsonVariant {
            variant_type: self.json_id() as u32,
            body,
            dimensions,
        };
        json_variant.serialize(serializer)
    }
}

struct VariantVisitor;

impl VariantVisitor {
    /// Extracts a signed value integer out of the JSON value or 0
    fn numeric_i64<E>(
        v: Option<serde_json::Value>,
        name: &str,
        min: i64,
        max: i64,
    ) -> Result<i64, E>
    where
        E: de::Error,
    {
        if let Some(v) = v {
            let v = v
                .as_i64()
                .ok_or_else(|| Error::custom(format!("Wrong type, expecting {} value", name)))?;
            if v < min || v > max {
                Err(Error::custom(format!(
                    "Value {} is out of range for {}",
                    v, name
                )))
            } else {
                Ok(v)
            }
        } else {
            Ok(0)
        }
    }

    /// Extracts an unsigned value integer out of the JSON value or 0
    fn numeric_u64<E>(
        v: Option<serde_json::Value>,
        name: &str,
        min: u64,
        max: u64,
    ) -> Result<u64, E>
    where
        E: de::Error,
    {
        if let Some(v) = v {
            let v = v
                .as_u64()
                .ok_or_else(|| Error::custom(format!("Wrong type, expecting {} value", name)))?;
            if v < min || v > max {
                Err(Error::custom(format!(
                    "Value {} is out of range for {}",
                    v, name
                )))
            } else {
                Ok(v)
            }
        } else {
            Ok(0)
        }
    }

    /// Extracts a double precision floating point number out of the JSON value or 0
    fn numeric_f64<E>(
        v: Option<serde_json::Value>,
        name: &str,
        min: f64,
        max: f64,
    ) -> Result<f64, E>
    where
        E: de::Error,
    {
        if let Some(v) = v {
            // Special case values for floating point values
            if let Some(v) = v.as_str() {
                match v {
                    VALUE_INFINITY => Ok(f64::INFINITY),
                    VALUE_NEG_INFINITY => Ok(f64::NEG_INFINITY),
                    VALUE_NAN => Ok(f64::NAN),
                    _ => Err(Error::custom(format!(
                        "Wrong type, expecting {} value",
                        name
                    ))),
                }
            } else {
                let v = v.as_f64().ok_or_else(|| {
                    Error::custom(format!("Wrong type, expecting {} value", name))
                })?;
                if v < min || v > max {
                    Err(Error::custom(format!(
                        "Value {} is out of range for {}",
                        v, name
                    )))
                } else {
                    Ok(v)
                }
            }
        } else {
            Ok(0.0)
        }
    }
}

impl<'de> serde::de::Visitor<'de> for VariantVisitor {
    type Value = Variant;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a variant value or null")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Variant::Empty)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = JsonVariant::deserialize(deserializer)?;

        let t = v.variant_type;
        let body = v.body;
        let dimensions = v.dimensions;

        if dimensions.is_some() {
            // TODO support arrays of values
            return Err(Error::custom("Dimensions not supported yet"));
        }

        match t {
            t if t == VariantJsonId::Empty as u32 => {
                if body.is_some() {
                    Err(Error::custom("Unexpected Body"))
                } else {
                    Ok(Variant::Empty)
                }
            }
            // Boolean
            t if t == VariantJsonId::Boolean as u32 => {
                let v = body.ok_or_else(|| Error::custom("Missing Boolean value"))?;
                Ok(Variant::Boolean(
                    v.as_bool()
                        .ok_or_else(|| Error::custom("Value is not Boolean"))?,
                ))
            }
            // Numerics
            t if t == VariantJsonId::SByte as u32 => {
                Ok(Variant::SByte(
                    Self::numeric_i64(body, "SByte", i8::MIN as i64, i8::MAX as i64)? as i8,
                ))
            }
            t if t == VariantJsonId::Byte as u32 => {
                Ok(Variant::Byte(
                    Self::numeric_u64(body, "Byte", u8::MIN as u64, u8::MAX as u64)? as u8,
                ))
            }
            t if t == VariantJsonId::Int16 as u32 => Ok(Variant::Int16(Self::numeric_i64(
                body,
                "Int16",
                i16::MIN as i64,
                i16::MAX as i64,
            )? as i16)),
            t if t == VariantJsonId::UInt16 as u32 => Ok(Variant::UInt16(Self::numeric_u64(
                body,
                "UInt16",
                u16::MIN as u64,
                u16::MAX as u64,
            )? as u16)),
            t if t == VariantJsonId::Int32 as u32 => Ok(Variant::Int32(Self::numeric_i64(
                body,
                "Int32",
                i32::MIN as i64,
                i32::MAX as i64,
            )? as i32)),
            t if t == VariantJsonId::UInt32 as u32 => Ok(Variant::UInt32(Self::numeric_u64(
                body,
                "UInt32",
                u32::MIN as u64,
                u32::MAX as u64,
            )? as u32)),
            t if t == VariantJsonId::Int64 as u32 => {
                let v = if let Some(v) = body {
                    const ERR: &str = "Int64 encoded as a string";
                    let v = v.as_str().ok_or_else(|| {
                        Error::custom(format!("Wrong type, expecting {} value", ERR))
                    })?;
                    v.parse::<i64>().map_err(|_| {
                        Error::custom(format!("Parse error, expecting {} value", ERR))
                    })?
                } else {
                    0i64
                };
                Ok(Variant::Int64(v))
            }
            t if t == VariantJsonId::UInt64 as u32 => {
                let v = if let Some(v) = body {
                    const ERR: &str = "UInt64 encoded as a string";
                    let v = v.as_str().ok_or_else(|| {
                        Error::custom(format!("Wrong type, expecting {} value", ERR))
                    })?;
                    v.parse::<u64>().map_err(|_| {
                        Error::custom(format!("Parse error, expecting {} value", ERR))
                    })?
                } else {
                    0u64
                };
                Ok(Variant::UInt64(v))
            }
            t if t == VariantJsonId::Float as u32 => Ok(Variant::Float(Self::numeric_f64(
                body,
                "Float",
                f32::MIN as f64,
                f32::MAX as f64,
            )? as f32)),
            t if t == VariantJsonId::Double as u32 => Ok(Variant::Double(Self::numeric_f64(
                body,
                "Double",
                f64::MIN,
                f64::MAX,
            )?)),
            t if t == VariantJsonId::String as u32 => {
                if let Some(ref v) = body {
                    if v.is_null() {
                        Ok(Variant::String(UAString::null()))
                    } else {
                        json_as_value(body, "UAString").map(|v| Variant::String(v))
                    }
                } else {
                    Ok(Variant::String(UAString::null()))
                }
            }
            t if t == VariantJsonId::DateTime as u32 => {
                json_as_value(body, "DateTime").map(|v| Variant::DateTime(Box::new(v)))
            }
            t if t == VariantJsonId::Guid as u32 => {
                json_as_value(body, "Guid").map(|v| Variant::Guid(Box::new(v)))
            }
            t if t == VariantJsonId::ByteString as u32 => {
                if let Some(ref v) = body {
                    if v.is_null() {
                        Ok(Variant::ByteString(ByteString::null()))
                    } else {
                        json_as_value(body, "ByteString").map(|v| Variant::ByteString(v))
                    }
                } else {
                    Ok(Variant::ByteString(ByteString::null()))
                }
            }
            t if t == VariantJsonId::XmlElement as u32 => {
                json_as_value(body, "XmlElement").map(|v| Variant::XmlElement(v))
            }
            t if t == VariantJsonId::NodeId as u32 => {
                json_as_value(body, "NodeId").map(|v| Variant::NodeId(Box::new(v)))
            }
            t if t == VariantJsonId::ExpandedNodeId as u32 => {
                json_as_value(body, "ExpandedNodeId").map(|v| Variant::ExpandedNodeId(Box::new(v)))
            }
            t if t == VariantJsonId::StatusCode as u32 => {
                if let Some(v) = body {
                    let v = serde_json::from_value::<u32>(v)
                        .map_err(|_| Error::custom("Invalid value, cannot parse StatusCode"))?;
                    Ok(Variant::StatusCode(StatusCode::from_bits_truncate(v)))
                } else {
                    Err(Error::custom("Invalid value, cannot parse StatusCode"))
                }
            }
            t if t == VariantJsonId::QualifiedName as u32 => {
                json_as_value(body, "QualifiedName").map(|v| Variant::QualifiedName(Box::new(v)))
            }
            t if t == VariantJsonId::LocalizedText as u32 => {
                json_as_value(body, "LocalizedText").map(|v| Variant::LocalizedText(Box::new(v)))
            }
            t if t == VariantJsonId::ExtensionObject as u32 => {
                json_as_value(body, "ExtensionObject")
                    .map(|v| Variant::ExtensionObject(Box::new(v)))
            }
            t if t == VariantJsonId::DataValue as u32 => {
                json_as_value(body, "DataValue").map(|v| Variant::DataValue(Box::new(v)))
            }
            t if t == VariantJsonId::Variant as u32 => {
                json_as_value(body, "Variant").map(|v| Variant::Variant(Box::new(v)))
            }
            t if t == VariantJsonId::DiagnosticInfo as u32 => {
                json_as_value(body, "DiagnosticInfo").map(|v| Variant::DiagnosticInfo(Box::new(v)))
            }
            t => Err(Error::custom(format!("Unhandled type {}", t))),
        }
    }
}

impl<'de> Deserialize<'de> for Variant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(VariantVisitor)
    }
}

impl Variant {
    fn json_id(&self) -> VariantJsonId {
        match self {
            Variant::Empty => VariantJsonId::Empty,
            Variant::Boolean(_) => VariantJsonId::Boolean,
            Variant::SByte(_) => VariantJsonId::SByte,
            Variant::Byte(_) => VariantJsonId::Byte,
            Variant::Int16(_) => VariantJsonId::Int16,
            Variant::UInt16(_) => VariantJsonId::UInt16,
            Variant::Int32(_) => VariantJsonId::Int32,
            Variant::UInt32(_) => VariantJsonId::UInt32,
            Variant::Int64(_) => VariantJsonId::Int64,
            Variant::UInt64(_) => VariantJsonId::UInt64,
            Variant::Float(_) => VariantJsonId::Float,
            Variant::Double(_) => VariantJsonId::Double,
            Variant::String(_) => VariantJsonId::String,
            Variant::DateTime(_) => VariantJsonId::DateTime,
            Variant::Guid(_) => VariantJsonId::Guid,
            Variant::ByteString(_) => VariantJsonId::ByteString,
            Variant::XmlElement(_) => VariantJsonId::XmlElement,
            Variant::NodeId(_) => VariantJsonId::NodeId,
            Variant::ExpandedNodeId(_) => VariantJsonId::ExpandedNodeId,
            Variant::StatusCode(_) => VariantJsonId::StatusCode,
            Variant::QualifiedName(_) => VariantJsonId::QualifiedName,
            Variant::LocalizedText(_) => VariantJsonId::LocalizedText,
            Variant::ExtensionObject(_) => VariantJsonId::ExtensionObject,
            Variant::Variant(_) => VariantJsonId::Variant,
            Variant::DataValue(_) => VariantJsonId::DataValue,
            Variant::DiagnosticInfo(_) => VariantJsonId::DiagnosticInfo,
            _ => {
                // TODO for arrays, will have to get the json id for the first element
                panic!("Cannot return type")
            }
        }
    }
}
