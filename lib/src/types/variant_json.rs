use std::{
    convert::TryFrom,
    fmt,
    io::Read,
    str::FromStr,
    {i16, i32, i64, i8, u16, u32, u64, u8},
};

use serde::{de, ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};

use crate::types::variant::Variant;

const FIELD_TYPE: &'static str = "Type";
const FIELD_BODY: &'static str = "Body";
const FIELD_DIMENSIONS: &'static str = "Dimensions";

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
        let mut map = serializer.serialize_map(None)?;

        // Write type
        let type_id = self.json_id() as u32;
        map.serialize_entry(FIELD_TYPE, &type_id)?;

        // Write body
        match self {
            Variant::Empty => map.serialize_entry(FIELD_BODY, &None::<i32>)?,
            // Boolean as json true or false
            Variant::Boolean(v) => map.serialize_entry(FIELD_BODY, v)?,
            // Integers except 64-bit variants as json numbers
            Variant::SByte(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::Byte(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::Int16(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::UInt16(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::Int32(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::UInt32(v) => map.serialize_entry(FIELD_BODY, v)?,
            // Integers 64-bit as strings
            Variant::Int64(v) => map.serialize_entry(FIELD_BODY, &v.to_string())?,
            Variant::UInt64(v) => map.serialize_entry(FIELD_BODY, &v.to_string())?,
            // Float/double as json numbers
            Variant::Float(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::Double(v) => map.serialize_entry(FIELD_BODY, v)?,
            // String as json strings - does not say what to do for null
            Variant::String(v) => map.serialize_entry(FIELD_BODY, v)?,
            // XmlElement as string
            Variant::XmlElement(v) => map.serialize_entry(FIELD_BODY, v)?,
            // Datetime as ISO 8601:2004 string, limited and trimmed within “0001-01-01T00:00:00Z” or “9999-12-31T23:59:59Z” range
            Variant::DateTime(v) => map.serialize_entry(FIELD_BODY, v)?,
            // Guid as string in format C496578A-0DFE-4B8F-870A-745238C6AEAE
            Variant::Guid(v) => map.serialize_entry(FIELD_BODY, v)?,
            // Bytestring as base64 encoded string
            Variant::ByteString(v) => map.serialize_entry(FIELD_BODY, v)?,
            /* ,
                        // NodeId as object - { IdType=[0123], Id=value, Namespace=3 }
                        Variant::NodeId(v) => map.serialize_entry(FIELD_BODY, v)?,
                        // ExpandedNodeId
                        Variant::ExpandedNodeId(v) => map.serialize_entry(FIELD_BODY, v)?,
                        // StatusCode as object - { Code=1234, Symbol="BadSomeError" }. A Good value can be null
                        Variant::StatusCode(v) => map.serialize_entry(FIELD_BODY, v)?,
                        // QualifiedName as object { Name="name", Uri="uri" }. See 5.4.2.14
                        Variant::QualifiedName(v) => map.serialize_entry(FIELD_BODY, v)?,
                        // LocalizedText as object { Locale="locale", Text="text" }
                        Variant::LocalizedText(v) => map.serialize_entry(FIELD_BODY, v)?,
                        // ExtensionObject as object { TypeId=nodeid, Encoding=[012], Body="data"}, see 5.4.2.16
                        Variant::ExtensionObject(v) => map.serialize_entry(FIELD_BODY, v)?,
                        // DataValue as object { Value=variant, Status=statuscode, SourceTimestamp=DateTime, SourcePicoSeconds=Uint16 etc.}
                        Variant::DataValue(v) =>map.serialize_entry(FIELD_BODY, v)?,
                        // DiagnosticInfo - see 5.4.2.13
                        Variant::DiagnosticInfo(v) => map.serialize_entry(FIELD_BODY, v)?,
            */
            Variant::Variant(v) => map.serialize_entry(FIELD_BODY, v)?,
            Variant::Array(array) => {
                // TODO serialize the values in an array
                // TODO get array dimensions and serialize in an array
                map.serialize_entry(FIELD_DIMENSIONS, &1)?;
            }
            _ => map.serialize_entry(FIELD_BODY, "UNSUPPORTED/TODO")?,
        };

        // TODO array dimensions (if applicable)

        map.end()
    }
}

struct VariantVisitor;

impl<'de> serde::de::Visitor<'de> for VariantVisitor {
    type Value = Variant;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a base64 encoded string value or null")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Self::Value::Empty)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Read Type
        // Read Body
        // Read Dimensions
        unimplemented!();
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
                panic!("Cannot return type")
            }
        }
    }
}
