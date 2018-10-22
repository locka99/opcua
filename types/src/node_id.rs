//! Contains the implementation of `NodeId` and `ExpandedNodeId`.

use std;
use std::u32;
use std::u16;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};

use basic_types::*;
use byte_string::ByteString;
use encoding::*;
use guid::Guid;
use node_ids::{ObjectId, ReferenceTypeId};
use status_codes::StatusCode;
use string::*;

/// The kind of identifier, numeric, string, guid or byte
#[derive(Eq, PartialEq, Clone, Debug, Hash, Serialize, Deserialize)]
pub enum Identifier {
    Numeric(UInt32),
    String(UAString),
    Guid(Guid),
    ByteString(ByteString),
}

impl From<Int32> for Identifier {
    fn from(v: Int32) -> Self {
        Identifier::Numeric(v as u32)
    }
}

impl From<UInt32> for Identifier {
    fn from(v: UInt32) -> Self {
        Identifier::Numeric(v as u32)
    }
}

impl<'a> From<&'a str> for Identifier {
    fn from(v: &'a str) -> Self {
        Identifier::from(UAString::from(v.to_string()))
    }
}

impl From<String> for Identifier {
    fn from(v: String) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<UAString> for Identifier {
    fn from(v: UAString) -> Self {
        Identifier::String(v)
    }
}

impl From<Guid> for Identifier {
    fn from(v: Guid) -> Self {
        Identifier::Guid(v)
    }
}

impl From<ByteString> for Identifier {
    fn from(v: ByteString) -> Self {
        Identifier::ByteString(v)
    }
}

/// An identifier for a node in the address space of an OPC UA Server.
#[derive(PartialEq, Eq, Clone, Debug, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// The index for a namespace
    pub namespace: UInt16,
    /// The identifier for the node in the address space
    pub identifier: Identifier,
}

impl BinaryEncoder<NodeId> for NodeId {
    fn byte_len(&self) -> usize {
        // Type determines the byte code
        let size: usize = match self.identifier {
            Identifier::Numeric(ref value) => {
                if self.namespace == 0 && *value <= 255 {
                    2
                } else if self.namespace <= 255 && *value <= 65535 {
                    4
                } else {
                    7
                }
            }
            Identifier::String(ref value) => {
                3 + value.byte_len()
            }
            Identifier::Guid(ref value) => {
                3 + value.byte_len()
            }
            Identifier::ByteString(ref value) => {
                3 + value.byte_len()
            }
        };
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        // Type determines the byte code
        match self.identifier {
            Identifier::Numeric(ref value) => {
                if self.namespace == 0 && *value <= 255 {
                    // node id fits into 2 bytes when the namespace is 0 and the value <= 255
                    size += write_u8(stream, 0x0)?;
                    size += write_u8(stream, *value as u8)?;
                } else if self.namespace <= 255 && *value <= 65535 {
                    // node id fits into 4 bytes when namespace <= 255 and value <= 65535
                    size += write_u8(stream, 0x1)?;
                    size += write_u8(stream, self.namespace as u8)?;
                    size += write_u16(stream, *value as u16)?;
                } else {
                    // full node id
                    size += write_u8(stream, 0x2)?;
                    size += write_u16(stream, self.namespace)?;
                    size += write_u32(stream, *value)?;
                }
            }
            Identifier::String(ref value) => {
                size += write_u8(stream, 0x3)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::Guid(ref value) => {
                size += write_u8(stream, 0x4)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::ByteString(ref value) => {
                size += write_u8(stream, 0x5)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
        }
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let identifier = read_u8(stream)?;
        let node_id = match identifier {
            0x0 => {
                let namespace = 0;
                let value = read_u8(stream)?;
                NodeId::new(namespace, u32::from(value))
            }
            0x1 => {
                let namespace = read_u8(stream)?;
                let value = read_u16(stream)?;
                NodeId::new(u16::from(namespace), u32::from(value))
            }
            0x2 => {
                let namespace = read_u16(stream)?;
                let value = read_u32(stream)?;
                NodeId::new(namespace, value)
            }
            0x3 => {
                let namespace = read_u16(stream)?;
                let value = UAString::decode(stream, decoding_limits)?;
                NodeId::new(namespace, value)
            }
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream, decoding_limits)?;
                NodeId::new(namespace, value)
            }
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream, decoding_limits)?;
                NodeId::new(namespace, value)
            }
            _ => {
                panic!("Unrecognized node id type {:?}", identifier);
            }
        };
        Ok(node_id)
    }
}

impl FromStr for NodeId {
    type Err = StatusCode;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use regex::Regex;

        lazy_static! {
            static ref RE: Regex = Regex::new(r"^(ns=(?P<ns>[0-9]+);)?(?P<t>[isgb])=(?P<v>.+)$").unwrap();
        }

        // Parses a node from a string using the format specified in 5.3.1.10 part 6
        //
        // ns=<namespaceindex>;<type>=<value>
        //
        // Where type:
        //   i = NUMERIC
        //   s = STRING
        //   g = GUID
        //   b = OPAQUE (ByteString)
        //
        // If namespace == 0, the ns=0; will be omitted

        let captures = RE.captures(s);
        if captures.is_none() {
            return Err(StatusCode::BadNodeIdInvalid);
        }
        let captures = captures.unwrap();

        // Check namespace (optional)
        let namespace = if let Some(ns) = captures.name("ns") {
            let parse_result = ns.as_str().parse::<UInt16>();
            if parse_result.is_err() {
                return Err(StatusCode::BadNodeIdInvalid);
            }
            parse_result.unwrap()
        } else {
            0
        };

        // type and value - these must exist or regex wouldn't have happened
        let t = captures.name("t").unwrap();
        let v = captures.name("v").unwrap();
        let node_id = match t.as_str() {
            "i" => {
                let number = v.as_str().parse::<UInt32>();
                if number.is_err() {
                    return Err(StatusCode::BadNodeIdInvalid);
                }
                NodeId::new(namespace, number.unwrap())
            }
            "s" => {
                let v = UAString::from(v.as_str());
                NodeId::new(namespace, v)
            }
            "g" => {
                let guid = Guid::from_str(v.as_str());
                if guid.is_err() {
                    return Err(StatusCode::BadNodeIdInvalid);
                }
                NodeId::new(namespace, guid.unwrap())
            }
            "b" => {
                // Byte string is encoded as a Base64 value
                let bytestring = ByteString::from_base64(v.as_str());
                if bytestring.is_none() {
                    return Err(StatusCode::BadNodeIdInvalid);
                }
                NodeId::new(namespace, bytestring.unwrap())
            }
            _ => {
                return Err(StatusCode::BadNodeIdInvalid);
            }
        };
        Ok(node_id)
    }
}

impl Into<String> for NodeId {
    fn into(self) -> String {
        self.to_string()
    }
}

impl ToString for NodeId {
    fn to_string(&self) -> String {
        let mut result = String::new();
        if self.namespace != 0 {
            result.push_str(&format!("ns={};", self.namespace));
        }
        result.push_str(&match self.identifier {
            Identifier::Numeric(ref value) => {
                format!("i={}", value)
            }
            Identifier::String(ref value) => {
                if value.is_null() {
                    "null".to_string()
                } else {
                    format!("s={}", value.as_ref())
                }
            }
            Identifier::Guid(ref value) => {
                format!("g={:?}", value)
            }
            Identifier::ByteString(ref value) => {
                // Base64 encode bytes
                format!("b={}", value.as_base64())
            }
        });
        result
    }
}

impl<'a> From<(UInt16, &'a str)> for NodeId {
    fn from(v: (UInt16, &'a str)) -> Self {
        Self::new(v.0, UAString::from(v.1))
    }
}

impl From<(UInt16, UAString)> for NodeId {
    fn from(v: (UInt16, UAString)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(UInt16, UInt32)> for NodeId {
    fn from(v: (UInt16, UInt32)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(UInt16, Guid)> for NodeId {
    fn from(v: (UInt16, Guid)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(UInt16, ByteString)> for NodeId {
    fn from(v: (UInt16, ByteString)) -> Self {
        Self::new(v.0, v.1)
    }
}

static NEXT_NODE_ID_NUMERIC: AtomicUsize = ATOMIC_USIZE_INIT;

impl Default for NodeId {
    fn default() -> Self {
        NodeId::null()
    }
}

impl NodeId {
    // Constructs a new NodeId from anything that can be turned into Identifier
    // UInt32, Guid, ByteString or String
    pub fn new<T>(namespace: UInt16, value: T) -> NodeId where T: 'static + Into<Identifier> {
        NodeId { namespace, identifier: value.into() }
    }

    /// Test if the node id is null, i.e. 0 namespace and 0 identifier
    pub fn is_null(&self) -> bool {
        match self.identifier {
            Identifier::Numeric(id) => { id == 0 && self.namespace == 0 }
            _ => false,
        }
    }

    /// Returns a null node id
    pub fn null() -> NodeId {
        NodeId::new(0, 0u32)
    }

    // Creates a numeric node id with an id incrementing up from 1000
    pub fn next_numeric() -> NodeId {
        NodeId::new(1, NEXT_NODE_ID_NUMERIC.fetch_add(1, Ordering::SeqCst) as u32)
    }

    /// Extracts an ObjectId from a node id, providing the node id holds an object id
    pub fn as_object_id(&self) -> std::result::Result<ObjectId, ()> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => ObjectId::from_u32(id),
            _ => Err(())
        }
    }

    pub fn as_reference_type_id(&self) -> std::result::Result<ReferenceTypeId, ()> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => ReferenceTypeId::from_u32(id),
            _ => Err(())
        }
    }

    /// Test if the node id is numeric
    pub fn is_numeric(&self) -> bool {
        match self.identifier {
            Identifier::Numeric(_) => true,
            _ => false,
        }
    }

    /// Test if the node id is a string
    pub fn is_string(&self) -> bool {
        match self.identifier {
            Identifier::String(_) => true,
            _ => false,
        }
    }

    /// Test if the node id is a guid
    pub fn is_guid(&self) -> bool {
        match self.identifier {
            Identifier::Guid(_) => true,
            _ => false,
        }
    }

    /// Test if the node id us a byte string
    pub fn is_byte_string(&self) -> bool {
        match self.identifier {
            Identifier::ByteString(_) => true,
            _ => false,
        }
    }
}

/// A NodeId that allows the namespace URI to be specified instead of an index.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ExpandedNodeId {
    pub node_id: NodeId,
    pub namespace_uri: UAString,
    pub server_index: UInt32,
}

impl BinaryEncoder<ExpandedNodeId> for ExpandedNodeId {
    fn byte_len(&self) -> usize {
        let mut size = self.node_id.byte_len();
        if !self.namespace_uri.is_null() {
            size += self.namespace_uri.byte_len();
        }
        if self.server_index != 0 {
            size += self.server_index.byte_len();
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;

        let mut data_encoding = 0;
        if !self.namespace_uri.is_null() {
            data_encoding |= 0x80;
        }
        if self.server_index != 0 {
            data_encoding |= 0x40;
        }

        // Type determines the byte code
        match self.node_id.identifier {
            Identifier::Numeric(ref value) => {
                if self.node_id.namespace == 0 && *value <= 255 {
                    // node id fits into 2 bytes when the namespace is 0 and the value <= 255
                    size += write_u8(stream, data_encoding)?;
                    size += write_u8(stream, *value as u8)?;
                } else if self.node_id.namespace <= 255 && *value <= 65535 {
                    // node id fits into 4 bytes when namespace <= 255 and value <= 65535
                    size += write_u8(stream, data_encoding | 0x1)?;
                    size += write_u8(stream, self.node_id.namespace as u8)?;
                    size += write_u16(stream, *value as u16)?;
                } else {
                    // full node id
                    size += write_u8(stream, data_encoding | 0x2)?;
                    size += write_u16(stream, self.node_id.namespace)?;
                    size += write_u32(stream, *value)?;
                }
            }
            Identifier::String(ref value) => {
                size += write_u8(stream, data_encoding | 0x3)?;
                size += write_u16(stream, self.node_id.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::Guid(ref value) => {
                size += write_u8(stream, data_encoding | 0x4)?;
                size += write_u16(stream, self.node_id.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::ByteString(ref value) => {
                size += write_u8(stream, data_encoding | 0x5)?;
                size += write_u16(stream, self.node_id.namespace)?;
                size += value.encode(stream)?;
            }
        }
        if !self.namespace_uri.is_null() {
            size += self.namespace_uri.encode(stream)?;
        }
        if self.server_index != 0 {
            size += self.server_index.encode(stream)?;
        }
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let data_encoding = read_u8(stream)?;
        let identifier = data_encoding & 0x0f;
        let node_id = match identifier {
            0x0 => {
                let value = read_u8(stream)?;
                NodeId::new(0, u32::from(value))
            }
            0x1 => {
                let namespace = read_u8(stream)?;
                let value = read_u16(stream)?;
                NodeId::new(u16::from(namespace), u32::from(value))
            }
            0x2 => {
                let namespace = read_u16(stream)?;
                let value = read_u32(stream)?;
                NodeId::new(namespace, value)
            }
            0x3 => {
                let namespace = read_u16(stream)?;
                let value = UAString::decode(stream, decoding_limits)?;
                NodeId::new(namespace, value)
            }
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream, decoding_limits)?;
                NodeId::new(namespace, value)
            }
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream, decoding_limits)?;
                NodeId::new(namespace, value)
            }
            _ => {
                panic!("Unrecognized node id type {:?}", identifier);
            }
        };

        // Optional stuff
        let namespace_uri = if data_encoding & 0x80 != 0 { UAString::decode(stream, decoding_limits)? } else { UAString::null() };
        let server_index = if data_encoding & 0x40 != 0 { UInt32::decode(stream, decoding_limits)? } else { 0 };

        Ok(ExpandedNodeId {
            node_id,
            namespace_uri,
            server_index,
        })
    }
}

impl<'a> Into<ExpandedNodeId> for &'a NodeId {
    fn into(self) -> ExpandedNodeId {
        self.clone().into()
    }
}

impl From<NodeId> for ExpandedNodeId {
    fn from(v: NodeId) -> Self {
        ExpandedNodeId {
            node_id: v,
            namespace_uri: UAString::null(),
            server_index: 0,
        }
    }
}

impl ExpandedNodeId {
    /// Creates an expanded node id from a node id
    pub fn new<T>(value: T) -> ExpandedNodeId where T: 'static + Into<ExpandedNodeId> {
        value.into()
    }

    pub fn null() -> ExpandedNodeId {
        Self::new(NodeId::null())
    }

    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}