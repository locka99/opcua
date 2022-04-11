// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the implementation of `NodeId` and `ExpandedNodeId`.

use std::{
    self,
    convert::TryFrom,
    fmt,
    io::{Read, Write},
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
    u16, u32,
};

use crate::types::{
    byte_string::ByteString,
    encoding::*,
    guid::Guid,
    node_ids::{ObjectId, ReferenceTypeId},
    status_codes::StatusCode,
    string::*,
};

/// The kind of identifier, numeric, string, guid or byte
#[derive(Eq, PartialEq, Clone, Debug, Hash, Serialize, Deserialize)]
pub enum Identifier {
    Numeric(u32),
    String(UAString),
    Guid(Guid),
    ByteString(ByteString),
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identifier::Numeric(v) => write!(f, "i={}", *v),
            Identifier::String(v) => write!(f, "s={}", v),
            Identifier::Guid(v) => write!(f, "g={:?}", v),
            Identifier::ByteString(v) => write!(f, "b={}", v.as_base64()),
        }
    }
}

impl FromStr for Identifier {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 2 {
            Err(())
        } else {
            let k = &s[..2];
            let v = &s[2..];
            match k {
                "i=" => v.parse::<u32>().map(|v| v.into()).map_err(|_| ()),
                "s=" => Ok(UAString::from(v).into()),
                "g=" => Guid::from_str(v).map(|v| v.into()).map_err(|_| ()),
                "b=" => ByteString::from_base64(v).map(|v| v.into()).ok_or(()),
                _ => Err(()),
            }
        }
    }
}

impl From<i32> for Identifier {
    fn from(v: i32) -> Self {
        Identifier::Numeric(v as u32)
    }
}

impl From<u32> for Identifier {
    fn from(v: u32) -> Self {
        Identifier::Numeric(v as u32)
    }
}

impl<'a> From<&'a str> for Identifier {
    fn from(v: &'a str) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<&String> for Identifier {
    fn from(v: &String) -> Self {
        Identifier::from(UAString::from(v))
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

#[derive(Debug)]
pub struct NodeIdError;

impl fmt::Display for NodeIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeIdError")
    }
}

impl std::error::Error for NodeIdError {}

/// An identifier for a node in the address space of an OPC UA Server.
#[derive(PartialEq, Eq, Clone, Debug, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// The index for a namespace
    pub namespace: u16,
    /// The identifier for the node in the address space
    pub identifier: Identifier,
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.namespace != 0 {
            write!(f, "ns={};{}", self.namespace, self.identifier)
        } else {
            write!(f, "{}", self.identifier)
        }
    }
}

impl BinaryEncoder<NodeId> for NodeId {
    fn byte_len(&self) -> usize {
        // Type determines the byte code
        let size: usize = match self.identifier {
            Identifier::Numeric(value) => {
                if self.namespace == 0 && value <= 255 {
                    2
                } else if self.namespace <= 255 && value <= 65535 {
                    4
                } else {
                    7
                }
            }
            Identifier::String(ref value) => 3 + value.byte_len(),
            Identifier::Guid(ref value) => 3 + value.byte_len(),
            Identifier::ByteString(ref value) => 3 + value.byte_len(),
        };
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        // Type determines the byte code
        match &self.identifier {
            Identifier::Numeric(value) => {
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
            Identifier::String(value) => {
                size += write_u8(stream, 0x3)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::Guid(value) => {
                size += write_u8(stream, 0x4)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::ByteString(value) => {
                size += write_u8(stream, 0x5)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
        }
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
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
                let value = UAString::decode(stream, decoding_options)?;
                NodeId::new(namespace, value)
            }
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream, decoding_options)?;
                NodeId::new(namespace, value)
            }
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream, decoding_options)?;
                NodeId::new(namespace, value)
            }
            _ => {
                error!("Unrecognized node id type {}", identifier);
                return Err(StatusCode::BadDecodingError);
            }
        };
        Ok(node_id)
    }
}

impl FromStr for NodeId {
    type Err = StatusCode;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use regex::Regex;

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

        lazy_static! {
            // Contains capture groups "ns" and "t" for namespace and type respectively
            static ref RE: Regex = Regex::new(r"^(ns=(?P<ns>[0-9]+);)?(?P<t>[isgb]=.+)$").unwrap();
        }

        let captures = RE.captures(s).ok_or(StatusCode::BadNodeIdInvalid)?;

        // Check namespace (optional)
        let namespace = if let Some(ns) = captures.name("ns") {
            ns.as_str()
                .parse::<u16>()
                .map_err(|_| StatusCode::BadNodeIdInvalid)?
        } else {
            0
        };

        // Type identifier
        let t = captures.name("t").unwrap();
        Identifier::from_str(t.as_str())
            .map(|t| NodeId::new(namespace, t))
            .map_err(|_| StatusCode::BadNodeIdInvalid)
    }
}

impl From<&NodeId> for NodeId {
    fn from(v: &NodeId) -> Self {
        v.clone()
    }
}

impl Into<String> for NodeId {
    fn into(self) -> String {
        self.to_string()
    }
}

impl<'a> From<(u16, &'a str)> for NodeId {
    fn from(v: (u16, &'a str)) -> Self {
        Self::new(v.0, UAString::from(v.1))
    }
}

impl From<(u16, UAString)> for NodeId {
    fn from(v: (u16, UAString)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(u16, u32)> for NodeId {
    fn from(v: (u16, u32)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(u16, Guid)> for NodeId {
    fn from(v: (u16, Guid)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(u16, ByteString)> for NodeId {
    fn from(v: (u16, ByteString)) -> Self {
        Self::new(v.0, v.1)
    }
}

static NEXT_NODE_ID_NUMERIC: AtomicUsize = AtomicUsize::new(0);

impl Default for NodeId {
    fn default() -> Self {
        NodeId::null()
    }
}

impl NodeId {
    // Constructs a new NodeId from anything that can be turned into Identifier
    // u32, Guid, ByteString or String
    pub fn new<T>(namespace: u16, value: T) -> NodeId
    where
        T: 'static + Into<Identifier>,
    {
        NodeId {
            namespace,
            identifier: value.into(),
        }
    }

    /// Returns the node id for the root folder.
    pub fn root_folder_id() -> NodeId {
        ObjectId::RootFolder.into()
    }

    /// Returns the node id for the objects folder.
    pub fn objects_folder_id() -> NodeId {
        ObjectId::ObjectsFolder.into()
    }

    /// Returns the node id for the types folder.
    pub fn types_folder_id() -> NodeId {
        ObjectId::TypesFolder.into()
    }

    /// Returns the node id for the views folder.
    pub fn views_folder_id() -> NodeId {
        ObjectId::ViewsFolder.into()
    }

    /// Test if the node id is null, i.e. 0 namespace and 0 identifier
    pub fn is_null(&self) -> bool {
        self.namespace == 0 && self.identifier == Identifier::Numeric(0)
    }

    /// Returns a null node id
    pub fn null() -> NodeId {
        NodeId::new(0, 0u32)
    }

    // Creates a numeric node id with an id incrementing up from 1000
    pub fn next_numeric(namespace: u16) -> NodeId {
        NodeId::new(
            namespace,
            NEXT_NODE_ID_NUMERIC.fetch_add(1, Ordering::SeqCst) as u32,
        )
    }

    /// Extracts an ObjectId from a node id, providing the node id holds an object id
    pub fn as_object_id(&self) -> std::result::Result<ObjectId, NodeIdError> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => {
                ObjectId::try_from(id).map_err(|_| NodeIdError)
            }
            _ => Err(NodeIdError),
        }
    }

    pub fn as_reference_type_id(&self) -> std::result::Result<ReferenceTypeId, NodeIdError> {
        // TODO this function should not exist - filter code should work with non ns 0 reference
        // types
        if self.is_null() {
            Err(NodeIdError)
        } else {
            match self.identifier {
                Identifier::Numeric(id) if self.namespace == 0 => {
                    ReferenceTypeId::try_from(id).map_err(|_| NodeIdError)
                }
                _ => Err(NodeIdError),
            }
        }
    }

    /// Test if the node id is numeric
    pub fn is_numeric(&self) -> bool {
        matches!(self.identifier, Identifier::Numeric(_))
    }

    /// Test if the node id is a string
    pub fn is_string(&self) -> bool {
        matches!(self.identifier, Identifier::String(_))
    }

    /// Test if the node id is a guid
    pub fn is_guid(&self) -> bool {
        matches!(self.identifier, Identifier::Guid(_))
    }

    /// Test if the node id us a byte string
    pub fn is_byte_string(&self) -> bool {
        matches!(self.identifier, Identifier::ByteString(_))
    }
}

/// A NodeId that allows the namespace URI to be specified instead of an index.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ExpandedNodeId {
    pub node_id: NodeId,
    pub namespace_uri: UAString,
    pub server_index: u32,
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
        match &self.node_id.identifier {
            Identifier::Numeric(value) => {
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
            Identifier::String(value) => {
                size += write_u8(stream, data_encoding | 0x3)?;
                size += write_u16(stream, self.node_id.namespace)?;
                size += value.encode(stream)?;
            }
            Identifier::Guid(value) => {
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

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
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
                let value = UAString::decode(stream, decoding_options)?;
                NodeId::new(namespace, value)
            }
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream, decoding_options)?;
                NodeId::new(namespace, value)
            }
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream, decoding_options)?;
                NodeId::new(namespace, value)
            }
            _ => {
                error!("Unrecognized expanded node id type {}", identifier);
                return Err(StatusCode::BadDecodingError);
            }
        };

        // Optional stuff
        let namespace_uri = if data_encoding & 0x80 != 0 {
            UAString::decode(stream, decoding_options)?
        } else {
            UAString::null()
        };
        let server_index = if data_encoding & 0x40 != 0 {
            u32::decode(stream, decoding_options)?
        } else {
            0
        };

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

impl fmt::Display for ExpandedNodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Formatted depending on the namespace uri being empty or not.
        if self.namespace_uri.is_empty() {
            // svr=<serverindex>;ns=<namespaceindex>;<type>=<value>
            write!(f, "svr={};{}", self.server_index, self.node_id)
        } else {
            // The % and ; chars have to be escaped out in the uri
            let namespace_uri = String::from(self.namespace_uri.as_ref())
                .replace('%', "%25")
                .replace(';', "%3b");
            // svr=<serverindex>;nsu=<uri>;<type>=<value>
            write!(
                f,
                "svr={};nsu={};{}",
                self.server_index, namespace_uri, self.node_id.identifier
            )
        }
    }
}

impl FromStr for ExpandedNodeId {
    type Err = StatusCode;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use regex::Regex;

        // Parses a node from a string using the format specified in 5.3.1.11 part 6
        //
        // svr=<serverindex>;ns=<namespaceindex>;<type>=<value>
        // or
        // svr=<serverindex>;nsu=<uri>;<type>=<value>

        lazy_static! {
            // Contains capture groups "svr", either "ns" or "nsu" and then "t" for type
            static ref RE: Regex = Regex::new(r"^svr=(?P<svr>[0-9]+);(ns=(?P<ns>[0-9]+)|nsu=(?P<nsu>[^;]+));(?P<t>[isgb]=.+)$").unwrap();
        }

        let captures = RE.captures(s).ok_or(StatusCode::BadNodeIdInvalid)?;

        // Server index
        let server_index = captures
            .name("svr")
            .ok_or(StatusCode::BadNodeIdInvalid)
            .and_then(|server_index| {
                server_index
                    .as_str()
                    .parse::<u32>()
                    .map_err(|_| StatusCode::BadNodeIdInvalid)
            })?;

        // Check for namespace uri
        let namespace_uri = if let Some(nsu) = captures.name("nsu") {
            // The % and ; chars need to be unescaped
            let nsu = String::from(nsu.as_str())
                .replace("%3b", ";")
                .replace("%25", "%");
            UAString::from(nsu)
        } else {
            UAString::null()
        };

        let namespace = if let Some(ns) = captures.name("ns") {
            ns.as_str()
                .parse::<u16>()
                .map_err(|_| StatusCode::BadNodeIdInvalid)?
        } else {
            0
        };

        // Type identifier
        let t = captures.name("t").unwrap();
        Identifier::from_str(t.as_str())
            .map(|t| ExpandedNodeId {
                server_index,
                namespace_uri,
                node_id: NodeId::new(namespace, t),
            })
            .map_err(|_| StatusCode::BadNodeIdInvalid)
    }
}

impl ExpandedNodeId {
    /// Creates an expanded node id from a node id
    pub fn new<T>(value: T) -> ExpandedNodeId
    where
        T: 'static + Into<ExpandedNodeId>,
    {
        value.into()
    }

    pub fn null() -> ExpandedNodeId {
        Self::new(NodeId::null())
    }

    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}
