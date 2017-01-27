use std;
use std::str::{FromStr};
use std::io::{Read, Write};

use types::*;

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub enum Identifier {
    Numeric(UInt64),
    String(UAString),
    Guid(Guid),
    ByteString(ByteString),
}

/// An identifier for a node in the address space of an OPC UA Server.
/// Data type ID 17
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
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
                    11
                }
            },
            Identifier::String(ref value) => {
                3 + value.byte_len()
            },
            Identifier::Guid(ref value) => {
                3 + value.byte_len()
            },
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
                    size += write_u64(stream, *value as u64)?;
                }
            },
            Identifier::String(ref value) => {
                size += write_u8(stream, 0x3)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            },
            Identifier::Guid(ref value) => {
                size += write_u8(stream, 0x4)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            },
            Identifier::ByteString(ref value) => {
                size += write_u8(stream, 0x5)?;
                size += write_u16(stream, self.namespace)?;
                size += value.encode(stream)?;
            }
        }
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let identifier = read_u8(stream)?;
        let node_id = match identifier {
            0x0 => {
                let namespace = 0;
                let value = read_u8(stream)? as u64;
                NodeId::new_numeric(namespace, value)
            },
            0x1 => {
                let namespace = read_u8(stream)? as u16;
                let value = read_u16(stream)? as u64;
                NodeId::new_numeric(namespace, value)
            },
            0x2 => {
                let namespace = read_u16(stream)?;
                let value = read_u64(stream)?;
                NodeId::new_numeric(namespace, value)
            },
            0x3 => {
                let namespace = read_u16(stream)?;
                let value = UAString::decode(stream)?;
                NodeId::new_string(namespace, value.to_str())
            },
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream)?;
                NodeId::new_guid(namespace, value)
            },
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream)?;
                NodeId::new_byte_string(namespace, value)
            }
            _ => {
                panic!("Unrecognized node id type {:?}", identifier);
            }
        };
        Ok(node_id)
    }
}

impl FromStr for NodeId {
    type Err = &'static StatusCode;
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
            return Err(&BAD_NODE_ID_INVALID)
        }
        let captures = captures.unwrap();

        let ns = captures.name("ns");

        // Check namespace (optional)
        let namespace = if ns.is_some() {
            let parse_result = ns.unwrap().as_str().parse::<UInt16>();
            if parse_result.is_err() {
                return Err(&BAD_NODE_ID_INVALID)
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
                let number = v.as_str().parse::<UInt64>();
                if number.is_err() {
                    return Err(&BAD_NODE_ID_INVALID)
                }
                NodeId::new_numeric(namespace, number.unwrap())
            },
            "s" => {
                NodeId::new_string(namespace, v.as_str())
            },
            "g" => {
                let guid = Guid::parse_str(v.as_str());
                if guid.is_err() {
                    return Err(&BAD_NODE_ID_INVALID)
                }
                NodeId::new_guid(namespace, guid.unwrap())
            },
            "b" => {
                // Parse hex back into bytes
                // NodeId::new_bytestring(namespace, ByteString::from_bytes(decoded_v.as_str()))
                error!("ByteString parsing needs to be implemented");
                return Err(&BAD_NODE_ID_INVALID);
            },
            _ => {
                return Err(&BAD_NODE_ID_INVALID)
            }
        };
        Ok(node_id)
    }
}

impl NodeId {
    /// Returns a null node id
    pub fn null() -> NodeId {
        NodeId::new_numeric(0, 0)
    }

    /// Makes a NodeId that holds a DataTypeId
    pub fn from_data_type_id(id: DataTypeId) -> NodeId {
        NodeId::new_numeric(0, id as UInt64)
    }

    /// Makes a NodeId that holds an ObjectId
    pub fn from_object_id(id: ObjectId) -> NodeId {
        NodeId::new_numeric(0, id as UInt64)
    }

    /// Makes a NodeId that holds an ObjectTypeId
    pub fn from_object_type_id(id: ObjectTypeId) -> NodeId {
        NodeId::new_numeric(0, id as UInt64)
    }

    /// Makes a NodeId that holds a ReferenceTypeId
    pub fn from_reference_type_id(id: ReferenceTypeId) -> NodeId {
        NodeId::new_numeric(0, id as UInt64)
    }

    /// Extracts an ObjectId from a node id, providing the node id holds an object id
    pub fn as_object_id(&self) -> std::result::Result<ObjectId, ()> {
        match self.identifier {
            Identifier::Numeric(object_id) if self.namespace == 0 => ObjectId::from_u64(object_id),
            _ => Err(())
        }
    }

    pub fn to_string(&self) -> String {
        let mut result = String::new();
        if self.namespace != 0 {
            result.push_str(&format!("ns={};", self.namespace));
        }
        result.push_str(&match self.identifier {
            Identifier::Numeric(ref value) => {
                format!("i={}", value)
            },
            Identifier::String(ref value) => {
                if value.is_null() {
                    "null".to_string()
                } else {
                    format!("s={}", value.to_str())
                }
            },
            Identifier::Guid(ref value) => {
                format!("g={:?}", value)
            },
            Identifier::ByteString(ref value) => {
                if value.is_null() {
                    "null".to_string()
                } else {
                    // Base64 encode bytes
                    format!("b=implementme", )
                }
            }
        });
        result
    }

    /// Construct a numeric node id
    pub fn new_numeric(namespace: UInt16, value: UInt64) -> NodeId {
        NodeId { namespace: namespace, identifier: Identifier::Numeric(value), }
    }

    /// Construct a string node id
    pub fn new_string(namespace: UInt16, value: &str) -> NodeId {
        NodeId { namespace: namespace, identifier: Identifier::String(UAString::from_str(value)), }
    }

    /// Construct a guid node id
    pub fn new_guid(namespace: UInt16, value: Guid) -> NodeId {
        NodeId { namespace: namespace, identifier: Identifier::Guid(value), }
    }

    /// Construct a bytestring node id
    pub fn new_byte_string(namespace: UInt16, value: ByteString) -> NodeId {
        NodeId { namespace: namespace, identifier: Identifier::ByteString(value), }
    }

    /// Test if the node id is null, i.e. 0 namespace and 0 identifier
    pub fn is_null(&self) -> bool {
        match self.identifier {
            Identifier::Numeric(id) => { id == 0 && self.namespace == 0 },
            _ => false,
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
/// Data type ID 18
#[derive(PartialEq, Debug, Clone)]
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
                    size += write_u8(stream, data_encoding | 0x0)?;
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
                    size += write_u64(stream, *value as u64)?;
                }
            },
            Identifier::String(ref value) => {
                size += write_u8(stream, data_encoding | 0x3)?;
                size += write_u16(stream, self.node_id.namespace)?;
                size += value.encode(stream)?;
            },
            Identifier::Guid(ref value) => {
                size += write_u8(stream, data_encoding | 0x4)?;
                size += write_u16(stream, self.node_id.namespace)?;
                size += value.encode(stream)?;
            },
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

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let data_encoding = read_u8(stream)?;
        let identifier = data_encoding & 0x0f;
        let node_id = match identifier {
            0x0 => {
                let namespace = 0;
                let value = read_u8(stream)? as u64;
                NodeId::new_numeric(namespace, value)
            },
            0x1 => {
                let namespace = read_u8(stream)? as u16;
                let value = read_u16(stream)? as u64;
                NodeId::new_numeric(namespace, value)
            },
            0x2 => {
                let namespace = read_u16(stream)?;
                let value = read_u64(stream)?;
                NodeId::new_numeric(namespace, value)
            },
            0x3 => {
                let namespace = read_u16(stream)?;
                let value = UAString::decode(stream)?;
                NodeId::new_string(namespace, value.to_str())
            },
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream)?;
                NodeId::new_guid(namespace, value)
            },
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream)?;
                NodeId::new_byte_string(namespace, value)
            }
            _ => {
                panic!("Unrecognized node id type {:?}", identifier);
            }
        };

        // Optional stuff
        let namespace_uri = if data_encoding & 0x80 != 0 { UAString::decode(stream)? } else { UAString::null() };
        let server_index = if data_encoding & 0x40 != 0 { UInt32::decode(stream)? } else { 0 };

        Ok(ExpandedNodeId {
            node_id: node_id,
            namespace_uri: namespace_uri,
            server_index: server_index,
        })
    }
}

impl ExpandedNodeId {
    /// Creates an expanded node id from a node id
    pub fn new(node_id: &NodeId) -> ExpandedNodeId {
        ExpandedNodeId {
            node_id: node_id.clone(),
            namespace_uri: UAString::null(),
            server_index: 0,
        }
    }

    pub fn null() -> ExpandedNodeId {
        Self::new(&NodeId::null())
    }

    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}