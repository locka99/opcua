use std::io::{Read, Write, Seek, Result};

use types::*;
use super::types::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum SecurityTokenRequestType {
    Issue = 0,
    Renew = 1
}

impl BinaryEncoder<SecurityTokenRequestType> for SecurityTokenRequestType {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write + Seek>(&self, stream: &mut S) -> Result<usize> {
        // All enums are Int32
        debug!("Writing security token request type as {}", *self as Int32);
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read + Seek>(stream: &mut S) -> Result< SecurityTokenRequestType> {
        // All enums are Int32
        let security_token_request_type = read_i32(stream)?;
        Ok(match security_token_request_type {
            0 => SecurityTokenRequestType::Issue,
            1 => SecurityTokenRequestType::Renew,
            _ => {
                error!("Don't know what security token request type {} is", security_token_request_type);
                SecurityTokenRequestType::Issue
            }
        })
    }
}

/// If you read the OPC UA Specs part 4 and part 6 both
/// describe DIFFERENT fields for OpenSecureChannel. Why?
/// Because shut-up. Part 6 tries to explain after casually
/// mentioning they're different but it would have made more
/// sense to call these things different names to begin with?
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSecureChannelRequest {
    /// Common request parameters. The authenticationToken is always omitted.
    pub request_header: RequestHeader,

    /// Client protocol (again) after hello
    pub client_protocol_version: UInt32,

    /// The type of SecurityToken request: An enumeration that shall be one of the following:
    /// ISSUE_0 creates a new SecurityToken for a new SecureChannel.
    /// RENEW_1 creates a new SecurityToken for an existing SecureChannel.
    pub request_type: SecurityTokenRequestType,

    /// The type of security to apply to the messages.
    /// The type MessageSecurityMode type is defined in 7.15.
    /// A SecureChannel may have to be created even if the securityMode is NONE. The exact behaviour
    /// depends on the mapping used and is described in the Part 6.
    pub security_mode: MessageSecurityMode,

    /// A random number that shall not be used in any other request. A new clientNonce shall be
    /// generated for each time a SecureChannel is renewed. This parameter shall have a length equal
    /// to key size used for the symmetric encryption algorithm that is identified by the securityPolicyUri
    pub client_nonce: ByteString,

    /// The requested lifetime, in milliseconds, for the new SecurityToken. It specifies when the
    /// Client expects to renew the SecureChannel by calling the OpenSecureChannel Service again.
    /// If a SecureChannel is not renewed, then all Messages sent using the current SecurityTokens
    /// shall be rejected by the receiver.
    pub requested_lifetime: Int32,
}

impl ObjectInfo for OpenSecureChannelRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::OpenSecureChannelRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<OpenSecureChannelRequest> for OpenSecureChannelRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.client_protocol_version.byte_len();
        size += self.request_type.byte_len();
        size += self.security_mode.byte_len();
        size += self.client_nonce.byte_len();
        size += self.requested_lifetime.byte_len();
        size
    }

    fn encode<S: Write + Seek>(&self, stream: &mut S) -> Result<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        debug!("e OpenSecureChannelRequest::request_header");
        size += self.client_protocol_version.encode(stream)?;
        debug!("e OpenSecureChannelRequest::client_protocol_version");
        size += self.request_type.encode(stream)?;
        debug!("e OpenSecureChannelRequest::request_type");
        size += self.security_mode.encode(stream)?;
        debug!("e OpenSecureChannelRequest::security_mode");
        size += self.client_nonce.encode(stream)?;
        debug!("e OpenSecureChannelRequest::client_nonce");
        size += self.requested_lifetime.encode(stream)?;
        debug!("e OpenSecureChannelRequest::requested_lifetime");
        Ok(size)
    }

    fn decode<S: Read + Seek>(stream: &mut S) -> Result< OpenSecureChannelRequest> {
        let request_header = RequestHeader::decode(stream)?;
        debug!("OpenSecureChannelRequest::request_header");
        let client_protocol_version = UInt32::decode(stream)?;
        debug!("OpenSecureChannelRequest::client_protocol_version");
        let request_type = SecurityTokenRequestType::decode(stream)?;
        debug!("OpenSecureChannelRequest::request_type");
        let security_mode = MessageSecurityMode::decode(stream)?;
        debug!("OpenSecureChannelRequest::security_mode");
        let client_nonce = ByteString::decode(stream)?;
        debug!("OpenSecureChannelRequest::client_nonce");
        let requested_lifetime = Int32::decode(stream)?;
        debug!("OpenSecureChannelRequest::requested_lifetime");
        Ok(OpenSecureChannelRequest {
            request_header: request_header,
            client_protocol_version: client_protocol_version,
            request_type: request_type,
            security_mode: security_mode,
            client_nonce: client_nonce,
            requested_lifetime: requested_lifetime,
        })
    }
}

/// OpenSecureChannelResponse is afflicted by same differences
/// between part 4 and 6 as the request
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSecureChannelResponse {
    /// Common response parameters
    pub response_header: ResponseHeader,
    /// Server protocol version
    pub server_protocol_version: UInt32,
    /// Describes the new SecurityToken issued by the Server. This structure is defined in-line
    /// with the following indented items.
    pub security_token: ChannelSecurityToken,
    /// A random number that shall not be used in any other request. A new serverNonce shall be
    /// generated for each time a SecureChannel is renewed. This parameter shall have a length equal
    /// to key size used for the symmetric encryption algorithm that is identified by the securityPolicyUri.
    pub server_nonce: ByteString,
}

impl ObjectInfo for OpenSecureChannelResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::OpenSecureChannelResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<OpenSecureChannelResponse> for OpenSecureChannelResponse {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;
        size += self.response_header.byte_len();
        size += self.server_protocol_version.byte_len();
        size += self.security_token.byte_len();
        size += self.server_nonce.byte_len();
        size
    }

    fn encode<S: Write + Seek>(&self, stream: &mut S) -> Result<usize> {
        let mut size: usize = 0;
        size += self.response_header.encode(stream)?;
        size += self.server_protocol_version.encode(stream)?;
        size += self.security_token.encode(stream)?;
        size += self.server_nonce.encode(stream)?;
        Ok(size)
    }

    fn decode<S: Read + Seek>(stream: &mut S) -> Result< OpenSecureChannelResponse> {
        let response_header = ResponseHeader::decode(stream)?;
        let server_protocol_version = UInt32::decode(stream)?;
        let security_token = ChannelSecurityToken::decode(stream)?;
        let server_nonce = ByteString::decode(stream)?;
        Ok(OpenSecureChannelResponse {
            response_header: response_header,
            server_protocol_version: server_protocol_version,
            security_token: security_token,
            server_nonce: server_nonce,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CloseSecureChannelRequest {
    /// Common request parameters. The authenticationToken is always omitted.
    pub request_header: RequestHeader,
    /// The identifier for the SecureChannel to close.
    pub secure_channel_id: ByteString
}

impl ObjectInfo for CloseSecureChannelRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::CloseSecureChannelRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<CloseSecureChannelRequest> for CloseSecureChannelRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.secure_channel_id.byte_len();
        size
    }

    fn encode<S: Write + Seek>(&self, stream: &mut S) -> Result<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.secure_channel_id.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read + Seek>(stream: &mut S) -> Result< CloseSecureChannelRequest> {
        let request_header = RequestHeader::decode(stream)?;
        let secure_channel_id = ByteString::decode(stream)?;
        Ok(CloseSecureChannelRequest {
            request_header: request_header,
            secure_channel_id: secure_channel_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CloseSecureChannelResponse {
    /// Common response parameters
    pub response_header: ResponseHeader,
}

impl ObjectInfo for CloseSecureChannelResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::CloseSecureChannelResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<CloseSecureChannelResponse> for CloseSecureChannelResponse {
    fn byte_len(&self) -> usize {
        self.response_header.byte_len()
    }

    fn encode<S: Write + Seek>(&self, stream: &mut S) -> Result<usize> {
        Ok(self.response_header.encode(stream)?)
    }

    fn decode<S: Read + Seek>(stream: &mut S) -> Result< CloseSecureChannelResponse> {
        let response_header = ResponseHeader::decode(stream)?;
        Ok(CloseSecureChannelResponse {
            response_header: response_header,
        })
    }
}