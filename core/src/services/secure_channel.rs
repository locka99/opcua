use std::io::{Read, Write, Result};

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

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode(stream: &mut Read) -> Result<SecurityTokenRequestType> {
        // All enums are Int32
        let security_token_request_type = read_i32(stream)?;
        Ok(match security_token_request_type {
            0 => { SecurityTokenRequestType::Issue }
            1 => { SecurityTokenRequestType::Renew }
            _ => {
                error!("Don't know what security token request type is");
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

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.client_protocol_version.encode(stream)?;
        size += self.request_type.encode(stream)?;
        size += self.security_mode.encode(stream)?;
        size += self.client_nonce.encode(stream)?;
        size += self.requested_lifetime.encode(stream)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<OpenSecureChannelRequest> {
        let request_header = RequestHeader::decode(stream)?;
        let client_protocol_version = UInt32::decode(stream)?;
        let request_type = SecurityTokenRequestType::decode(stream)?;
        let security_mode = MessageSecurityMode::decode(stream)?;
        let client_nonce = ByteString::decode(stream)?;
        let requested_lifetime = Int32::decode(stream)?;
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

#[derive(Debug, Clone, PartialEq)]
pub struct OpenSecureChannelResponse {
    /// Common response parameters
    pub response_header: ResponseHeader,
    /// Describes the new SecurityToken issued by the Server. This structure is defined in-line
    /// with the following indented items.
    pub security_token: ChannelSecurityToken,
    /// A unique identifier for the SecureChannel. This is the identifier that shall be supplied
    /// whenever the SecureChannel is renewed.
    pub channel_id: ByteString,
    /// A unique identifier for a single SecurityToken within the channel. This is the identifier
    /// that shall be passed with each Message secured with the SecurityToken
    pub token_id: ByteString,
    /// The time when the SecurityToken was created.
    pub created_at: UtcTime,
    /// The lifetime of the SecurityToken in milliseconds. The UTC expiration time for the token may
    /// be calculated by adding the lifetime to the createdAt time.
    pub revised_lifetime: Duration,
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
        size += self.security_token.byte_len();
        size += self.channel_id.byte_len();
        size += self.token_id.byte_len();
        size += self.created_at.byte_len();
        size += self.revised_lifetime.byte_len();
        size += self.server_nonce.byte_len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += self.response_header.encode(stream)?;
        size += self.security_token.encode(stream)?;
        size += self.channel_id.encode(stream)?;
        size += self.token_id.encode(stream)?;
        size += self.created_at.encode(stream)?;
        size += self.revised_lifetime.encode(stream)?;
        size += self.server_nonce.encode(stream)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<OpenSecureChannelResponse> {
        let response_header = ResponseHeader::decode(stream)?;
        let security_token = ChannelSecurityToken::decode(stream)?;
        let channel_id = ByteString::decode(stream)?;
        let token_id = ByteString::decode(stream)?;
        let created_at = UtcTime::decode(stream)?;
        let revised_lifetime = Duration::decode(stream)?;
        let server_nonce = ByteString::decode(stream)?;
        Ok(OpenSecureChannelResponse {
            response_header: response_header,
            security_token: security_token,
            channel_id: channel_id,
            token_id: token_id,
            created_at: created_at,
            revised_lifetime: revised_lifetime,
            server_nonce: server_nonce,
        })
    }
}

#[derive(Debug, PartialEq)]
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
        unimplemented!();
    }

    fn encode(&self, _: &mut Write) -> Result<usize> {
        // This impl should be overridden
        unimplemented!()
    }

    fn decode(stream: &mut Read) -> Result<CloseSecureChannelRequest> {
        let request_header = RequestHeader::decode(stream)?;
        let secure_channel_id = ByteString::decode(stream)?;
        Ok(CloseSecureChannelRequest {
            request_header: request_header,
            secure_channel_id: secure_channel_id,
        })
    }
}

#[derive(Debug, PartialEq)]
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
        unimplemented!();
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        Ok(self.response_header.encode(stream)?)
    }

    fn decode(_: &mut Read) -> Result<CloseSecureChannelResponse> {
        // This impl should be overridden
        unimplemented!()
    }
}