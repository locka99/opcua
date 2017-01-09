use std::io::{Read, Write, Result};

use types::*;

/// Implemented by objects
pub trait ObjectInfo {
    fn object_id(&self) -> ObjectId;

    fn node_id(&self) -> NodeId {
        NodeId::from_object_id(self.object_id())
    }
}

/// ONLY complex service specific data types go in this file

// ApplicationDescription_Encoding_DefaultXml = 309,
// ApplicationDescription_Encoding_DefaultBinary = 310,
#[derive(Debug)]
pub struct ApplicationDescription {
    /// Specifies an application that is available.
    pub application_uri: ByteString,
    /// The globally unique identifier for the application instance. This URI is used as ServerUri
    /// in Services if the application is a Server.
    pub product_uri: ByteString,
    /// A localized descriptive name for the application.
    pub application_name: LocalizedText,
    /// The type of application. This value is an enumeration with
    /// one of the following values:
    /// SERVER_0    The application is a Server.
    /// CLIENT_1    The application is a Client.
    /// CLIENTANDSERVER_2 The application is a Client and a Server.
    /// DISCOVERYSERVER_3 The application is a DiscoveryServer.
    pub application_type: ApplicationType,
    /// A URI that identifies the Gateway Server associated with the discoveryUrls. This value is
    /// not specified if the Server can be accessed directly. This
    /// field is not used if the applicationType is CLIENT_1.
    pub gateway_server_uri: UAString,
    /// A URI that identifies the discovery profile supported by the URLs provided.
    /// This field is not used if the applicationType is CLIENT_1.
    /// If this value is not specified then the Endpoints shall
    /// support the Discovery Services defined in 5.4. Alternate
    /// discovery profiles are defined in Part 7.
    pub discovery_profile_uri: UAString,
    /// A list of URLs for the discovery Endpoints provided by the application. If the applicationType
    /// is CLIENT_1, this field shall contain an empty list.
    pub discovery_urls: Vec<UAString>,
}

impl BinaryEncoder<ApplicationDescription> for ApplicationDescription {
    fn byte_len(&self) -> usize {
        unimplemented!();
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += self.application_uri.encode(stream)?;
        size += self.product_uri.encode(stream)?;
        size += self.application_name.encode(stream)?;
        size += self.application_type.encode(stream)?;
        size += self.gateway_server_uri.encode(stream)?;
        size += self.discovery_profile_uri.encode(stream)?;
        // TODO discovery_urls
        // size += self.application_uri.encode(stream)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<ApplicationDescription> {
        // This impl should be overridden
        unimplemented!()
    }
}

// ApplicationInstanceCertificate = 311,
#[derive(Debug)]
pub struct ApplicationInstanceCertificate {
    /// The certificate is currently an opaque blob. Part 4 7.2 says
    /// the stuff it should contain
    pub certificate: ByteString,
}

impl BinaryEncoder<ApplicationInstanceCertificate> for ApplicationInstanceCertificate {
    fn byte_len(&self) -> usize {
        self.certificate.byte_len()
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        self.certificate.encode(stream)
    }

    fn decode(stream: &mut Read) -> Result<ApplicationInstanceCertificate> {
        let certificate = ByteString::decode(stream)?;
        debug!("ApplicationInstanceCertificate::certificate = {:?}", certificate);
        Ok(ApplicationInstanceCertificate {
            certificate: certificate,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChannelSecurityToken {
    pub secure_channel_id: UInt32,
    pub token_id: UInt32,
    pub created_at: UtcTime,
    pub revised_lifetime: Int32,
}

impl BinaryEncoder<ChannelSecurityToken> for ChannelSecurityToken {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.secure_channel_id.byte_len();
        size += self.token_id.byte_len();
        size += self.created_at.byte_len();
        size += self.revised_lifetime.byte_len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size = 0;
        size += self.secure_channel_id.encode(stream)?;
        size += self.token_id.encode(stream)?;
        size += self.created_at.encode(stream)?;
        size += self.revised_lifetime.encode(stream)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<ChannelSecurityToken> {
        let secure_channel_id = UInt32::decode(stream)?;
        let token_id = UInt32::decode(stream)?;
        let created_at = UtcTime::decode(stream)?;
        let revised_lifetime = Int32::decode(stream)?;
        Ok(ChannelSecurityToken {
            secure_channel_id: secure_channel_id,
            token_id: token_id,
            created_at: created_at,
            revised_lifetime: revised_lifetime,
        })
    }
}

#[derive(Debug)]
pub struct UserTokenPolicy {
    pub policy_id: UAString,
    pub token_type: UserIdentityToken,
    pub issued_token_type: UAString,
    pub issuer_endpoint_url: UAString,
    pub security_policy_url: UAString,
}

impl BinaryEncoder<UserTokenPolicy> for UserTokenPolicy {
    fn byte_len(&self) -> usize {
        unimplemented!();
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        // This impl should be overridden
        unimplemented!()
    }

    fn decode(stream: &mut Read) -> Result<UserTokenPolicy> {
        // This impl should be overridden
        unimplemented!()
    }
}

// EndpointDescription = 312,
#[derive(Debug)]
pub struct EndpointDescription {
    pub endpoint_url: UAString,
    pub server: ApplicationDescription,
    pub server_certificate: ApplicationInstanceCertificate,
    pub security_mode: MessageSecurityMode,
    pub user_identity_tokens: Vec<UserTokenPolicy>,
    pub transport_profile_uri: UAString,
    pub security_level: Byte
}

impl BinaryEncoder<EndpointDescription> for EndpointDescription {
    fn byte_len(&self) -> usize {
        unimplemented!();
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        // This impl should be overridden
        unimplemented!()
    }

    fn decode(stream: &mut Read) -> Result<EndpointDescription> {
        // This impl should be overridden
        unimplemented!()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ApplicationType {
    SERVER = 0,
    CLIENT = 1,
    CLIENTANDSERVER = 2,
    DISCOVERYSERVER = 3
}

impl BinaryEncoder<ApplicationType> for ApplicationType {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        write_i32(stream, *self as Int32)
    }

    fn decode(stream: &mut Read) -> Result<ApplicationType> {
        let value = read_i32(stream)?;
        Ok(match value {
            0 => { ApplicationType::SERVER },
            1 => { ApplicationType::CLIENT },
            2 => { ApplicationType::CLIENTANDSERVER },
            3 => { ApplicationType::DISCOVERYSERVER },
            _ => {
                error!("Invalid ApplicationType");
                ApplicationType::SERVER
            }
        })
    }
}

#[derive(Debug)]
pub struct UserIdentityToken {
    pub token_data: Vec<Byte>,
    pub server_nonce: Vec<Byte>,
}

impl BinaryEncoder<UserIdentityToken> for UserIdentityToken {
    fn byte_len(&self) -> usize {
        4 + 4 + self.token_data.len() + self.server_nonce.len()
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += write_u32(stream, self.token_data.len() as UInt32)?;
        for b in &self.token_data {
            size += write_u8(stream, *b)?;
        }
        size += write_u32(stream, self.server_nonce.len() as UInt32)?;
        for b in &self.server_nonce {
            size += write_u8(stream, *b)?;
        }
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<UserIdentityToken> {
        let token_data_len = read_u32(stream)?;
        let mut token_data = Vec::with_capacity(token_data_len as usize);
        token_data.resize(token_data_len as usize, 0u8);
        stream.read_exact(&mut token_data)?;

        let server_nonce_len = read_u32(stream)?;
        let mut server_nonce = Vec::with_capacity(server_nonce_len as usize);
        server_nonce.resize(server_nonce_len as usize, 0u8);
        stream.read_exact(&mut server_nonce)?;

        Ok(UserIdentityToken {
            token_data: token_data,
            server_nonce: server_nonce,
        })
    }
}

// SessionAuthenticationToken = 388,
#[derive(Debug, Clone, PartialEq)]
pub struct SessionAuthenticationToken {
    pub token: NodeId
}

impl BinaryEncoder<SessionAuthenticationToken> for SessionAuthenticationToken {
    fn byte_len(&self) -> usize {
        self.token.byte_len()
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        Ok(self.token.encode(stream)?)
    }

    fn decode(stream: &mut Read) -> Result<SessionAuthenticationToken> {
        let token = NodeId::decode(stream)?;
        Ok(SessionAuthenticationToken {
            token: token,
        })
    }
}

// RequestHeader = 389,
#[derive(Debug, Clone, PartialEq)]
pub struct RequestHeader {
    /// The secret Session identifier used to verify that the request is associated with
    /// the Session. The SessionAuthenticationToken type is defined in 7.31.
    pub authentication_token: SessionAuthenticationToken,
    /// The time the Client sent the request. The parameter is only used for diagnostic and logging
    /// purposes in the server.
    pub timestamp: UtcTime,
    ///  A requestHandle associated with the request. This client defined handle can be
    /// used to cancel the request. It is also returned in the response.
    pub request_handle: IntegerId,
    /// A bit mask that identifies the types of vendor-specific diagnostics to be returned
    /// in diagnosticInfo response parameters. The value of this parameter may consist of
    /// zero, one or more of the following values. No value indicates that diagnostics
    /// are not to be returned.
    ///
    /// Bit Value   Diagnostics to return
    /// 0x0000 0001 ServiceLevel / SymbolicId
    /// 0x0000 0002 ServiceLevel / LocalizedText
    /// 0x0000 0004 ServiceLevel / AdditionalInfo
    /// 0x0000 0008 ServiceLevel / Inner StatusCode
    /// 0x0000 0010 ServiceLevel / Inner Diagnostics
    /// 0x0000 0020 OperationLevel / SymbolicId
    /// 0x0000 0040 OperationLevel / LocalizedText
    /// 0x0000 0080 OperationLevel / AdditionalInfo
    /// 0x0000 0100 OperationLevel / Inner StatusCode
    /// 0x0000 0200 OperationLevel / Inner Diagnostics
    ///
    /// Each of these values is composed of two components, level and type, as described
    /// below. If none are requested, as indicated by a 0 value, or if no diagnostic
    /// information was encountered in processing of the request, then diagnostics information
    /// is not returned.
    ///
    /// Level:
    ///   ServiceLevel return diagnostics in the diagnosticInfo of the Service.
    ///   OperationLevel return diagnostics in the diagnosticInfo defined for individual
    ///   operations requested in the Service.
    ///
    /// Type:
    ///   SymbolicId  return a namespace-qualified, symbolic identifier for an error
    ///     or condition. The maximum length of this identifier is 32 characters.
    ///   LocalizedText return up to 256 bytes of localized text that describes the
    ///     symbolic id.
    ///   AdditionalInfo return a byte string that contains additional diagnostic
    ///     information, such as a memory image. The format of this byte string is
    ///     vendor-specific, and may depend on the type of error or condition encountered.
    ///   InnerStatusCode return the inner StatusCode associated with the operation or Service.
    ///   InnerDiagnostics return the inner diagnostic info associated with the operation or Service.
    ///     The contents of the inner diagnostic info structure are determined by other bits in the
    ///     mask. Note that setting this bit could cause multiple levels of nested
    ///     diagnostic info structures to be returned.
    pub return_diagnostics: UInt32,
    /// An identifier that identifies the Client’s security audit log entry associated with
    /// this request. An empty string value means that this parameter is not used. The AuditEntryId
    /// typically contains who initiated the action and from where it was initiated.
    /// The AuditEventId is included in the AuditEvent to allow human readers to correlate an Event
    /// with the initiating action. More details of the Audit mechanisms are defined in 6.2
    /// and in Part 3.
    pub audit_entry_id: UAString,
    /// This timeout in milliseconds is used in the Client side Communication Stack to set the
    /// timeout on a per-call base. For a Server this timeout is only a hint and can be
    /// used to cancel long running operations to free resources. If the Server detects a
    /// timeout, he can cancel the operation by sending the Service result Bad_Timeout.
    /// The Server should wait at minimum the timeout after he received the request before
    /// cancelling the operation. The Server shall check the timeoutHint parameter of a
    /// PublishRequest before processing a PublishResponse. If the request timed out, a
    /// Bad_Timeout Service result is sent and another PublishRequest is used.  The
    /// value of 0 indicates no timeout.
    pub timeout_hint: UInt32,
    /// Reserved for future use. Applications that do not understand the header should ignore it.
    pub additional_header: ExtensionObject,
}

impl BinaryEncoder<RequestHeader> for RequestHeader {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;
        size += self.authentication_token.byte_len();
        size += self.timestamp.byte_len();
        size += self.request_handle.byte_len();
        size += self.return_diagnostics.byte_len();
        size += self.audit_entry_id.byte_len();
        size += self.timeout_hint.byte_len();
        size += self.additional_header.byte_len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += self.authentication_token.encode(stream)?;
        size += self.timestamp.encode(stream)?;
        size += self.request_handle.encode(stream)?;
        size += self.return_diagnostics.encode(stream)?;
        size += self.audit_entry_id.encode(stream)?;
        size += self.timeout_hint.encode(stream)?;
        size += self.additional_header.encode(stream)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<RequestHeader> {
        let authentication_token = SessionAuthenticationToken::decode(stream)?;
        let timestamp = UtcTime::decode(stream)?;
        let request_handle = IntegerId::decode(stream)?;
        let return_diagnostics = UInt32::decode(stream)?;
        let audit_entry_id = UAString::decode(stream)?;
        let timeout_hint = UInt32::decode(stream)?;
        let additional_header = ExtensionObject::decode(stream)?;
        Ok(RequestHeader {
            authentication_token: authentication_token,
            timestamp: timestamp,
            request_handle: request_handle,
            return_diagnostics: return_diagnostics,
            audit_entry_id: audit_entry_id,
            timeout_hint: timeout_hint,
            additional_header: additional_header,
        })
    }
}

//ResponseHeader = 392,
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseHeader {
    pub timestamp: UtcTime,
    pub request_handle: IntegerId,
    pub service_result: StatusCode,
    pub service_diagnostics: DiagnosticInfo,
    pub string_table: UAString,
    pub additional_header: ExtensionObject,
}

impl BinaryEncoder<ResponseHeader> for ResponseHeader {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.timestamp.byte_len();
        size += self.request_handle.byte_len();
        size += self.service_result.byte_len();
        size += self.service_diagnostics.byte_len();
        size += self.string_table.byte_len();
        size += self.additional_header.byte_len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size = 0;
        size += self.timestamp.encode(stream)?;
        size += self.request_handle.encode(stream)?;
        size += self.service_result.encode(stream)?;
        size += self.service_diagnostics.encode(stream)?;
        size += self.string_table.encode(stream)?;
        size += self.additional_header.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<ResponseHeader> {
        let timestamp = UtcTime::decode(stream)?;
        let request_handle = IntegerId::decode(stream)?;
        let service_result = StatusCode::decode(stream)?;
        let service_diagnostics = DiagnosticInfo::decode(stream)?;
        let string_table = UAString::decode(stream)?;
        let additional_header = ExtensionObject::decode(stream)?;
        Ok(ResponseHeader {
            timestamp: timestamp,
            request_handle: request_handle,
            service_result: service_result,
            service_diagnostics: service_diagnostics,
            string_table: string_table,
            additional_header: additional_header,
        })
    }
}

// SignedSoftwareCertificate_Encoding_DefaultXml = 345,
// SignedSoftwareCertificate_Encoding_DefaultBinary = 346,
#[derive(Debug)]
pub struct SignedSoftwareCertificate {
    /// The certificate data serialized as a ByteString.
    pub certificate_data: ByteString,
    /// The signature for the certificateData
    pub signature: ByteString,
}

impl BinaryEncoder<SignedSoftwareCertificate> for SignedSoftwareCertificate {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.certificate_data.byte_len();
        size += self.signature.byte_len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size = 0;
        size += self.certificate_data.encode(stream)?;
        size += self.signature.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<SignedSoftwareCertificate> {
        let certificate_data = ByteString::decode(stream)?;
        let signature = ByteString::decode(stream)?;
        Ok(SignedSoftwareCertificate {
            certificate_data: certificate_data,
            signature: signature,
        })
    }
}

// SignatureData = 456,
#[derive(Debug)]
pub struct SignatureData {
    /// A string containing the URI of the algorithm. The URI string values are defined as part of
    /// the security profiles specified in Part 7.
    pub algorithm: UAString,
    /// This is a signature generated with the private key associated with a Certificate.
    pub signature: ByteString,
}

impl BinaryEncoder<SignatureData> for SignatureData {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.algorithm.byte_len();
        size += self.signature.byte_len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size = 0;
        size += self.algorithm.encode(stream)?;
        size += self.signature.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<SignatureData> {
        let algorithm = ByteString::decode(stream)?;
        let signature = ByteString::decode(stream)?;
        Ok(SignatureData {
            algorithm: algorithm,
            signature: signature,
        })
    }
}
