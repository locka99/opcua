// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{
    self,
    io::{Read, Write},
};

use crate::types::{
    data_types::*, date_time::DateTime, diagnostic_info::DiagnosticBits, encoding::*,
    extension_object::ExtensionObject, node_id::NodeId, string::UAString,
};

/// The `RequestHeader` contains information common to every request from a client to the server.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestHeader {
    /// The secret Session identifier used to verify that the request is associated with
    /// the Session. The SessionAuthenticationToken type is defined in 7.31.
    pub authentication_token: NodeId,
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
    pub return_diagnostics: DiagnosticBits,
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
    /// timeout, he can cancel the operation by sending the Service result BadTimeout.
    /// The Server should wait at minimum the timeout after he received the request before
    /// cancelling the operation. The Server shall check the timeoutHint parameter of a
    /// PublishRequest before processing a PublishResponse. If the request timed out, a
    /// BadTimeout Service result is sent and another PublishRequest is used.  The
    /// value of 0 indicates no timeout.
    pub timeout_hint: u32,
    /// Reserved for future use. Applications that do not understand the header should ignore it.
    pub additional_header: ExtensionObject,
}

impl Default for RequestHeader {
    fn default() -> Self {
        Self {
            authentication_token: NodeId::default(),
            timestamp: DateTime::default(),
            request_handle: 0,
            return_diagnostics: DiagnosticBits::empty(),
            audit_entry_id: Default::default(),
            timeout_hint: 0,
            additional_header: Default::default(),
        }
    }
}

impl BinaryEncoder<RequestHeader> for RequestHeader {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;
        size += self.authentication_token.byte_len();
        size += self.timestamp.byte_len();
        size += self.request_handle.byte_len();
        size += self.return_diagnostics.bits().byte_len();
        size += self.audit_entry_id.byte_len();
        size += self.timeout_hint.byte_len();
        size += self.additional_header.byte_len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        size += self.authentication_token.encode(stream)?;
        size += self.timestamp.encode(stream)?;
        size += self.request_handle.encode(stream)?;
        size += self.return_diagnostics.bits().encode(stream)?;
        size += self.audit_entry_id.encode(stream)?;
        size += self.timeout_hint.encode(stream)?;
        size += self.additional_header.encode(stream)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let authentication_token = NodeId::decode(stream, decoding_options)?;
        let timestamp = UtcTime::decode(stream, decoding_options)?;
        let request_handle = IntegerId::decode(stream, decoding_options)?;
        let return_diagnostics =
            DiagnosticBits::from_bits_truncate(u32::decode(stream, decoding_options)?);
        let audit_entry_id = UAString::decode(stream, decoding_options)?;
        let timeout_hint = u32::decode(stream, decoding_options)?;
        let additional_header = ExtensionObject::decode(stream, decoding_options)?;
        Ok(RequestHeader {
            authentication_token,
            timestamp,
            request_handle,
            return_diagnostics,
            audit_entry_id,
            timeout_hint,
            additional_header,
        })
    }
}

impl RequestHeader {
    pub fn new(
        authentication_token: &NodeId,
        timestamp: &DateTime,
        request_handle: IntegerId,
    ) -> RequestHeader {
        RequestHeader {
            authentication_token: authentication_token.clone(),
            timestamp: *timestamp,
            request_handle,
            return_diagnostics: DiagnosticBits::empty(),
            audit_entry_id: UAString::null(),
            timeout_hint: 0,
            additional_header: ExtensionObject::null(),
        }
    }

    pub fn dummy() -> RequestHeader {
        RequestHeader::new(&NodeId::null(), &DateTime::now(), 1)
    }
}
