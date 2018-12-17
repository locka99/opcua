use std::{self, io::{Read, Write}};

use crate::{
    attribute::AttributeId,
    constants,
    basic_types::*,
    extension_object::ExtensionObject,
    byte_string::ByteString,
    data_types::*,
    data_value::DataValue,
    date_time::DateTime,
    encoding::*,
    node_id::NodeId,
    node_ids::ObjectId,
    diagnostic_info::{DiagnosticBits, DiagnosticInfo},
    profiles,
    service_types::{
        AnonymousIdentityToken, ApplicationType, DataChangeFilter, DataChangeTrigger,
        EndpointDescription, ReadValueId, ServiceFault, SignatureData, UserNameIdentityToken, UserTokenType,
        MonitoredItemCreateRequest, MonitoringParameters, CallMethodRequest, ServerDiagnosticsSummaryDataType,
        ApplicationDescription, UserTokenPolicy,
    },
    status_codes::StatusCode,
    string::UAString,
    supported_message::SupportedMessage,
    variant::Variant,
};

/// Implemented by messages
pub trait MessageInfo {
    /// The object id associated with the message
    fn object_id(&self) -> ObjectId;
}

impl ServiceFault {
    pub fn new(request_header: &RequestHeader, service_result: StatusCode) -> ServiceFault {
        ServiceFault {
            response_header: ResponseHeader::new_service_result(request_header, service_result)
        }
    }

    pub fn new_supported_message(request_header: &RequestHeader, service_result: StatusCode) -> SupportedMessage {
        ServiceFault::new(request_header, service_result).into()
    }
}

// RequestHeader = 389,
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

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let authentication_token = NodeId::decode(stream, decoding_limits)?;
        let timestamp = UtcTime::decode(stream, decoding_limits)?;
        let request_handle = IntegerId::decode(stream, decoding_limits)?;
        let return_diagnostics = DiagnosticBits::from_bits_truncate(u32::decode(stream, decoding_limits)?);
        let audit_entry_id = UAString::decode(stream, decoding_limits)?;
        let timeout_hint = u32::decode(stream, decoding_limits)?;
        let additional_header = ExtensionObject::decode(stream, decoding_limits)?;
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
    pub fn new(authentication_token: &NodeId, timestamp: &DateTime, request_handle: IntegerId) -> RequestHeader {
        RequestHeader {
            authentication_token: authentication_token.clone(),
            timestamp: timestamp.clone(),
            request_handle,
            return_diagnostics: DiagnosticBits::empty(),
            audit_entry_id: UAString::null(),
            timeout_hint: 0,
            additional_header: ExtensionObject::null(),
        }
    }
}

//ResponseHeader = 392,
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseHeader {
    pub timestamp: UtcTime,
    pub request_handle: IntegerId,
    pub service_result: StatusCode,
    pub service_diagnostics: DiagnosticInfo,
    pub string_table: Option<Vec<UAString>>,
    pub additional_header: ExtensionObject,
}

impl BinaryEncoder<ResponseHeader> for ResponseHeader {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.timestamp.byte_len();
        size += self.request_handle.byte_len();
        size += self.service_result.byte_len();
        size += self.service_diagnostics.byte_len();
        size += byte_len_array(&self.string_table);
        size += self.additional_header.byte_len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.timestamp.encode(stream)?;
        size += self.request_handle.encode(stream)?;
        size += self.service_result.encode(stream)?;
        size += self.service_diagnostics.encode(stream)?;
        size += write_array(stream, &self.string_table)?;
        size += self.additional_header.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let timestamp = UtcTime::decode(stream, decoding_limits)?;
        let request_handle = IntegerId::decode(stream, decoding_limits)?;
        let service_result = StatusCode::decode(stream, decoding_limits)?;
        let service_diagnostics = DiagnosticInfo::decode(stream, decoding_limits)?;
        let string_table: Option<Vec<UAString>> = read_array(stream, decoding_limits)?;
        let additional_header = ExtensionObject::decode(stream, decoding_limits)?;
        Ok(ResponseHeader {
            timestamp,
            request_handle,
            service_result,
            service_diagnostics,
            string_table,
            additional_header,
        })
    }
}

impl ResponseHeader {
    pub fn new_good(request_header: &RequestHeader) -> ResponseHeader {
        ResponseHeader::new_service_result(request_header, StatusCode::Good)
    }

    pub fn new_service_result(request_header: &RequestHeader, service_result: StatusCode) -> ResponseHeader {
        ResponseHeader::new_timestamped_service_result(DateTime::now(), request_header, service_result)
    }

    pub fn new_timestamped_service_result(timestamp: DateTime, request_header: &RequestHeader, service_result: StatusCode) -> ResponseHeader {
        ResponseHeader {
            timestamp,
            request_handle: request_header.request_handle,
            service_result,
            service_diagnostics: DiagnosticInfo::default(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }

    /// For testing, nothing else
    pub fn null() -> ResponseHeader {
        ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 0,
            service_result: StatusCode::Good,
            service_diagnostics: DiagnosticInfo::default(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }
}

impl UserTokenPolicy {
    pub fn anonymous() -> UserTokenPolicy {
        UserTokenPolicy {
            policy_id: UAString::from("anonymous"),
            token_type: UserTokenType::Anonymous,
            issued_token_type: UAString::null(),
            issuer_endpoint_url: UAString::null(),
            security_policy_uri: UAString::null(),
        }
    }
}

pub struct ValueChangeFilter {}

impl ValueChangeFilter {
    pub fn compare(&self, v1: &DataValue, v2: &DataValue) -> bool {
        v1.value == v2.value
    }
}

impl DataChangeFilter {
    /// Compares one data value to another and returns true if they differ, according to their trigger
    /// type of status, status/value or status/value/timestamp
    pub fn compare(&self, v1: &DataValue, v2: &DataValue, eu_range: Option<(f64, f64)>) -> bool {
        match self.trigger {
            DataChangeTrigger::Status => {
                v1.status == v2.status
            }
            DataChangeTrigger::StatusValue => {
                v1.status == v2.status &&
                    self.compare_value_option(&v1.value, &v2.value, eu_range)
            }
            DataChangeTrigger::StatusValueTimestamp => {
                v1.status == v2.status &&
                    self.compare_value_option(&v1.value, &v2.value, eu_range) &&
                    v1.server_timestamp == v2.server_timestamp
            }
        }
    }

    pub fn compare_value_option(&self, v1: &Option<Variant>, v2: &Option<Variant>, eu_range: Option<(f64, f64)>) -> bool {
        // Get the actual variant values
        if (v1.is_some() && v2.is_none()) ||
            (v1.is_none() && v2.is_some()) {
            false
        } else if v1.is_none() && v2.is_none() {
            // If it's always none then it hasn't changed
            true
        } else {
            // Otherwise test the filter
            let v1 = v1.as_ref().unwrap();
            let v2 = v2.as_ref().unwrap();
            let result = self.compare_value(v1, v2, eu_range);
            if let Ok(result) = result {
                result
            } else {
                true
            }
        }
    }

    /// Compares two values, either a straight value compare or a numeric comparison against the
    /// deadband settings. If deadband is asked for and the values are not convertible into a numeric
    /// value, the result is false. The value is true if the values are the same within the limits
    /// set.
    ///
    /// The eu_range is the engineering unit range and represents the range that the value should
    /// typically operate between. It's used for percentage change operations and ignored otherwise.
    ///
    /// # Errors
    ///
    /// BadDeadbandFilterInvalid indicates the deadband settings were invalid, e.g. an invalid
    /// type, or the args were invalid. A (low, high) range must be supplied for a percentage deadband compare.
    pub fn compare_value(&self, v1: &Variant, v2: &Variant, eu_range: Option<(f64, f64)>) -> std::result::Result<bool, StatusCode> {
        // TODO be able to compare arrays of numbers

        if self.deadband_type == 0 {
            // Straight comparison of values
            Ok(v1 == v2)
        } else {
            // Absolute
            let v1 = v1.as_f64();
            let v2 = v2.as_f64();
            if v1.is_none() || v2.is_none() {
                Ok(false)
            } else {
                let v1 = v1.unwrap();
                let v2 = v2.unwrap();

                if self.deadband_value < 0f64 {
                    Err(StatusCode::BadDeadbandFilterInvalid)
                } else if self.deadband_type == 1 {
                    Ok(DataChangeFilter::abs_compare(v1, v2, self.deadband_value))
                } else if self.deadband_type == 2 {
                    if eu_range.is_none() {
                        return Err(StatusCode::BadDeadbandFilterInvalid);
                    }
                    let (low, high) = eu_range.unwrap();
                    if low >= high {
                        return Err(StatusCode::BadDeadbandFilterInvalid);
                    }
                    Ok(DataChangeFilter::pct_compare(v1, v2, low, high, self.deadband_value))
                } else {
                    // Type is not recognized
                    Err(StatusCode::BadDeadbandFilterInvalid)
                }
            }
        }
    }

    /// Compares the difference between v1 and v2 to the threshold. The two values are considered equal
    /// if their difference is less than or equal to the threshold.
    pub fn abs_compare(v1: f64, v2: f64, threshold_diff: f64) -> bool {
        let diff = (v1 - v2).abs();
        diff <= threshold_diff
    }

    /// Compares the percentage difference between v1 and v2 using the low-high range as the comparison.
    /// The two values are considered equal if their perentage difference is less than or equal to the
    /// threshold.
    pub fn pct_compare(v1: f64, v2: f64, low: f64, high: f64, threshold_pct_change: f64) -> bool {
        let v1_pct = 100f64 * (v1 - low) / (high - low);
        let v2_pct = 100f64 * (v2 - low) / (high - low);
        let pct_change = (v1_pct - v2_pct).abs();
        // Comparison is equal if the % change of v1 - v2 < the threshold
        pct_change <= threshold_pct_change
    }
}

impl EndpointDescription {
    /// Finds the policy id for the specified token type in the endpoint, otherwise None
    pub fn find_policy_id(&self, token_type: UserTokenType) -> Option<UAString> {
        if let Some(ref tokens) = self.user_identity_tokens {
            if let Some(token) = tokens.iter().find(|t| t.token_type == token_type) {
                Some(token.policy_id.clone())
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl UserNameIdentityToken {
    /// Ensures the token is valid
    pub fn is_valid(&self) -> bool {
        !self.user_name.is_null() && !self.password.is_null()
    }

    /// Authenticates the token against the supplied username and password.
    pub fn authenticate(&self, username: &str, password: &[u8]) -> Result<(), StatusCode> {
        // No comparison will be made unless user and pass are explicitly set to something in the token
        // Even if someone has a blank password, client should pass an empty string, not null.
        let valid = if self.is_valid() {
            // Plaintext encryption
            if self.encryption_algorithm.is_null() {
                // Password shall be a UTF-8 encoded string
                let id_user = self.user_name.as_ref();
                let id_pass = self.password.value.as_ref().unwrap();
                if username == id_user {
                    if password == id_pass.as_slice() {
                        true
                    } else {
                        error!("Authentication error: User name {} supplied by client is recognised but password is not", username);
                        false
                    }
                } else {
                    error!("Authentication error: User name supplied by client is unrecognised");
                    false
                }
            } else {
                // TODO See 7.36.3. UserTokenPolicy and SecurityPolicy should be used to provide
                // a means to encrypt a password and not send it plain text. Sending a plaintext
                // password over unsecured network is a bad thing!!!
                error!("Authentication error: Unsupported encryption algorithm {}", self.encryption_algorithm.as_ref());
                false
            }
        } else {
            error!("Authentication error: User / pass credentials not supplied in token");
            false
        };
        if valid {
            Ok(())
        } else {
            Err(StatusCode::BadIdentityTokenRejected)
        }
    }
}

impl<'a> From<&'a NodeId> for ReadValueId {
    fn from(node_id: &'a NodeId) -> Self {
        Self::from(node_id.clone())
    }
}

impl From<NodeId> for ReadValueId {
    fn from(node_id: NodeId) -> Self {
        ReadValueId {
            node_id,
            attribute_id: AttributeId::Value as u32,
            index_range: UAString::null(),
            data_encoding: QualifiedName::null(),
        }
    }
}

impl<'a> From<(u16, &'a str)> for ReadValueId {
    fn from(v: (u16, &'a str)) -> Self {
        Self::from(NodeId::from(v))
    }
}

impl Default for AnonymousIdentityToken {
    fn default() -> Self {
        AnonymousIdentityToken {
            policy_id: UAString::from(profiles::SECURITY_USER_TOKEN_POLICY_ANONYMOUS)
        }
    }
}

impl SignatureData {
    pub fn null() -> SignatureData {
        SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null(),
        }
    }
}

impl MonitoredItemCreateRequest {
    /// Adds an item to monitor to the subscription
    pub fn new(item_to_monitor: ReadValueId, monitoring_mode: MonitoringMode, requested_parameters: MonitoringParameters) -> MonitoredItemCreateRequest {
        MonitoredItemCreateRequest {
            item_to_monitor,
            monitoring_mode,
            requested_parameters,
        }
    }
}

impl ApplicationDescription {
    pub fn null() -> ApplicationDescription {
        ApplicationDescription {
            application_uri: UAString::null(),
            product_uri: UAString::null(),
            application_name: LocalizedText::null(),
            application_type: ApplicationType::Server,
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: None,
        }
    }
}

impl Default for MonitoringParameters {
    fn default() -> Self {
        MonitoringParameters {
            client_handle: 0,
            sampling_interval: -1f64,
            filter: ExtensionObject::null(),
            queue_size: 1,
            discard_oldest: true,
        }
    }
}

impl Into<CallMethodRequest> for (NodeId, NodeId, Option<Vec<Variant>>) {
    fn into(self) -> CallMethodRequest {
        CallMethodRequest {
            object_id: self.0,
            method_id: self.1,
            input_arguments: self.2,
        }
    }
}

impl Default for ServerDiagnosticsSummaryDataType {
    fn default() -> Self {
        ServerDiagnosticsSummaryDataType {
            server_view_count: 0,
            current_session_count: 0,
            cumulated_session_count: 0,
            security_rejected_session_count: 0,
            rejected_session_count: 0,
            session_timeout_count: 0,
            session_abort_count: 0,
            current_subscription_count: 0,
            cumulated_subscription_count: 0,
            publishing_interval_count: 0,
            security_rejected_requests_count: 0,
            rejected_requests_count: 0,
        }
    }
}

impl<'a> From<&'a str> for EndpointDescription {
    fn from(v: &'a str) -> Self {
        EndpointDescription::from((v, constants::SECURITY_POLICY_NONE_URI, MessageSecurityMode::None))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode)> for EndpointDescription {
    fn from(v: (&'a str, &'a str, MessageSecurityMode)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, None))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode, UserTokenPolicy)> for EndpointDescription {
    fn from(v: (&'a str, &'a str, MessageSecurityMode, UserTokenPolicy)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, Some(vec![v.3])))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode, Vec<UserTokenPolicy>)> for EndpointDescription {
    fn from(v: (&'a str, &'a str, MessageSecurityMode, Vec<UserTokenPolicy>)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, Some(v.3)))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode, Option<Vec<UserTokenPolicy>>)> for EndpointDescription {
    fn from(v: (&'a str, &'a str, MessageSecurityMode, Option<Vec<UserTokenPolicy>>)) -> Self {
        EndpointDescription {
            endpoint_url: UAString::from(v.0),
            security_policy_uri: UAString::from(v.1),
            security_mode: v.2,
            server: ApplicationDescription::null(),
            security_level: 0,
            server_certificate: ByteString::null(),
            transport_profile_uri: UAString::null(),
            user_identity_tokens: v.3,
        }
    }
}
