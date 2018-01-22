use std;
use std::io::{Read, Write};

use profiles;
use encoding::*;
use basic_types::*;
use string::UAString;
use byte_string::ByteString;
use attribute::AttributeId;
use data_types::*;
use date_time::DateTime;
use data_value::DataValue;
use node_id::NodeId;
use variant::Variant;
use supported_message::SupportedMessage;
use status_codes::StatusCode;
use status_codes::StatusCode::*;
use node_ids::ObjectId;
use service_types::{DataChangeFilter, AnonymousIdentityToken, UserNameIdentityToken, SignatureData, ReadValueId, EndpointDescription, ServiceFault};
use service_types::{MonitoredItemCreateRequest, MonitoringParameters};
use service_types::ApplicationDescription;

/// Implemented by messages
pub trait MessageInfo {
    /// The object id associated with the message
    fn object_id(&self) -> ObjectId;
}

/// The enumeration for the type of user identity token supported by an endpoint.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UserTokenType {
    // No token required
    Anonymous = 0,
    // A username/password token
    Username = 1,
    // An X509v3 certificate token
    Certificate = 2,
    // Any WS-security defined token
    IssuedToken = 3,
}

impl BinaryEncoder<UserTokenType> for UserTokenType {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let user_token_type = read_i32(stream)?;
        match user_token_type {
            0 => Ok(UserTokenType::Anonymous),
            1 => Ok(UserTokenType::Username),
            2 => Ok(UserTokenType::Certificate),
            3 => Ok(UserTokenType::IssuedToken),
            _ => {
                error!("Don't know what user token type {} is", user_token_type);
                Err(BadUnexpectedError)
            }
        }
    }
}

impl Into<SupportedMessage> for ServiceFault {
    fn into(self) -> SupportedMessage {
        SupportedMessage::ServiceFault(self)
    }
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ApplicationType {
    Server = 0,
    Client = 1,
    ClientAndServer = 2,
    DiscoveryServer = 3,
}

impl BinaryEncoder<ApplicationType> for ApplicationType {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let value = read_i32(stream)?;
        Ok(match value {
            0 => { ApplicationType::Server }
            1 => { ApplicationType::Client }
            2 => { ApplicationType::ClientAndServer }
            3 => { ApplicationType::DiscoveryServer }
            _ => {
                error!("Invalid ApplicationType");
                ApplicationType::Server
            }
        })
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
    /// timeout, he can cancel the operation by sending the Service result BadTimeout.
    /// The Server should wait at minimum the timeout after he received the request before
    /// cancelling the operation. The Server shall check the timeoutHint parameter of a
    /// PublishRequest before processing a PublishResponse. If the request timed out, a
    /// BadTimeout Service result is sent and another PublishRequest is used.  The
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

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
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

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let authentication_token = NodeId::decode(stream)?;
        let timestamp = UtcTime::decode(stream)?;
        let request_handle = IntegerId::decode(stream)?;
        let return_diagnostics = UInt32::decode(stream)?;
        let audit_entry_id = UAString::decode(stream)?;
        let timeout_hint = UInt32::decode(stream)?;
        let additional_header = ExtensionObject::decode(stream)?;
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
            return_diagnostics: 0,
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

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let timestamp = UtcTime::decode(stream)?;
        let request_handle = IntegerId::decode(stream)?;
        let service_result = StatusCode::decode(stream)?;
        let service_diagnostics = DiagnosticInfo::decode(stream)?;
        let string_table: Option<Vec<UAString>> = read_array(stream)?;
        let additional_header = ExtensionObject::decode(stream)?;
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
        ResponseHeader::new_service_result(request_header, Good)
    }

    pub fn new_service_result(request_header: &RequestHeader, service_result: StatusCode) -> ResponseHeader {
        ResponseHeader::new_timestamped_service_result(DateTime::now(), request_header, service_result)
    }

    pub fn new_timestamped_service_result(timestamp: DateTime, request_header: &RequestHeader, service_result: StatusCode) -> ResponseHeader {
        ResponseHeader {
            timestamp,
            request_handle: request_header.request_handle,
            service_result,
            service_diagnostics: DiagnosticInfo::new(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }

    /// For testing, nothing else
    pub fn null() -> ResponseHeader {
        ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 0,
            service_result: Good,
            service_diagnostics: DiagnosticInfo::new(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TimestampsToReturn {
    Source = 0,
    Server = 1,
    Both = 2,
    Neither = 3,
}

impl BinaryEncoder<TimestampsToReturn> for TimestampsToReturn {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(TimestampsToReturn::Source),
            1 => Ok(TimestampsToReturn::Server),
            2 => Ok(TimestampsToReturn::Both),
            3 => Ok(TimestampsToReturn::Neither),
            _ => {
                error!("Don't know what TimestampsToReturn value {} is", value);
                Err(BadTimestampsToReturnInvalid)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NodeClass {
    Unspecified = 0,
    Object = 1,
    Variable = 2,
    Method = 4,
    ObjectType = 8,
    VariableType = 16,
    ReferenceType = 32,
    DataType = 64,
    View = 128,
}

impl BinaryEncoder<NodeClass> for NodeClass {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        let result = NodeClass::from_i32(value);
        if result.is_some() {
            Ok(result.unwrap())
        } else {
            error!("Don't know what node class {} is", value);
            Err(BadNodeClassInvalid)
        }
    }
}

impl NodeClass {
    pub fn from_i32(value: Int32) -> Option<NodeClass> {
        match value {
            0 => Some(NodeClass::Unspecified),
            1 => Some(NodeClass::Object),
            2 => Some(NodeClass::Variable),
            4 => Some(NodeClass::Method),
            8 => Some(NodeClass::ObjectType),
            16 => Some(NodeClass::VariableType),
            32 => Some(NodeClass::ReferenceType),
            64 => Some(NodeClass::DataType),
            128 => Some(NodeClass::View),
            _ => {
                None
            }
        }
    }
}


#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DataChangeTrigger {
    Status = 0,
    StatusValue = 1,
    StatusValueTimestamp = 2,
}

impl BinaryEncoder<DataChangeTrigger> for DataChangeTrigger {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(DataChangeTrigger::Status),
            1 => Ok(DataChangeTrigger::StatusValue),
            2 => Ok(DataChangeTrigger::StatusValueTimestamp),
            _ => {
                error!("Don't know what data change trigger {} is", value);
                Err(BadUnexpectedError)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FilterOperator {
    Equals = 0,
    IsNull = 1,
    GreaterThan = 2,
    LessThan = 3,
    GreaterThanOrEqual = 4,
    LessThanOrEqual = 5,
    Like = 6,
    Not = 7,
    Between = 8,
    InList = 9,
    And = 10,
    Or = 11,
    Cast = 12,
    BitwiseAnd = 16,
    BitwiseOr = 17,
}

impl BinaryEncoder<FilterOperator> for FilterOperator {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(FilterOperator::Equals),
            1 => Ok(FilterOperator::IsNull),
            2 => Ok(FilterOperator::GreaterThan),
            3 => Ok(FilterOperator::LessThan),
            4 => Ok(FilterOperator::GreaterThanOrEqual),
            5 => Ok(FilterOperator::LessThanOrEqual),
            6 => Ok(FilterOperator::Like),
            7 => Ok(FilterOperator::Not),
            8 => Ok(FilterOperator::Between),
            9 => Ok(FilterOperator::InList),
            10 => Ok(FilterOperator::And),
            11 => Ok(FilterOperator::Or),
            12 => Ok(FilterOperator::Cast),
            16 => Ok(FilterOperator::BitwiseAnd),
            17 => Ok(FilterOperator::BitwiseOr),
            _ => {
                error!("Don't know what filter operator {} is", value);
                Err(BadFilterOperatorInvalid)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BrowseDirection {
    Forward = 0,
    Inverse = 1,
    Both = 2,
}

impl BinaryEncoder<BrowseDirection> for BrowseDirection {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(BrowseDirection::Forward),
            1 => Ok(BrowseDirection::Inverse),
            2 => Ok(BrowseDirection::Both),
            _ => {
                error!("Don't know what browse direction {} is", value);
                Err(BadBrowseDirectionInvalid)
            }
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum SecurityTokenRequestType {
    Issue = 0,
    Renew = 1,
}

impl BinaryEncoder<SecurityTokenRequestType> for SecurityTokenRequestType {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
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
                return Ok(false);
            }

            let v1 = v1.unwrap();
            let v2 = v2.unwrap();

            if self.deadband_value < 0f64 {
                return Err(BadDeadbandFilterInvalid);
            }
            if self.deadband_type == 1 {
                Ok(DataChangeFilter::abs_compare(v1, v2, self.deadband_value))
            } else if self.deadband_type == 2 {
                if eu_range.is_none() {
                    return Err(BadDeadbandFilterInvalid);
                }
                let (low, high) = eu_range.unwrap();
                if low >= high {
                    return Err(BadDeadbandFilterInvalid);
                }
                Ok(DataChangeFilter::pct_compare(v1, v2, low, high, self.deadband_value))
            } else {
                // Type is not recognized
                return Err(BadDeadbandFilterInvalid);
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
            Err(BadIdentityTokenRejected)
        }
    }
}

impl ReadValueId {
    pub fn read_value(node_id: NodeId) -> ReadValueId {
        ReadValueId {
            node_id,
            attribute_id: AttributeId::Value as UInt32,
            // Value
            index_range: UAString::null(),
            data_encoding: QualifiedName::null(),
        }
    }
}

impl AnonymousIdentityToken {
    pub fn new() -> AnonymousIdentityToken {
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ServerState {
    Running = 0,
    Failed = 1,
    NoConfiguration = 2,
    Suspended = 3,
    Shutdown = 4,
    Test = 5,
    CommunicationFault = 6,
    Unknown = 7,
}

impl BinaryEncoder<ServerState> for ServerState {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(ServerState::Running),
            1 => Ok(ServerState::Failed),
            2 => Ok(ServerState::NoConfiguration),
            3 => Ok(ServerState::Suspended),
            4 => Ok(ServerState::Shutdown),
            5 => Ok(ServerState::Test),
            6 => Ok(ServerState::CommunicationFault),
            7 => Ok(ServerState::Unknown),
            _ => {
                error!("Don't know what server state {} is", value);
                Err(BadUnexpectedError)
            }
        }
    }
}
