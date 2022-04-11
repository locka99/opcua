use std::{self, fmt};

use crate::types::{
    attribute::AttributeId,
    byte_string::ByteString,
    constants,
    data_value::DataValue,
    extension_object::ExtensionObject,
    localized_text::LocalizedText,
    node_id::NodeId,
    node_ids::{DataTypeId, ObjectId},
    profiles,
    qualified_name::QualifiedName,
    request_header::RequestHeader,
    response_header::ResponseHeader,
    service_types::{
        enums::DeadbandType, AnonymousIdentityToken, ApplicationDescription, ApplicationType,
        Argument, CallMethodRequest, DataChangeFilter, DataChangeTrigger, EndpointDescription,
        MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters,
        ReadValueId, ServerDiagnosticsSummaryDataType, ServiceCounterDataType, ServiceFault,
        SignatureData, UserNameIdentityToken, UserTokenPolicy, UserTokenType,
    },
    status_codes::StatusCode,
    string::UAString,
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
            response_header: ResponseHeader::new_service_result(request_header, service_result),
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

impl DataChangeFilter {
    /// Compares one data value to another and returns true if they differ, according to their trigger
    /// type of status, status/value or status/value/timestamp
    pub fn compare(&self, v1: &DataValue, v2: &DataValue, eu_range: Option<(f64, f64)>) -> bool {
        match self.trigger {
            DataChangeTrigger::Status => v1.status == v2.status,
            DataChangeTrigger::StatusValue => {
                v1.status == v2.status && self.compare_value_option(&v1.value, &v2.value, eu_range)
            }
            DataChangeTrigger::StatusValueTimestamp => {
                v1.status == v2.status
                    && self.compare_value_option(&v1.value, &v2.value, eu_range)
                    && v1.server_timestamp == v2.server_timestamp
            }
        }
    }

    /// Compares two variant values to each other. Returns true if they are considered the "same".
    pub fn compare_value_option(
        &self,
        v1: &Option<Variant>,
        v2: &Option<Variant>,
        eu_range: Option<(f64, f64)>,
    ) -> bool {
        match (v1, v2) {
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => {
                // If it's always none then it hasn't changed
                true
            }
            (Some(v1), Some(v2)) => {
                // Otherwise test the filter
                self.compare_value(v1, v2, eu_range).unwrap_or(true)
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
    pub fn compare_value(
        &self,
        v1: &Variant,
        v2: &Variant,
        eu_range: Option<(f64, f64)>,
    ) -> std::result::Result<bool, StatusCode> {
        // TODO be able to compare arrays of numbers
        if self.deadband_type == DeadbandType::None as u32 {
            // Straight comparison of values
            Ok(v1 == v2)
        } else {
            // Absolute
            match (v1.as_f64(), v2.as_f64()) {
                (None, _) | (_, None) => Ok(false),
                (Some(v1), Some(v2)) => {
                    if self.deadband_value < 0f64 {
                        Err(StatusCode::BadDeadbandFilterInvalid)
                    } else if self.deadband_type == DeadbandType::Absolute as u32 {
                        Ok(DataChangeFilter::abs_compare(v1, v2, self.deadband_value))
                    } else if self.deadband_type == DeadbandType::Percent as u32 {
                        match eu_range {
                            None => Err(StatusCode::BadDeadbandFilterInvalid),
                            Some((low, high)) => {
                                if low >= high {
                                    Err(StatusCode::BadDeadbandFilterInvalid)
                                } else {
                                    Ok(DataChangeFilter::pct_compare(
                                        v1,
                                        v2,
                                        low,
                                        high,
                                        self.deadband_value,
                                    ))
                                }
                            }
                        }
                    } else {
                        // Type is not recognized
                        Err(StatusCode::BadDeadbandFilterInvalid)
                    }
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
    /// Returns a reference to a policy that matches the supplied token type, otherwise None
    pub fn find_policy(&self, token_type: UserTokenType) -> Option<&UserTokenPolicy> {
        if let Some(ref policies) = self.user_identity_tokens {
            policies.iter().find(|t| t.token_type == token_type)
        } else {
            None
        }
    }

    /// Returns a reference to a policy that matches the supplied policy id
    pub fn find_policy_by_id(&self, policy_id: &str) -> Option<&UserTokenPolicy> {
        if let Some(ref policies) = self.user_identity_tokens {
            policies.iter().find(|t| t.policy_id.as_ref() == policy_id)
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

    // Get the plaintext password as a string, if possible.
    pub fn plaintext_password(&self) -> Result<String, StatusCode> {
        if !self.encryption_algorithm.is_empty() {
            // Should not be calling this function at all encryption is applied
            panic!();
        }
        String::from_utf8(self.password.as_ref().to_vec()).map_err(|_| StatusCode::BadDecodingError)
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
                //  a means to encrypt a password and not send it plain text. Sending a plaintext
                //  password over unsecured network is a bad thing!!!
                error!(
                    "Authentication error: Unsupported encryption algorithm {}",
                    self.encryption_algorithm.as_ref()
                );
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
            policy_id: UAString::from(profiles::SECURITY_USER_TOKEN_POLICY_ANONYMOUS),
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

impl Into<MonitoredItemCreateRequest> for NodeId {
    fn into(self) -> MonitoredItemCreateRequest {
        MonitoredItemCreateRequest::new(
            self.into(),
            MonitoringMode::Reporting,
            MonitoringParameters::default(),
        )
    }
}

impl MonitoredItemCreateRequest {
    /// Adds an item to monitor to the subscription
    pub fn new(
        item_to_monitor: ReadValueId,
        monitoring_mode: MonitoringMode,
        requested_parameters: MonitoringParameters,
    ) -> MonitoredItemCreateRequest {
        MonitoredItemCreateRequest {
            item_to_monitor,
            monitoring_mode,
            requested_parameters,
        }
    }
}

impl Default for ApplicationDescription {
    fn default() -> Self {
        Self {
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
        EndpointDescription::from((
            v,
            constants::SECURITY_POLICY_NONE_URI,
            MessageSecurityMode::None,
        ))
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

impl<'a> From<(&'a str, &'a str, MessageSecurityMode, Vec<UserTokenPolicy>)>
    for EndpointDescription
{
    fn from(v: (&'a str, &'a str, MessageSecurityMode, Vec<UserTokenPolicy>)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, Some(v.3)))
    }
}

impl<'a>
    From<(
        &'a str,
        &'a str,
        MessageSecurityMode,
        Option<Vec<UserTokenPolicy>>,
    )> for EndpointDescription
{
    fn from(
        v: (
            &'a str,
            &'a str,
            MessageSecurityMode,
            Option<Vec<UserTokenPolicy>>,
        ),
    ) -> Self {
        EndpointDescription {
            endpoint_url: UAString::from(v.0),
            security_policy_uri: UAString::from(v.1),
            security_mode: v.2,
            server: ApplicationDescription::default(),
            security_level: 0,
            server_certificate: ByteString::null(),
            transport_profile_uri: UAString::null(),
            user_identity_tokens: v.3,
        }
    }
}

const MESSAGE_SECURITY_MODE_NONE: &str = "None";
const MESSAGE_SECURITY_MODE_SIGN: &str = "Sign";
const MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT: &str = "SignAndEncrypt";

impl fmt::Display for MessageSecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MessageSecurityMode::None => MESSAGE_SECURITY_MODE_NONE,
            MessageSecurityMode::Sign => MESSAGE_SECURITY_MODE_SIGN,
            MessageSecurityMode::SignAndEncrypt => MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT,
            _ => "",
        };
        write!(f, "{}", name)
    }
}

impl From<MessageSecurityMode> for String {
    fn from(security_mode: MessageSecurityMode) -> Self {
        String::from(match security_mode {
            MessageSecurityMode::None => MESSAGE_SECURITY_MODE_NONE,
            MessageSecurityMode::Sign => MESSAGE_SECURITY_MODE_SIGN,
            MessageSecurityMode::SignAndEncrypt => MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT,
            _ => "",
        })
    }
}

impl<'a> From<&'a str> for MessageSecurityMode {
    fn from(str: &'a str) -> Self {
        match str {
            MESSAGE_SECURITY_MODE_NONE => MessageSecurityMode::None,
            MESSAGE_SECURITY_MODE_SIGN => MessageSecurityMode::Sign,
            MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT => MessageSecurityMode::SignAndEncrypt,
            _ => {
                error!("Specified security mode \"{}\" is not recognized", str);
                MessageSecurityMode::Invalid
            }
        }
    }
}

impl From<(&str, DataTypeId)> for Argument {
    fn from(v: (&str, DataTypeId)) -> Self {
        Argument {
            name: UAString::from(v.0),
            data_type: v.1.into(),
            value_rank: -1,
            array_dimensions: None,
            description: LocalizedText::new("", ""),
        }
    }
}

impl Default for ServiceCounterDataType {
    fn default() -> Self {
        Self {
            total_count: 0,
            error_count: 0,
        }
    }
}

impl ServiceCounterDataType {
    pub fn success(&mut self) {
        self.total_count += 1;
    }

    pub fn error(&mut self) {
        self.total_count += 1;
        self.error_count += 1;
    }
}
