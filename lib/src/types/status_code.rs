use std::{
    error::Error,
    fmt::Display,
    io::{Read, Write},
};

use super::encoding::{read_u32, write_u32, BinaryEncoder, DecodingOptions, EncodingResult};

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Default)]
/// Wrapper around an OPC-UA status code, with utilities for displaying,
/// parsing, and reading.
pub struct StatusCode(u32);

const SUBCODE_MASK: u32 = 0xffff_0000;
const INFO_BITS_MASK: u32 = 0b0011_1111_1111;

impl StatusCode {
    pub fn is_good(&self) -> bool {
        matches!(self.severity(), StatusCodeSeverity::Good)
    }

    pub fn is_bad(&self) -> bool {
        matches!(self.severity(), StatusCodeSeverity::Bad)
    }

    pub fn is_uncertain(&self) -> bool {
        matches!(self.severity(), StatusCodeSeverity::Uncertain)
    }

    /// Get the inner status code.
    pub fn bits(&self) -> u32 {
        self.0
    }

    pub fn from_category(category: SubStatusCode) -> Self {
        Self(category as u32)
    }

    fn get_bool(&self, offset: u8) -> bool {
        (self.0 & (1 << offset)) != 0
    }

    #[must_use = "Status code is copied, not modified in place."]
    fn set_bool(mut self, value: bool, offset: u8) -> Self {
        self.0 = self.0 & !(1 << offset) | ((value as u32) << offset);
        self
    }

    /// Get the severity of the status code.
    pub fn severity(&self) -> StatusCodeSeverity {
        // A severity of 0b11 is considered bad according to the standard
        StatusCodeSeverity::from_value((self.0 >> 30) & 0b11).unwrap_or(StatusCodeSeverity::Bad)
    }

    /// Set the severity. Note that this will clear the subcode.
    ///
    /// It is equivalent to `set_sub_code(SubStatusCode::Good/Bad/Uncertain)`
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_severity(mut self, value: StatusCodeSeverity) -> Self {
        // Setting the severity to an arbitrary value is not defined since it
        // overwrites the subcode, so we clear the category
        self.0 = self.0 & !SUBCODE_MASK | ((value as u32) << 30);
        self
    }

    /// Get the structure changed flag.
    pub fn structure_changed(&self) -> bool {
        self.get_bool(15)
    }

    /// Set the structure changed flag.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_structure_changed(self, value: bool) -> Self {
        self.set_bool(value, 15)
    }

    /// Get the semantics changed flag.
    pub fn semantics_changed(&self) -> bool {
        self.get_bool(14)
    }

    /// Set the semantics changed flag.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_semantics_changed(self, value: bool) -> Self {
        self.set_bool(value, 14)
    }

    /// Get the sub code of this status.
    pub fn sub_code(&self) -> SubStatusCode {
        SubStatusCode::from_value(self.0 & SUBCODE_MASK).unwrap_or(SubStatusCode::Invalid)
    }

    /// Set the sub code.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_sub_code(mut self, value: SubStatusCode) -> Self {
        self.0 = self.0 & !SUBCODE_MASK | ((value as u32) & SUBCODE_MASK);
        self
    }

    /// Get the info type, whether this status code represents a data value or not.
    pub fn info_type(&self) -> StatusCodeInfoType {
        StatusCodeInfoType::from_value((self.0 >> 10) & 1).unwrap_or(StatusCodeInfoType::NotUsed)
    }

    /// Set the info type, this will clear the info bits if set to NotUsed.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_info_type(mut self, value: StatusCodeInfoType) -> Self {
        self.0 = self.0 & !(1 << 10) | ((value as u32) & 1) << 10;
        // Clear the info bits if we are setting info type to not used.
        if matches!(value, StatusCodeInfoType::NotUsed) {
            self.0 = self.0 & !INFO_BITS_MASK;
        }
        self
    }

    /// Whether the value is bounded by some limit.
    pub fn limit(&self) -> StatusCodeLimit {
        // Cannot be None here.
        StatusCodeLimit::from_value((self.0 >> 8) & 0b11).unwrap_or_default()
    }

    /// Set whether the value is bounded by some limit.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_limit(mut self, limit: StatusCodeLimit) -> Self {
        self.0 = self.0 & !(0b11 << 8) | ((limit as u32) << 8);
        self
    }

    /// Get whether the "overflow" flag is set.
    pub fn overflow(&self) -> bool {
        self.get_bool(7)
    }

    /// Set the "overflow" flag.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_overflow(self, value: bool) -> Self {
        self.set_bool(value, 7)
    }

    /// Get whether the "multi_value" flag is set.
    pub fn multi_value(&self) -> bool {
        self.get_bool(4)
    }

    /// Set the "multi_value" flag.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_multi_value(self, value: bool) -> Self {
        self.set_bool(value, 4)
    }

    /// Get whether the "extra_data" flag is set.
    pub fn extra_data(&self) -> bool {
        self.get_bool(3)
    }

    /// Set the "extra_data" flag.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_extra_data(self, value: bool) -> Self {
        self.set_bool(value, 3)
    }

    /// Get whether the "partial" flag is set.
    pub fn partial(&self) -> bool {
        self.get_bool(2)
    }

    /// Set the "partial" flag.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_partial(self, value: bool) -> Self {
        self.set_bool(value, 2)
    }

    /// Get the historical value type, only applicable to historical values.
    pub fn value_type(&self) -> StatusCodeValueType {
        StatusCodeValueType::from_value(self.0 & 0b11).unwrap_or(StatusCodeValueType::Undefined)
    }

    /// Set the historical value type, only applicable to historical values.
    #[must_use = "Status code is copied, not modified in place."]
    pub fn set_value_type(mut self, value: StatusCodeValueType) -> Self {
        self.0 = self.0 & !0b11 | ((value as u32) & 0b11);
        self
    }

    /// Validate the status code.
    /// Status codes may be invalid in order to be compatible with future OPC-UA versions,
    /// but this can be called to check if they are valid according to the standard
    /// when this was written (1.05)
    pub fn validate(&self) -> Result<(), StatusCodeValidationError> {
        if self.0 >> 30 == 0b11 {
            return Err(StatusCodeValidationError::InvalidSeverity);
        }

        if self.0 & (0b11 << 28) != 0 || self.0 & (0b111 << 11) != 0 || self.0 & (0b11 << 5) != 0 {
            return Err(StatusCodeValidationError::UsedReservedBit);
        }

        if self.sub_code() == SubStatusCode::Invalid {
            return Err(StatusCodeValidationError::UnknownSubCode);
        }

        if matches!(self.info_type(), StatusCodeInfoType::NotUsed) && self.0 & INFO_BITS_MASK != 0 {
            return Err(StatusCodeValidationError::InvalidInfoBits);
        }

        Ok(())
    }
}

impl Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Special case 0 for efficiency.
        if self.0 == 0 {
            return write!(f, "Good");
        }

        write!(f, "{}", self.sub_code())?;
        if self.structure_changed() {
            write!(f, ", StructureChanged")?;
        }
        if self.semantics_changed() {
            write!(f, ", SemanticsChanged")?;
        }
        if self.limit() != StatusCodeLimit::None {
            write!(f, ", {}", self.limit())?;
        }
        if self.overflow() {
            write!(f, ", Overflow")?;
        }
        if self.multi_value() {
            write!(f, ", MultiValue")?;
        }
        if self.extra_data() {
            write!(f, ", ExtraData")?;
        }
        if self.partial() {
            write!(f, ", Partial")?;
        }
        if self.value_type() != StatusCodeValueType::Raw {
            write!(f, ", {}", self.value_type())?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self, self.0)
    }
}

impl BinaryEncoder<StatusCode> for StatusCode {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u32(stream, self.bits())
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingOptions) -> EncodingResult<Self> {
        Ok(StatusCode(read_u32(stream)?))
    }
}

impl From<u32> for StatusCode {
    fn from(value: u32) -> Self {
        StatusCode(value)
    }
}

impl From<StatusCode> for std::io::Error {
    fn from(value: StatusCode) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("StatusCode {value}"))
    }
}

impl Error for StatusCode {}

#[derive(Debug, Clone)]
pub enum StatusCodeValidationError {
    /// Severity is the reserved value 0b11
    InvalidSeverity,
    /// Used one of the reserved bits 5, 6, 11, 12, 13, 28, or 29
    UsedReservedBit,
    /// Sub code is not recognized
    UnknownSubCode,
    /// Info type is 0, but info bits are non-zero.
    InvalidInfoBits,
}

/// Macro that expands to an enum with specific values,
/// conversions from those values, and a simple string representation.
/// Each entry must have a comment, which expands to a comment on the
/// variant, and to a `description` method to get the description at compile time.
macro_rules! value_enum_impl {
    (#[doc = $edoc:literal] $type:ident, $(#[doc = $doc:literal] $code:ident = $val:literal),* $(,)?) => {
        value_enum_impl!(#[doc = $edoc] $type, _enum $($doc $code = $val),*);
        value_enum_impl!($type, _name $($code),*);
        value_enum_impl!($type, _from_val $($code = $val),*);
        value_enum_impl!($type, _description $($doc $code),*);
    };

    (#[doc = $edoc:literal] $type:ident, _enum $($comment:literal $code:ident = $val:literal),*) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, PartialEq, Eq, Hash)]
        #[doc = $edoc]
        pub enum $type {
            $(#[doc = $comment] $code = $val),*
        }

        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{} ({})", self.name(), (*self) as u32)
            }
        }
    };

    ($type:ident, _enum $($comment:literal $code:ident = $val:literal),*) => {
        #[allow(non_camel_case_types)]
        #[derive(Debug, Copy, Clone)]
        pub enum $type {
            $($(#[doc = $comment])? $code = $val),*
        }
    };

    ($type:ident, _name $($code:ident),*) => {
        impl $type {
            pub fn name(&self) -> &'static str {
                match self {
                    $(Self::$code => stringify!($code)),*
                }
            }
        }

        impl std::str::FromStr for $type {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(stringify!($code) => Ok(Self::$code)),*,
                    _ => Err(())
                }
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.name())
            }
        }
    };

    ($type:ident, _description $($comment:literal $code:ident),*) => {
        impl $type {
            pub fn description(&self) -> &'static str {
                match self {
                    $(Self::$code => $comment),*
                }
            }
        }
    };

    ($type:ident, _from_val $($code:ident = $val:literal),*) => {
        impl $type {
            pub fn from_value(val: u32) -> Option<Self> {
                match val {
                    $($val => Some(Self::$code)),*,
                    _ => None
                }
            }
        }
    }
}

// Note that the comments on variants are deliberately without an initial space.
// The initial space is included in the `description`, fixing this
// would require a proc-macro.
// This looks fine in IDE expanded documentation, and in API docs.

value_enum_impl!(
    /// Limit bits on a status code.
    StatusCodeLimit,
    ///Value is constant
    Constant = 0b11,
    ///Value is at high limit.
    High = 0b10,
    ///Value is at low limit.
    Low = 0b01,
    ///Value is not at a limit.
    None = 0b00,
);

impl Default for StatusCodeLimit {
    fn default() -> Self {
        Self::None
    }
}

value_enum_impl!(
    /// Severity of a status code.
    StatusCodeSeverity,
    ///Status code is good.
    Good = 0b00,
    ///Status code is uncertain.
    Uncertain = 0b01,
    ///Status code is bad.
    Bad = 0b10,
);

impl Default for StatusCodeSeverity {
    fn default() -> Self {
        Self::Good
    }
}

value_enum_impl!(
    /// The type of data value
    StatusCodeValueType,
    /// Value is raw
    Raw = 0b00,
    /// Value is calculated
    Calculated = 0b01,
    /// Value is interpolated
    Interpolated = 0b10,
    /// Undefined value type
    Undefined = 0b11
);

value_enum_impl!(
    /// Whether the status code represents a data value or something else.
    StatusCodeInfoType,
    /// Info bits are not used and shall be zero.
    NotUsed = 0,
    /// Status code is associated with a data value.
    DataValue = 1,
);

/// This macro accepts the OPC-UA status codes CSV verbatim, and converts it to
/// an enum, SubStatusCode, and constants under `StatusCode` for convenience.
///
/// Conveniently, this CSV is a valid rust token tree, though newlines cannot be significant in rust.
macro_rules! sub_code_impl {
    ($($code:ident,$val:literal,$doc:literal)*) => {
        value_enum_impl!(
            /// The category of a status code.
            SubStatusCode,
            $(#[doc = $doc] $code = $val),*
        );
        sub_code_impl!(_code_consts $($doc $code = $val),*);
    };

    (_code_consts $($comment:literal $code:ident = $val:literal),*) => {
        #[allow(non_upper_case_globals)]
        impl StatusCode {
            $(#[doc = $comment] pub const $code: StatusCode = StatusCode($val);)*
        }
    };
}

sub_code_impl! {
    Good,0x00000000,"The operation succeeded."
    Uncertain,0x40000000,"The operation was uncertain."
    Bad,0x80000000,"The operation failed."
    BadUnexpectedError,0x80010000,"An unexpected error occurred."
    BadInternalError,0x80020000,"An internal error occurred as a result of a programming or configuration error."
    BadOutOfMemory,0x80030000,"Not enough memory to complete the operation."
    BadResourceUnavailable,0x80040000,"An operating system resource is not available."
    BadCommunicationError,0x80050000,"A low level communication error occurred."
    BadEncodingError,0x80060000,"Encoding halted because of invalid data in the objects being serialized."
    BadDecodingError,0x80070000,"Decoding halted because of invalid data in the stream."
    BadEncodingLimitsExceeded,0x80080000,"The message encoding/decoding limits imposed by the stack have been exceeded."
    BadRequestTooLarge,0x80B80000,"The request message size exceeds limits set by the server."
    BadResponseTooLarge,0x80B90000,"The response message size exceeds limits set by the client or server."
    BadUnknownResponse,0x80090000,"An unrecognized response was received from the server."
    BadTimeout,0x800A0000,"The operation timed out."
    BadServiceUnsupported,0x800B0000,"The server does not support the requested service."
    BadShutdown,0x800C0000,"The operation was cancelled because the application is shutting down."
    BadServerNotConnected,0x800D0000,"The operation could not complete because the client is not connected to the server."
    BadServerHalted,0x800E0000,"The server has stopped and cannot process any requests."
    BadNothingToDo,0x800F0000,"No processing could be done because there was nothing to do."
    BadTooManyOperations,0x80100000,"The request could not be processed because it specified too many operations."
    BadTooManyMonitoredItems,0x80DB0000,"The request could not be processed because there are too many monitored items in the subscription."
    BadDataTypeIdUnknown,0x80110000,"The extension object cannot be (de)serialized because the data type id is not recognized."
    BadCertificateInvalid,0x80120000,"The certificate provided as a parameter is not valid."
    BadSecurityChecksFailed,0x80130000,"An error occurred verifying security."
    BadCertificatePolicyCheckFailed,0x81140000,"The certificate does not meet the requirements of the security policy."
    BadCertificateTimeInvalid,0x80140000,"The certificate has expired or is not yet valid."
    BadCertificateIssuerTimeInvalid,0x80150000,"An issuer certificate has expired or is not yet valid."
    BadCertificateHostNameInvalid,0x80160000,"The HostName used to connect to a server does not match a HostName in the certificate."
    BadCertificateUriInvalid,0x80170000,"The URI specified in the ApplicationDescription does not match the URI in the certificate."
    BadCertificateUseNotAllowed,0x80180000,"The certificate may not be used for the requested operation."
    BadCertificateIssuerUseNotAllowed,0x80190000,"The issuer certificate may not be used for the requested operation."
    BadCertificateUntrusted,0x801A0000,"The certificate is not trusted."
    BadCertificateRevocationUnknown,0x801B0000,"It was not possible to determine if the certificate has been revoked."
    BadCertificateIssuerRevocationUnknown,0x801C0000,"It was not possible to determine if the issuer certificate has been revoked."
    BadCertificateRevoked,0x801D0000,"The certificate has been revoked."
    BadCertificateIssuerRevoked,0x801E0000,"The issuer certificate has been revoked."
    BadCertificateChainIncomplete,0x810D0000,"The certificate chain is incomplete."
    BadUserAccessDenied,0x801F0000,"User does not have permission to perform the requested operation."
    BadIdentityTokenInvalid,0x80200000,"The user identity token is not valid."
    BadIdentityTokenRejected,0x80210000,"The user identity token is valid but the server has rejected it."
    BadSecureChannelIdInvalid,0x80220000,"The specified secure channel is no longer valid."
    BadInvalidTimestamp,0x80230000,"The timestamp is outside the range allowed by the server."
    BadNonceInvalid,0x80240000,"The nonce does appear to be not a random value or it is not the correct length."
    BadSessionIdInvalid,0x80250000,"The session id is not valid."
    BadSessionClosed,0x80260000,"The session was closed by the client."
    BadSessionNotActivated,0x80270000,"The session cannot be used because ActivateSession has not been called."
    BadSubscriptionIdInvalid,0x80280000,"The subscription id is not valid."
    BadRequestHeaderInvalid,0x802A0000,"The header for the request is missing or invalid."
    BadTimestampsToReturnInvalid,0x802B0000,"The timestamps to return parameter is invalid."
    BadRequestCancelledByClient,0x802C0000,"The request was cancelled by the client."
    BadTooManyArguments,0x80E50000,"Too many arguments were provided."
    BadLicenseExpired,0x810E0000,"The server requires a license to operate in general or to perform a service or operation, but existing license is expired."
    BadLicenseLimitsExceeded,0x810F0000,"The server has limits on number of allowed operations / objects, based on installed licenses, and these limits where exceeded."
    BadLicenseNotAvailable,0x81100000,"The server does not have a license which is required to operate in general or to perform a service or operation."
    BadServerTooBusy,0x80EE0000,"The Server does not have the resources to process the request at this time."
    GoodPasswordChangeRequired,0x00EF0000,"The log-on for the user succeeded but the user is required to change the password."
    GoodSubscriptionTransferred,0x002D0000,"The subscription was transferred to another session."
    GoodCompletesAsynchronously,0x002E0000,"The processing will complete asynchronously."
    GoodOverload,0x002F0000,"Sampling has slowed down due to resource limitations."
    GoodClamped,0x00300000,"The value written was accepted but was clamped."
    BadNoCommunication,0x80310000,"Communication with the data source is defined, but not established, and there is no last known value available."
    BadWaitingForInitialData,0x80320000,"Waiting for the server to obtain values from the underlying data source."
    BadNodeIdInvalid,0x80330000,"The syntax the node id is not valid or refers to a node that is not valid for the operation."
    BadNodeIdUnknown,0x80340000,"The node id refers to a node that does not exist in the server address space."
    BadAttributeIdInvalid,0x80350000,"The attribute is not supported for the specified Node."
    BadIndexRangeInvalid,0x80360000,"The syntax of the index range parameter is invalid."
    BadIndexRangeNoData,0x80370000,"No data exists within the range of indexes specified."
    BadIndexRangeDataMismatch,0x80EA0000,"The written data does not match the IndexRange specified."
    BadDataEncodingInvalid,0x80380000,"The data encoding is invalid."
    BadDataEncodingUnsupported,0x80390000,"The server does not support the requested data encoding for the node."
    BadNotReadable,0x803A0000,"The access level does not allow reading or subscribing to the Node."
    BadNotWritable,0x803B0000,"The access level does not allow writing to the Node."
    BadOutOfRange,0x803C0000,"The value was out of range."
    BadNotSupported,0x803D0000,"The requested operation is not supported."
    BadNotFound,0x803E0000,"A requested item was not found or a search operation ended without success."
    BadObjectDeleted,0x803F0000,"The object cannot be used because it has been deleted."
    BadNotImplemented,0x80400000,"Requested operation is not implemented."
    BadMonitoringModeInvalid,0x80410000,"The monitoring mode is invalid."
    BadMonitoredItemIdInvalid,0x80420000,"The monitoring item id does not refer to a valid monitored item."
    BadMonitoredItemFilterInvalid,0x80430000,"The monitored item filter parameter is not valid."
    BadMonitoredItemFilterUnsupported,0x80440000,"The server does not support the requested monitored item filter."
    BadFilterNotAllowed,0x80450000,"A monitoring filter cannot be used in combination with the attribute specified."
    BadStructureMissing,0x80460000,"A mandatory structured parameter was missing or null."
    BadEventFilterInvalid,0x80470000,"The event filter is not valid."
    BadContentFilterInvalid,0x80480000,"The content filter is not valid."
    BadFilterOperatorInvalid,0x80C10000,"An unrecognized operator was provided in a filter."
    BadFilterOperatorUnsupported,0x80C20000,"A valid operator was provided, but the server does not provide support for this filter operator."
    BadFilterOperandCountMismatch,0x80C30000,"The number of operands provided for the filter operator was less then expected for the operand provided."
    BadFilterOperandInvalid,0x80490000,"The operand used in a content filter is not valid."
    BadFilterElementInvalid,0x80C40000,"The referenced element is not a valid element in the content filter."
    BadFilterLiteralInvalid,0x80C50000,"The referenced literal is not a valid value."
    BadContinuationPointInvalid,0x804A0000,"The continuation point provide is longer valid."
    BadNoContinuationPoints,0x804B0000,"The operation could not be processed because all continuation points have been allocated."
    BadReferenceTypeIdInvalid,0x804C0000,"The reference type id does not refer to a valid reference type node."
    BadBrowseDirectionInvalid,0x804D0000,"The browse direction is not valid."
    BadNodeNotInView,0x804E0000,"The node is not part of the view."
    BadNumericOverflow,0x81120000,"The number was not accepted because of a numeric overflow."
    BadLocaleNotSupported,0x80ED0000,"The locale in the requested write operation is not supported."
    BadNoValue,0x80F00000,"The variable has no default value and no initial value."
    BadServerUriInvalid,0x804F0000,"The ServerUri is not a valid URI."
    BadServerNameMissing,0x80500000,"No ServerName was specified."
    BadDiscoveryUrlMissing,0x80510000,"No DiscoveryUrl was specified."
    BadSempahoreFileMissing,0x80520000,"The semaphore file specified by the client is not valid."
    BadRequestTypeInvalid,0x80530000,"The security token request type is not valid."
    BadSecurityModeRejected,0x80540000,"The security mode does not meet the requirements set by the server."
    BadSecurityPolicyRejected,0x80550000,"The security policy does not meet the requirements set by the server."
    BadTooManySessions,0x80560000,"The server has reached its maximum number of sessions."
    BadUserSignatureInvalid,0x80570000,"The user token signature is missing or invalid."
    BadApplicationSignatureInvalid,0x80580000,"The signature generated with the client certificate is missing or invalid."
    BadNoValidCertificates,0x80590000,"The client did not provide at least one software certificate that is valid and meets the profile requirements for the server."
    BadIdentityChangeNotSupported,0x80C60000,"The server does not support changing the user identity assigned to the session."
    BadRequestCancelledByRequest,0x805A0000,"The request was cancelled by the client with the Cancel service."
    BadParentNodeIdInvalid,0x805B0000,"The parent node id does not to refer to a valid node."
    BadReferenceNotAllowed,0x805C0000,"The reference could not be created because it violates constraints imposed by the data model."
    BadNodeIdRejected,0x805D0000,"The requested node id was reject because it was either invalid or server does not allow node ids to be specified by the client."
    BadNodeIdExists,0x805E0000,"The requested node id is already used by another node."
    BadNodeClassInvalid,0x805F0000,"The node class is not valid."
    BadBrowseNameInvalid,0x80600000,"The browse name is invalid."
    BadBrowseNameDuplicated,0x80610000,"The browse name is not unique among nodes that share the same relationship with the parent."
    BadNodeAttributesInvalid,0x80620000,"The node attributes are not valid for the node class."
    BadTypeDefinitionInvalid,0x80630000,"The type definition node id does not reference an appropriate type node."
    BadSourceNodeIdInvalid,0x80640000,"The source node id does not reference a valid node."
    BadTargetNodeIdInvalid,0x80650000,"The target node id does not reference a valid node."
    BadDuplicateReferenceNotAllowed,0x80660000,"The reference type between the nodes is already defined."
    BadInvalidSelfReference,0x80670000,"The server does not allow this type of self reference on this node."
    BadReferenceLocalOnly,0x80680000,"The reference type is not valid for a reference to a remote server."
    BadNoDeleteRights,0x80690000,"The server will not allow the node to be deleted."
    UncertainReferenceNotDeleted,0x40BC0000,"The server was not able to delete all target references."
    BadServerIndexInvalid,0x806A0000,"The server index is not valid."
    BadViewIdUnknown,0x806B0000,"The view id does not refer to a valid view node."
    BadViewTimestampInvalid,0x80C90000,"The view timestamp is not available or not supported."
    BadViewParameterMismatch,0x80CA0000,"The view parameters are not consistent with each other."
    BadViewVersionInvalid,0x80CB0000,"The view version is not available or not supported."
    UncertainNotAllNodesAvailable,0x40C00000,"The list of references may not be complete because the underlying system is not available."
    GoodResultsMayBeIncomplete,0x00BA0000,"The server should have followed a reference to a node in a remote server but did not. The result set may be incomplete."
    BadNotTypeDefinition,0x80C80000,"The provided Nodeid was not a type definition nodeid."
    UncertainReferenceOutOfServer,0x406C0000,"One of the references to follow in the relative path references to a node in the address space in another server."
    BadTooManyMatches,0x806D0000,"The requested operation has too many matches to return."
    BadQueryTooComplex,0x806E0000,"The requested operation requires too many resources in the server."
    BadNoMatch,0x806F0000,"The requested operation has no match to return."
    BadMaxAgeInvalid,0x80700000,"The max age parameter is invalid."
    BadSecurityModeInsufficient,0x80E60000,"The operation is not permitted over the current secure channel."
    BadHistoryOperationInvalid,0x80710000,"The history details parameter is not valid."
    BadHistoryOperationUnsupported,0x80720000,"The server does not support the requested operation."
    BadInvalidTimestampArgument,0x80BD0000,"The defined timestamp to return was invalid."
    BadWriteNotSupported,0x80730000,"The server does not support writing the combination of value, status and timestamps provided."
    BadTypeMismatch,0x80740000,"The value supplied for the attribute is not of the same type as the attribute's value."
    BadMethodInvalid,0x80750000,"The method id does not refer to a method for the specified object."
    BadArgumentsMissing,0x80760000,"The client did not specify all of the input arguments for the method."
    BadNotExecutable,0x81110000,"The executable attribute does not allow the execution of the method."
    BadTooManySubscriptions,0x80770000,"The server has reached its maximum number of subscriptions."
    BadTooManyPublishRequests,0x80780000,"The server has reached the maximum number of queued publish requests."
    BadNoSubscription,0x80790000,"There is no subscription available for this session."
    BadSequenceNumberUnknown,0x807A0000,"The sequence number is unknown to the server."
    GoodRetransmissionQueueNotSupported,0x00DF0000,"The Server does not support retransmission queue and acknowledgement of sequence numbers is not available."
    BadMessageNotAvailable,0x807B0000,"The requested notification message is no longer available."
    BadInsufficientClientProfile,0x807C0000,"The client of the current session does not support one or more Profiles that are necessary for the subscription."
    BadStateNotActive,0x80BF0000,"The sub-state machine is not currently active."
    BadAlreadyExists,0x81150000,"An equivalent rule already exists."
    BadTcpServerTooBusy,0x807D0000,"The server cannot process the request because it is too busy."
    BadTcpMessageTypeInvalid,0x807E0000,"The type of the message specified in the header invalid."
    BadTcpSecureChannelUnknown,0x807F0000,"The SecureChannelId and/or TokenId are not currently in use."
    BadTcpMessageTooLarge,0x80800000,"The size of the message chunk specified in the header is too large."
    BadTcpNotEnoughResources,0x80810000,"There are not enough resources to process the request."
    BadTcpInternalError,0x80820000,"An internal error occurred."
    BadTcpEndpointUrlInvalid,0x80830000,"The server does not recognize the QueryString specified."
    BadRequestInterrupted,0x80840000,"The request could not be sent because of a network interruption."
    BadRequestTimeout,0x80850000,"Timeout occurred while processing the request."
    BadSecureChannelClosed,0x80860000,"The secure channel has been closed."
    BadSecureChannelTokenUnknown,0x80870000,"The token has expired or is not recognized."
    BadSequenceNumberInvalid,0x80880000,"The sequence number is not valid."
    BadProtocolVersionUnsupported,0x80BE0000,"The applications do not have compatible protocol versions."
    BadConfigurationError,0x80890000,"There is a problem with the configuration that affects the usefulness of the value."
    BadNotConnected,0x808A0000,"The variable should receive its value from another variable, but has never been configured to do so."
    BadDeviceFailure,0x808B0000,"There has been a failure in the device/data source that generates the value that has affected the value."
    BadSensorFailure,0x808C0000,"There has been a failure in the sensor from which the value is derived by the device/data source."
    BadOutOfService,0x808D0000,"The source of the data is not operational."
    BadDeadbandFilterInvalid,0x808E0000,"The deadband filter is not valid."
    UncertainNoCommunicationLastUsableValue,0x408F0000,"Communication to the data source has failed. The variable value is the last value that had a good quality."
    UncertainLastUsableValue,0x40900000,"Whatever was updating this value has stopped doing so."
    UncertainSubstituteValue,0x40910000,"The value is an operational value that was manually overwritten."
    UncertainInitialValue,0x40920000,"The value is an initial value for a variable that normally receives its value from another variable."
    UncertainSensorNotAccurate,0x40930000,"The value is at one of the sensor limits."
    UncertainEngineeringUnitsExceeded,0x40940000,"The value is outside of the range of values defined for this parameter."
    UncertainSubNormal,0x40950000,"The data value is derived from multiple sources and has less than the required number of Good sources."
    GoodLocalOverride,0x00960000,"The value has been overridden."
    GoodSubNormal,0x00EB0000,"The value is derived from multiple sources and has the required number of Good sources, but less than the full number of Good sources."
    BadRefreshInProgress,0x80970000,"This Condition refresh failed, a Condition refresh operation is already in progress."
    BadConditionAlreadyDisabled,0x80980000,"This condition has already been disabled."
    BadConditionAlreadyEnabled,0x80CC0000,"This condition has already been enabled."
    BadConditionDisabled,0x80990000,"Property not available, this condition is disabled."
    BadEventIdUnknown,0x809A0000,"The specified event id is not recognized."
    BadEventNotAcknowledgeable,0x80BB0000,"The event cannot be acknowledged."
    BadDialogNotActive,0x80CD0000,"The dialog condition is not active."
    BadDialogResponseInvalid,0x80CE0000,"The response is not valid for the dialog."
    BadConditionBranchAlreadyAcked,0x80CF0000,"The condition branch has already been acknowledged."
    BadConditionBranchAlreadyConfirmed,0x80D00000,"The condition branch has already been confirmed."
    BadConditionAlreadyShelved,0x80D10000,"The condition has already been shelved."
    BadConditionNotShelved,0x80D20000,"The condition is not currently shelved."
    BadShelvingTimeOutOfRange,0x80D30000,"The shelving time not within an acceptable range."
    BadNoData,0x809B0000,"No data exists for the requested time range or event filter."
    BadBoundNotFound,0x80D70000,"No data found to provide upper or lower bound value."
    BadBoundNotSupported,0x80D80000,"The server cannot retrieve a bound for the variable."
    BadDataLost,0x809D0000,"Data is missing due to collection started/stopped/lost."
    BadDataUnavailable,0x809E0000,"Expected data is unavailable for the requested time range due to an un-mounted volume, an off-line archive or tape, or similar reason for temporary unavailability."
    BadEntryExists,0x809F0000,"The data or event was not successfully inserted because a matching entry exists."
    BadNoEntryExists,0x80A00000,"The data or event was not successfully updated because no matching entry exists."
    BadTimestampNotSupported,0x80A10000,"The Client requested history using a TimestampsToReturn the Server does not support."
    GoodEntryInserted,0x00A20000,"The data or event was successfully inserted into the historical database."
    GoodEntryReplaced,0x00A30000,"The data or event field was successfully replaced in the historical database."
    UncertainDataSubNormal,0x40A40000,"The aggregate value is derived from multiple values and has less than the required number of Good values."
    GoodNoData,0x00A50000,"No data exists for the requested time range or event filter."
    GoodMoreData,0x00A60000,"More data is available in the time range beyond the number of values requested."
    BadAggregateListMismatch,0x80D40000,"The requested number of Aggregates does not match the requested number of NodeIds."
    BadAggregateNotSupported,0x80D50000,"The requested Aggregate is not support by the server."
    BadAggregateInvalidInputs,0x80D60000,"The aggregate value could not be derived due to invalid data inputs."
    BadAggregateConfigurationRejected,0x80DA0000,"The aggregate configuration is not valid for specified node."
    GoodDataIgnored,0x00D90000,"The request specifies fields which are not valid for the EventType or cannot be saved by the historian."
    BadRequestNotAllowed,0x80E40000,"The request was rejected by the server because it did not meet the criteria set by the server."
    BadRequestNotComplete,0x81130000,"The request has not been processed by the server yet."
    BadTransactionPending,0x80E80000,"The operation is not allowed because a transaction is in progress."
    BadTicketRequired,0x811F0000,"The device identity needs a ticket before it can be accepted."
    BadTicketInvalid,0x81200000,"The device identity needs a ticket before it can be accepted."
    BadLocked,0x80E90000,"The requested operation is not allowed, because the Node is locked by a different application."
    BadRequiresLock,0x80EC0000,"The requested operation is not allowed, because the Node is not locked by the application."
    GoodEdited,0x00DC0000,"The value does not come from the real source and has been edited by the server."
    GoodPostActionFailed,0x00DD0000,"There was an error in execution of these post-actions."
    UncertainDominantValueChanged,0x40DE0000,"The related EngineeringUnit has been changed but the Variable Value is still provided based on the previous unit."
    GoodDependentValueChanged,0x00E00000,"A dependent value has been changed but the change has not been applied to the device."
    BadDominantValueChanged,0x80E10000,"The related EngineeringUnit has been changed but this change has not been applied to the device. The Variable Value is still dependent on the previous unit but its status is currently Bad."
    UncertainDependentValueChanged,0x40E20000,"A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is uncertain."
    BadDependentValueChanged,0x80E30000,"A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is Bad."
    GoodEdited_DependentValueChanged,0x01160000,"It is delivered with a dominant Variable value when a dependent Variable has changed but the change has not been applied."
    GoodEdited_DominantValueChanged,0x01170000,"It is delivered with a dependent Variable value when a dominant Variable has changed but the change has not been applied."
    GoodEdited_DominantValueChanged_DependentValueChanged,0x01180000,"It is delivered with a dependent Variable value when a dominant or dependent Variable has changed but change has not been applied."
    BadEdited_OutOfRange,0x81190000,"It is delivered with a Variable value when Variable has changed but the value is not legal."
    BadInitialValue_OutOfRange,0x811A0000,"It is delivered with a Variable value when a source Variable has changed but the value is not legal."
    BadOutOfRange_DominantValueChanged,0x811B0000,"It is delivered with a dependent Variable value when a dominant Variable has changed and the value is not legal."
    BadEdited_OutOfRange_DominantValueChanged,0x811C0000,"It is delivered with a dependent Variable value when a dominant Variable has changed, the value is not legal and the change has not been applied."
    BadOutOfRange_DominantValueChanged_DependentValueChanged,0x811D0000,"It is delivered with a dependent Variable value when a dominant or dependent Variable has changed and the value is not legal."
    BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged,0x811E0000,"It is delivered with a dependent Variable value when a dominant or dependent Variable has changed, the value is not legal and the change has not been applied."
    GoodCommunicationEvent,0x00A70000,"The communication layer has raised an event."
    GoodShutdownEvent,0x00A80000,"The system is shutting down."
    GoodCallAgain,0x00A90000,"The operation is not finished and needs to be called again."
    GoodNonCriticalTimeout,0x00AA0000,"A non-critical timeout occurred."
    BadInvalidArgument,0x80AB0000,"One or more arguments are invalid."
    BadConnectionRejected,0x80AC0000,"Could not establish a network connection to remote server."
    BadDisconnect,0x80AD0000,"The server has disconnected from the client."
    BadConnectionClosed,0x80AE0000,"The network connection has been closed."
    BadInvalidState,0x80AF0000,"The operation cannot be completed because the object is closed, uninitialized or in some other invalid state."
    BadEndOfStream,0x80B00000,"Cannot move beyond end of the stream."
    BadNoDataAvailable,0x80B10000,"No data is currently available for reading from a non-blocking stream."
    BadWaitingForResponse,0x80B20000,"The asynchronous operation is waiting for a response."
    BadOperationAbandoned,0x80B30000,"The asynchronous operation was abandoned by the caller."
    BadExpectedStreamToBlock,0x80B40000,"The stream did not return all data requested (possibly because it is a non-blocking stream)."
    BadWouldBlock,0x80B50000,"Non blocking behaviour is required and the operation would block."
    BadSyntaxError,0x80B60000,"A value had an invalid syntax."
    BadMaxConnectionsReached,0x80B70000,"The operation could not be finished because all available connections are in use."
    UncertainTransducerInManual,0x42080000,"The value may not be accurate because the transducer is in manual mode."
    UncertainSimulatedValue,0x42090000,"The value is simulated."
    UncertainSensorCalibration,0x420A0000,"The value may not be accurate due to a sensor calibration fault."
    UncertainConfigurationError,0x420F0000,"The value may not be accurate due to a configuration issue."
    GoodCascadeInitializationAcknowledged,0x04010000,"The value source supports cascade handshaking and the value has been Initialized based on an initialization request from a cascade secondary."
    GoodCascadeInitializationRequest,0x04020000,"The value source supports cascade handshaking and is requesting initialization of a cascade primary."
    GoodCascadeNotInvited,0x04030000,"The value source supports cascade handshaking, however, the source’s current state does not allow for cascade."
    GoodCascadeNotSelected,0x04040000,"The value source supports cascade handshaking, however, the source has not selected the corresponding cascade primary for use."
    GoodFaultStateActive,0x04070000,"There is a fault state condition active in the value source."
    GoodInitiateFaultState,0x04080000,"A fault state condition is being requested of the destination."
    GoodCascade,0x04090000,"The value is accurate, and the signal source supports cascade handshaking."
    BadDataSetIdInvalid,0x80E70000,"The DataSet specified for the DataSetWriter creation is invalid."

    Invalid,0xFFFFFFFF,"Invalid status code"
}
// Note that the invalid status code is impossible to get normally.

#[cfg(test)]
mod tests {
    use super::{
        StatusCode, StatusCodeInfoType, StatusCodeLimit, StatusCodeSeverity,
        StatusCodeValidationError, StatusCodeValueType, SubStatusCode,
    };

    #[test]
    fn test_from_sub_code() {
        assert_eq!("Good", StatusCode::Good.to_string());
        assert_eq!(
            "BadBrowseDirectionInvalid",
            StatusCode::BadBrowseDirectionInvalid.to_string()
        );
        assert_eq!(
            "UncertainDependentValueChanged",
            StatusCode::UncertainDependentValueChanged.to_string()
        );
    }

    #[test]
    fn test_modify() {
        let code = StatusCode::from(0);
        assert_eq!(code, StatusCode::Good);
        let code = code.set_severity(StatusCodeSeverity::Uncertain);
        assert_eq!(code.severity(), StatusCodeSeverity::Uncertain);
        let code = code.set_severity(StatusCodeSeverity::Bad);
        assert_eq!(code.severity(), StatusCodeSeverity::Bad);

        code.validate().unwrap();

        assert!(!code.structure_changed());
        let code = code.set_structure_changed(true);
        code.validate().unwrap();
        assert!(code.structure_changed());
        let code = code.set_structure_changed(false);
        assert!(!code.structure_changed());
        let code = code.set_structure_changed(true);

        assert!(!code.semantics_changed());
        let code = code.set_semantics_changed(true);
        code.validate().unwrap();
        assert!(code.semantics_changed());
        let code = code.set_semantics_changed(false);
        assert!(!code.semantics_changed());
        let code = code.set_semantics_changed(true);

        assert_eq!(code.sub_code(), SubStatusCode::Bad);
        let code = code.set_sub_code(SubStatusCode::BadAggregateConfigurationRejected);
        assert_eq!(
            code.sub_code(),
            SubStatusCode::BadAggregateConfigurationRejected
        );
        let code = code.set_sub_code(SubStatusCode::UncertainNotAllNodesAvailable);
        assert_eq!(
            code.sub_code(),
            SubStatusCode::UncertainNotAllNodesAvailable
        );

        assert_eq!(code.info_type(), StatusCodeInfoType::NotUsed);
        let code = code.set_info_type(StatusCodeInfoType::DataValue);
        assert_eq!(code.info_type(), StatusCodeInfoType::DataValue);
        code.validate().unwrap();
        let code = code.set_info_type(StatusCodeInfoType::NotUsed);
        assert_eq!(code.info_type(), StatusCodeInfoType::NotUsed);

        assert_eq!(code.limit(), StatusCodeLimit::None);
        let code = code.set_limit(StatusCodeLimit::High);
        assert_eq!(code.limit(), StatusCodeLimit::High);
        let code = code.set_limit(StatusCodeLimit::Constant);
        assert_eq!(code.limit(), StatusCodeLimit::Constant);

        assert!(matches!(
            code.validate(),
            Err(StatusCodeValidationError::InvalidInfoBits)
        ));
        let code = code.set_info_type(StatusCodeInfoType::DataValue);
        code.validate().unwrap();

        assert!(!code.overflow());
        let code = code.set_overflow(true);
        code.validate().unwrap();
        assert!(code.overflow());
        let code = code.set_overflow(false);
        assert!(!code.overflow());
        let code = code.set_overflow(true);

        assert!(!code.multi_value());
        let code = code.set_multi_value(true);
        code.validate().unwrap();
        assert!(code.multi_value());
        let code = code.set_multi_value(false);
        assert!(!code.multi_value());
        let code = code.set_multi_value(true);

        assert!(!code.extra_data());
        let code = code.set_extra_data(true);
        code.validate().unwrap();
        assert!(code.extra_data());
        let code = code.set_extra_data(false);
        assert!(!code.extra_data());
        let code = code.set_extra_data(true);

        assert!(!code.partial());
        let code = code.set_partial(true);
        code.validate().unwrap();
        assert!(code.partial());
        let code = code.set_partial(false);
        assert!(!code.partial());
        let code = code.set_partial(true);

        assert_eq!(code.value_type(), StatusCodeValueType::Raw);
        let code = code.set_value_type(StatusCodeValueType::Calculated);
        assert_eq!(code.value_type(), StatusCodeValueType::Calculated);
        let code = code.set_value_type(StatusCodeValueType::Interpolated);
        assert_eq!(code.value_type(), StatusCodeValueType::Interpolated);

        assert_eq!(StatusCodeSeverity::Uncertain, code.severity());
        assert!(code.structure_changed());
        assert!(code.semantics_changed());
        assert_eq!(code.info_type(), StatusCodeInfoType::DataValue);
        assert_eq!(
            code.sub_code(),
            SubStatusCode::UncertainNotAllNodesAvailable
        );
        assert!(code.overflow());
        assert!(code.multi_value());
        assert!(code.extra_data());
        assert!(code.partial());
        assert_eq!(code.value_type(), StatusCodeValueType::Interpolated);

        code.validate().unwrap();
    }
}
