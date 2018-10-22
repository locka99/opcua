use std::io::{Read, Write};

use encoding::*;
use status_codes::StatusCode;

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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        // All enums are Int32
        let user_token_type = read_i32(stream)?;
        match user_token_type {
            0 => Ok(UserTokenType::Anonymous),
            1 => Ok(UserTokenType::Username),
            2 => Ok(UserTokenType::Certificate),
            3 => Ok(UserTokenType::IssuedToken),
            _ => {
                error!("Don't know what user token type {} is", user_token_type);
                Err(StatusCode::BadUnexpectedError)
            }
        }
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
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

#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(TimestampsToReturn::Source),
            1 => Ok(TimestampsToReturn::Server),
            2 => Ok(TimestampsToReturn::Both),
            3 => Ok(TimestampsToReturn::Neither),
            _ => {
                error!("Don't know what TimestampsToReturn value {} is", value);
                Err(StatusCode::BadTimestampsToReturnInvalid)
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        if let Some(result) = NodeClass::from_i32(value) {
            Ok(result)
        } else {
            error!("Don't know what node class {} is", value);
            Err(StatusCode::BadNodeClassInvalid)
        }
    }
}

impl NodeClass {
    pub fn from_i32(value: i32) -> Option<NodeClass> {
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


#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(DataChangeTrigger::Status),
            1 => Ok(DataChangeTrigger::StatusValue),
            2 => Ok(DataChangeTrigger::StatusValueTimestamp),
            _ => {
                error!("Don't know what data change trigger {} is", value);
                Err(StatusCode::BadUnexpectedError)
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
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
                Err(StatusCode::BadFilterOperatorInvalid)
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        // All enums are Int32
        let value = read_i32(stream)?;
        match value {
            0 => Ok(BrowseDirection::Forward),
            1 => Ok(BrowseDirection::Inverse),
            2 => Ok(BrowseDirection::Both),
            _ => {
                error!("Don't know what browse direction {} is", value);
                Err(StatusCode::BadBrowseDirectionInvalid)
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
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
        write_i32(stream, *self as i32)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
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
                Err(StatusCode::BadUnexpectedError)
            }
        }
    }
}
