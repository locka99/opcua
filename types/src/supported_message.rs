//! Defines all messages, request or response that are supported by the
//! implementation. The SupportedMessage enumeration contains a value for
//! each of those messages enabling them to be passed around in an agnostic
//! fashion. 

use std::io::{Read, Write};

use encoding::*;
use node_id::NodeId;
use service_types::*;
use generated::*;

/// This macro helps avoid tedious repetition as new messages are added
/// The first form just handles the trailing comma after the last entry to save some pointless
/// editing when new messages are added to the list.
macro_rules! supported_messages {
    [ $( $x:ident, ) * ] => (supported_messages![ $( $x ),* ];);
    [ $( $x:ident ), * ] => {
        #[derive(Debug, PartialEq, Clone)]
        pub enum SupportedMessage {
            /// An invalid request / response of some form
            Invalid(ObjectId),
            /// Other messages
            $( $x($x), )*
        }

        impl BinaryEncoder <SupportedMessage> for SupportedMessage {
            fn byte_len(&self) -> usize {
                match *self {
                    SupportedMessage::Invalid(object_id) => {
                        panic!("Unsupported message {:?}", object_id);
                    },
                    $( SupportedMessage::$x(ref value) => value.byte_len(), )*
                }
            }

            fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
                match *self {
                    SupportedMessage::Invalid(object_id) => {
                        panic!("Unsupported message {:?}", object_id);
                    },
                    $( SupportedMessage::$x(ref value) => value.encode(stream), )*
                }
            }

            fn decode<S: Read>(_: &mut S) -> EncodingResult<Self> {
                // THIS WILL NOT DO ANYTHING
                panic!("Cannot decode a stream to a supported message type");
            }
        }

        impl SupportedMessage {
            pub fn node_id(&self) -> NodeId {
                match *self {
                    SupportedMessage::Invalid(object_id) => {
                        panic!("Unsupported message {:?}", object_id);
                    },
                    $( SupportedMessage::$x(ref value) => value.node_id(), )*
                }
            }
        }
    }
}

impl SupportedMessage {
    pub fn decode_by_object_id<S: Read>(stream: &mut S, object_id: ObjectId) -> EncodingResult<Self> {
        trace!("decoding object_id {:?}", object_id);
        let decoded_message = match object_id {
            ObjectId::ServiceFault_Encoding_DefaultBinary => {
                SupportedMessage::ServiceFault(ServiceFault::decode(stream)?)
            }
            ObjectId::OpenSecureChannelRequest_Encoding_DefaultBinary => {
                SupportedMessage::OpenSecureChannelRequest(OpenSecureChannelRequest::decode(stream)?)
            }
            ObjectId::OpenSecureChannelResponse_Encoding_DefaultBinary => {
                SupportedMessage::OpenSecureChannelResponse(OpenSecureChannelResponse::decode(stream)?)
            }
            ObjectId::CloseSecureChannelRequest_Encoding_DefaultBinary => {
                SupportedMessage::CloseSecureChannelRequest(CloseSecureChannelRequest::decode(stream)?)
            }
            ObjectId::CloseSecureChannelResponse_Encoding_DefaultBinary => {
                SupportedMessage::CloseSecureChannelResponse(CloseSecureChannelResponse::decode(stream)?)
            }
            ObjectId::FindServersRequest_Encoding_DefaultBinary => {
                SupportedMessage::FindServersRequest(FindServersRequest::decode(stream)?)
            }
            ObjectId::FindServersResponse_Encoding_DefaultBinary => {
                SupportedMessage::FindServersResponse(FindServersResponse::decode(stream)?)
            }
            ObjectId::GetEndpointsRequest_Encoding_DefaultBinary => {
                SupportedMessage::GetEndpointsRequest(GetEndpointsRequest::decode(stream)?)
            }
            ObjectId::GetEndpointsResponse_Encoding_DefaultBinary => {
                SupportedMessage::GetEndpointsResponse(GetEndpointsResponse::decode(stream)?)
            }
            ObjectId::CreateSessionRequest_Encoding_DefaultBinary => {
                SupportedMessage::CreateSessionRequest(CreateSessionRequest::decode(stream)?)
            }
            ObjectId::CreateSessionResponse_Encoding_DefaultBinary => {
                SupportedMessage::CreateSessionResponse(CreateSessionResponse::decode(stream)?)
            }
            ObjectId::CloseSessionRequest_Encoding_DefaultBinary => {
                SupportedMessage::CloseSessionRequest(CloseSessionRequest::decode(stream)?)
            }
            ObjectId::CloseSessionResponse_Encoding_DefaultBinary => {
                SupportedMessage::CloseSessionResponse(CloseSessionResponse::decode(stream)?)
            }
            ObjectId::ActivateSessionRequest_Encoding_DefaultBinary => {
                SupportedMessage::ActivateSessionRequest(ActivateSessionRequest::decode(stream)?)
            }
            ObjectId::ActivateSessionResponse_Encoding_DefaultBinary => {
                SupportedMessage::ActivateSessionResponse(ActivateSessionResponse::decode(stream)?)
            }
            ObjectId::BrowseRequest_Encoding_DefaultBinary => {
                SupportedMessage::BrowseRequest(BrowseRequest::decode(stream)?)
            }
            ObjectId::BrowseResponse_Encoding_DefaultBinary => {
                SupportedMessage::BrowseResponse(BrowseResponse::decode(stream)?)
            }
            ObjectId::BrowseNextRequest_Encoding_DefaultBinary => {
                SupportedMessage::BrowseNextRequest(BrowseNextRequest::decode(stream)?)
            }
            ObjectId::BrowseNextResponse_Encoding_DefaultBinary => {
                SupportedMessage::BrowseNextResponse(BrowseNextResponse::decode(stream)?)
            }
            ObjectId::CreateSubscriptionRequest_Encoding_DefaultBinary => {
                SupportedMessage::CreateSubscriptionRequest(CreateSubscriptionRequest::decode(stream)?)
            }
            ObjectId::CreateSubscriptionResponse_Encoding_DefaultBinary => {
                SupportedMessage::CreateSubscriptionResponse(CreateSubscriptionResponse::decode(stream)?)
            }
            ObjectId::ModifySubscriptionRequest_Encoding_DefaultBinary => {
                SupportedMessage::ModifySubscriptionRequest(ModifySubscriptionRequest::decode(stream)?)
            }
            ObjectId::ModifySubscriptionResponse_Encoding_DefaultBinary => {
                SupportedMessage::ModifySubscriptionResponse(ModifySubscriptionResponse::decode(stream)?)
            }
            ObjectId::DeleteSubscriptionsRequest_Encoding_DefaultBinary => {
                SupportedMessage::DeleteSubscriptionsRequest(DeleteSubscriptionsRequest::decode(stream)?)
            }
            ObjectId::DeleteSubscriptionsResponse_Encoding_DefaultBinary => {
                SupportedMessage::DeleteSubscriptionsResponse(DeleteSubscriptionsResponse::decode(stream)?)
            }
            ObjectId::SetPublishingModeRequest_Encoding_DefaultBinary => {
                SupportedMessage::SetPublishingModeRequest(SetPublishingModeRequest::decode(stream)?)
            }
            ObjectId::SetPublishingModeResponse_Encoding_DefaultBinary => {
                SupportedMessage::SetPublishingModeResponse(SetPublishingModeResponse::decode(stream)?)
            }
            ObjectId::PublishRequest_Encoding_DefaultBinary => {
                SupportedMessage::PublishRequest(PublishRequest::decode(stream)?)
            }
            ObjectId::PublishResponse_Encoding_DefaultBinary => {
                SupportedMessage::PublishResponse(PublishResponse::decode(stream)?)
            }
            ObjectId::RepublishRequest_Encoding_DefaultBinary => {
                SupportedMessage::RepublishRequest(RepublishRequest::decode(stream)?)
            }
            ObjectId::RepublishResponse_Encoding_DefaultBinary => {
                SupportedMessage::RepublishResponse(RepublishResponse::decode(stream)?)
            }
            ObjectId::ReadRequest_Encoding_DefaultBinary => {
                SupportedMessage::ReadRequest(ReadRequest::decode(stream)?)
            }
            ObjectId::ReadResponse_Encoding_DefaultBinary => {
                SupportedMessage::ReadResponse(ReadResponse::decode(stream)?)
            }
            ObjectId::WriteRequest_Encoding_DefaultBinary => {
                SupportedMessage::WriteRequest(WriteRequest::decode(stream)?)
            }
            ObjectId::WriteResponse_Encoding_DefaultBinary => {
                SupportedMessage::WriteResponse(WriteResponse::decode(stream)?)
            }
            ObjectId::TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary => {
                SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(TranslateBrowsePathsToNodeIdsRequest::decode(stream)?)
            }
            ObjectId::TranslateBrowsePathsToNodeIdsResponse_Encoding_DefaultBinary => {
                SupportedMessage::TranslateBrowsePathsToNodeIdsResponse(TranslateBrowsePathsToNodeIdsResponse::decode(stream)?)
            }
            ObjectId::CreateMonitoredItemsRequest_Encoding_DefaultBinary => {
                SupportedMessage::CreateMonitoredItemsRequest(CreateMonitoredItemsRequest::decode(stream)?)
            }
            ObjectId::CreateMonitoredItemsResponse_Encoding_DefaultBinary => {
                SupportedMessage::CreateMonitoredItemsResponse(CreateMonitoredItemsResponse::decode(stream)?)
            }
            ObjectId::ModifyMonitoredItemsRequest_Encoding_DefaultBinary => {
                SupportedMessage::ModifyMonitoredItemsRequest(ModifyMonitoredItemsRequest::decode(stream)?)
            }
            ObjectId::ModifyMonitoredItemsResponse_Encoding_DefaultBinary => {
                SupportedMessage::ModifyMonitoredItemsResponse(ModifyMonitoredItemsResponse::decode(stream)?)
            }
            ObjectId::DeleteMonitoredItemsRequest_Encoding_DefaultBinary => {
                SupportedMessage::DeleteMonitoredItemsRequest(DeleteMonitoredItemsRequest::decode(stream)?)
            }
            ObjectId::DeleteMonitoredItemsResponse_Encoding_DefaultBinary => {
                SupportedMessage::DeleteMonitoredItemsResponse(DeleteMonitoredItemsResponse::decode(stream)?)
            }
            _ => {
                debug!("decoding unsupported for object id {:?}", object_id);
                SupportedMessage::Invalid(object_id)
            }
        };
        Ok(decoded_message)
    }
}

// These are all the messages handled into and out of streams by the OPCUA server / client code
supported_messages![
    // A service fault, returned when the service failed
    ServiceFault,
    // Secure channel service
    OpenSecureChannelRequest,
    OpenSecureChannelResponse,
    CloseSecureChannelRequest,
    CloseSecureChannelResponse,
    // Discovery service
    GetEndpointsRequest,
    GetEndpointsResponse,
    FindServersRequest,
    FindServersResponse,
    // Session service
    CreateSessionRequest,
    CreateSessionResponse,
    CloseSessionRequest,
    CloseSessionResponse,
    ActivateSessionRequest,
    ActivateSessionResponse,
    // MonitoredItem service
    CreateMonitoredItemsRequest,
    CreateMonitoredItemsResponse,
    ModifyMonitoredItemsRequest,
    ModifyMonitoredItemsResponse,
    DeleteMonitoredItemsRequest,
    DeleteMonitoredItemsResponse,
    // Subscription service
    CreateSubscriptionRequest,
    CreateSubscriptionResponse,
    ModifySubscriptionRequest,
    ModifySubscriptionResponse,
    DeleteSubscriptionsRequest,
    DeleteSubscriptionsResponse,
    SetPublishingModeRequest,
    SetPublishingModeResponse,
    // View service
    BrowseRequest,
    BrowseResponse,
    BrowseNextRequest,
    BrowseNextResponse,
    PublishRequest,
    PublishResponse,
    RepublishRequest,
    RepublishResponse,
    TranslateBrowsePathsToNodeIdsRequest,
    TranslateBrowsePathsToNodeIdsResponse,
    // Attribute service
    ReadRequest,
    ReadResponse,
    WriteRequest,
    WriteResponse,
];
