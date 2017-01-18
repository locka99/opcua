use std::io::{Read, Write, Result};

use types::*;
use services::*;
use services::secure_channel::*;
use services::discovery::*;
use comms::*;

// This macro helps avoid tedious repetition as new messages are added

macro_rules! supported_messages {
    [ $( $x:ident ), * ] => {
        #[derive(Debug, PartialEq)]
        pub enum SupportedMessage {
            Invalid(ObjectId),
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

            fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
                match *self {
                    SupportedMessage::Invalid(object_id) => {
                        panic!("Unsupported message {:?}", object_id);
                    },
                    $( SupportedMessage::$x(ref value) => value.encode(stream), )*
                }
            }

            fn decode<S: Read>(stream: &mut S) -> Result<SupportedMessage> {
                // THIS WILL NOT DO ANYTHING
                panic!("Cannot decode a stream to a supported message type");
            }
        }

        impl SupportedMessage {
            /* // Can't do this without concat_idents!()
                match *object_id {
                    $( ObjectId::$x_Encoding_DefaultBinary => { $x::decode(s) }, )*
                    _ => {
                        Err(Error::new(ErrorKind::Other, "Message object id is not supported"))
                    }
                }
            } */

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
    pub fn decode_by_object_id<S: Read>(stream: &mut S, object_id: ObjectId) -> Result<SupportedMessage> {
        debug!("decoding object_id {:?}", object_id);
        let decoded_message = match object_id {
            ObjectId::OpenSecureChannelRequest_Encoding_DefaultBinary => {
                SupportedMessage::OpenSecureChannelRequest(OpenSecureChannelRequest::decode(stream)?)
            },
            ObjectId::OpenSecureChannelResponse_Encoding_DefaultBinary => {
                SupportedMessage::OpenSecureChannelResponse(OpenSecureChannelResponse::decode(stream)?)
            },
            ObjectId::CloseSecureChannelRequest_Encoding_DefaultBinary => {
                SupportedMessage::CloseSecureChannelRequest(CloseSecureChannelRequest::decode(stream)?)
            },
            ObjectId::CloseSecureChannelResponse_Encoding_DefaultBinary => {
                SupportedMessage::CloseSecureChannelResponse(CloseSecureChannelResponse::decode(stream)?)
            },
            ObjectId::GetEndpointsRequest_Encoding_DefaultBinary => {
                SupportedMessage::GetEndpointsRequest(GetEndpointsRequest::decode(stream)?)
            },
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
    // Secure channel service
    OpenSecureChannelRequest,
    OpenSecureChannelResponse,
    CloseSecureChannelRequest,
    CloseSecureChannelResponse,
    // Discovery service
    GetEndpointsRequest,
    GetEndpointsResponse
];
