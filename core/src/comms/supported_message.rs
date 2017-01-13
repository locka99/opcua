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
            // Can't do this without concat_idents!()
            /* pub fn decode_by_object_id<S: Read>(object_id: &ObjectId, stream: &mut S) -> Result {
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
