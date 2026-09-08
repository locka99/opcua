use crate::core::comms::tcp_types::{
    MESSAGE_HEADER_LEN,
    CHUNK_MESSAGE, OPEN_SECURE_CHANNEL_MESSAGE, CLOSE_SECURE_CHANNEL_MESSAGE,
    HELLO_MESSAGE, ACKNOWLEDGE_MESSAGE, ERROR_MESSAGE, REVERSE_HELLO_MESSAGE,
    CHUNK_FINAL, CHUNK_INTERMEDIATE, CHUNK_FINAL_ERROR};
use crate::prelude::{MESSAGE_CHUNK_HEADER_SIZE,
    AsymmetricSecurityHeader, MessageChunkHeader, MessageChunkType, MessageIsFinalType,
    SequenceHeader, StatusCode, SymmetricSecurityHeader};
use crate::puffin::query::OpcuaQueryMatcher;
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::{
    AcknowledgeMessage, ActivateSessionRequest, ActivateSessionResponse, BinaryEncoder, CloseSecureChannelRequest, CloseSecureChannelResponse, CloseSessionRequest, CloseSessionResponse, CreateSessionRequest, CreateSessionResponse, ErrorMessage, GetEndpointsRequest, GetEndpointsResponse, HelloMessage, Identifier, MessageHeader, MessageType, NodeId, ObjectId, OpenSecureChannelRequest, OpenSecureChannelResponse, ReadRequest, ReadResponse, ReverseHelloMessage, ServiceFault, UAString};

use extractable_macro::Extractable;
use paste::paste;

use puffin::codec;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::error::Error;
use puffin::protocol::{
    Extractable,
    OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight};
use puffin::trace::{Knowledge, Source};

use std::collections::VecDeque;
use std::io;
use std::io::Read;
use std::str;

pub const MAX_WIRE_SIZE: usize = 40960;

// Neither MessageChunkType, nor MessageIsFinalType is directly encoded,
// so we define here a simplified ChunkType that is extractable:
#[derive(Clone, Copy, Debug, Deserialize, Eq, Extractable, Hash, PartialEq, Serialize)]
#[extractable(OpcuaProtocolTypes)]
pub enum ChunkType {
    Open,
    Intermediate,
    Final,
    FinalError,
    Close
}

impl ChunkType{
    pub fn to_message_chunk_type(self) -> MessageChunkType {
        match self {
            ChunkType::Open  => MessageChunkType::OpenSecureChannel,
            ChunkType::Close => MessageChunkType::CloseSecureChannel,
            _                => MessageChunkType::Message
        }
    }
    pub fn to_is_final(self) -> MessageIsFinalType {
        match self {
            ChunkType::Intermediate => MessageIsFinalType::Intermediate,
            ChunkType::FinalError   => MessageIsFinalType::FinalError,
            _                       => MessageIsFinalType::Final
        }
    }
}

impl CodecP for ChunkType{
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ChunkType::Open  => bytes.extend_from_slice(OPEN_SECURE_CHANNEL_MESSAGE),
            ChunkType::Close => bytes.extend_from_slice(CLOSE_SECURE_CHANNEL_MESSAGE),
            _                => bytes.extend_from_slice(CHUNK_MESSAGE)
        }
        match self {
            ChunkType::Intermediate => bytes.push(CHUNK_INTERMEDIATE),
            ChunkType::FinalError   => bytes.push(CHUNK_FINAL_ERROR),
            _                       => bytes.push(CHUNK_FINAL)
        }
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        let mut head = [0u8; 4];
        rd.read_exact(&mut head)?;
        match &head[0..3] {
            OPEN_SECURE_CHANNEL_MESSAGE => *self = ChunkType::Open,
            CLOSE_SECURE_CHANNEL_MESSAGE => *self = ChunkType::Close,
            CHUNK_MESSAGE =>
                match head[3] {
                    CHUNK_INTERMEDIATE => *self = ChunkType::Intermediate,
                    CHUNK_FINAL        => *self = ChunkType::Final,
                    CHUNK_FINAL_ERROR  => *self = ChunkType::FinalError,
                    _ => return Err(Error::Codec("Unexpected message head!".to_string()))
                },
                _ => return Err(Error::Codec("Unexpected message head!".to_string()))
            }
        Ok(())
    }
}


/// The enum type [`crate::core::comms::tcp_codec::Message`] defines
/// all UA Connection Protocol messages and chunks of UA Secure Channel messages
/// that are Signed and/or Encrypted.
/// However chunks make no distinction between:
///  - OpensecureChannel messages that are encrypted
///  - normal messages that are only protected by a MAC
/// Therefore to avoid modifying the original code, we redefine a similar Message
/// structure here that is more suited to the fuzzer.
/// This Message structure is used as [`OpaqueProtocolMessage`].
/// These messages are opaque in the sense that chunks may be encrypted.
/// Yet, knowledge can be learned from them if they are not encrypted.
/// The [`OpaqueProtocolMessageFlight`] is used for exchanges with the PUT.

#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub enum UaMessage {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Reverse(ReverseHelloMessage),
    Open(MessageChunkHeader, AsymmetricSecurityHeader, EncryptedBody),
    // without #[extractable_ignore] Trying to extract a dummy type: u8 (repeated many times)
    // with    #[extractable_ignore] EncryptedBody: error Unable to find variable (Some(Agent(AgentName(0))), 1)[None]/EncryptedBody!
    Chunk(MessageChunkHeader, MessageBody),
}

impl Codec for UaMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            UaMessage::Hello(ref h) => CodecP::encode(h, bytes),
            UaMessage::Acknowledge(ref a) => CodecP::encode(a, bytes),
            UaMessage::Error(ref e) => CodecP::encode(e, bytes),
            UaMessage::Reverse(ref r) => CodecP::encode(r, bytes),
            UaMessage::Open(ref header, ref security, ref body) => {
                CodecP::encode(header, bytes);
                CodecP::encode(security, bytes);
                CodecP::encode(body, bytes);
            }
            UaMessage::Chunk(ref header, ref body ) => {
                CodecP::encode(header, bytes);
                CodecP::encode(body, bytes);
            }
        }
    }

    fn read(rd: &mut Reader) -> Option<Self> {
        if let Some(head) = rd.peek(3) {
        match head {
            HELLO_MESSAGE => {
                let mut h = HelloMessage::new(&"",0,0,0,0);
                if let Ok(()) = HelloMessage::read(&mut h, rd) {Some(UaMessage::Hello(h))}
                else {None}
            }
            ACKNOWLEDGE_MESSAGE => {
                let mut a = AcknowledgeMessage {
                    message_header: MessageHeader::new(MessageType::Acknowledge),
                    protocol_version: 0,
                    receive_buffer_size: 0,
                    send_buffer_size: 0,
                    max_message_size: 0,
                    max_chunk_count: 0
                };
                if let Ok(()) = AcknowledgeMessage::read(&mut a, rd) {Some(UaMessage::Acknowledge(a))}
                else {None}
            }
            REVERSE_HELLO_MESSAGE => {
                let mut r = ReverseHelloMessage{
                    message_header: MessageHeader::new(MessageType::Reverse),
                    server_uri: UAString::null(),
                    endpoint_url: UAString::null()
                };
                if let Ok(()) = ReverseHelloMessage::read(&mut r, rd) {Some(UaMessage::Reverse(r))}
                else {None}
            }
            ERROR_MESSAGE => {
                let mut e = ErrorMessage{
                    message_header: MessageHeader::new(MessageType::Error),
                    error: 0,
                    reason: UAString::null()
                };
                if let Ok(()) = ErrorMessage::read(&mut e, rd) {Some(UaMessage::Error(e))}
                else {None}
            }
            OPEN_SECURE_CHANNEL_MESSAGE => {
                let mut header = MessageChunkHeader::default();
                if let Err(_) = MessageChunkHeader::read(&mut header, rd) {return None}
                let mut size = (header.message_size as usize) - MESSAGE_CHUNK_HEADER_SIZE;
                let mut security = AsymmetricSecurityHeader::none();
                if let Err(_) = AsymmetricSecurityHeader::read(&mut security, rd) {return None}
                size = size - security.byte_len();
                if size < 1 { return None }
                let mut body = vec![0u8; size];
                match rd.read_exact(&mut body) {
                    Ok(()) => Some(
                        UaMessage::Open(header, security, EncryptedBody {cipher_text: body})),
                    Err(_) => None
                }
            }
            CLOSE_SECURE_CHANNEL_MESSAGE | CHUNK_MESSAGE => {
                let mut header = MessageChunkHeader::default();
                if let Ok(()) = MessageChunkHeader::read(&mut header, rd) {
                    let size = (header.message_size as usize) - MESSAGE_CHUNK_HEADER_SIZE;
                    if size < 1 { return None }
                    let mut body = MessageBody::default();
                    if let Ok(()) = CodecP::read(&mut body, rd) {
                        Some(UaMessage::Chunk(header, body))
                    } else {None}
                } else {None}
            }
            _ => None
        }
        } else {None}
    }
}

impl codec::VecCodecWoSize for UaMessage {}

impl OpaqueProtocolMessage<OpcuaProtocolTypes> for UaMessage {
    fn debug(&self, _info: &str) {
        panic!("Not implemented yet.");
    }
}

// /!\ a ServiceMessage may be encoded as a MessageFlight and not
//     only as a single message.
impl ProtocolMessage<OpcuaProtocolTypes, UaMessage> for UaMessage {
    fn create_opaque(&self) -> UaMessage {
        self.clone()
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented yet.");
    }
}


#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct Message {
    pub connexion_id: u8,
    pub message: UaMessage
}

impl Codec for Message {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CodecP::encode(&self.connexion_id, bytes);
        CodecP::encode(&self.message, bytes);
    }

    fn read(rd: &mut Reader) -> Option<Self> {
        return None
    }
}

impl codec::VecCodecWoSize for Message {}


impl OpaqueProtocolMessage<OpcuaProtocolTypes> for Message {
    fn debug(&self, _info: &str) {
        panic!("Not implemented yet.");
    }
}

// /!\ a ServiceMessage may be encoded as a MessageFlight and not
//     only as a single message.
impl ProtocolMessage<OpcuaProtocolTypes, Message> for Message {
    fn create_opaque(&self) -> Message {
        self.clone()
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented yet.");
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct EncryptedBody {
    pub cipher_text: Vec<u8>
}

impl Default for EncryptedBody {
    fn default() -> EncryptedBody {
        EncryptedBody{
            cipher_text: vec![]
        }
    }
}

impl CodecP for EncryptedBody {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.cipher_text);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        self.cipher_text.read(rd)?;
        Ok(())
    }
}

/**
The enum type [`crate::core::supported_message::SupportedMessage`] defines all [`ProtocolMessage`],
i.e. all possible OPC UA service requests before security is applied to them,
and all possible responses after security has been removed from them.
/!\ We use here a simplified enum type, called a [`ServiceMessage`]
*/
macro_rules! service_message_enum {
    [ $( $x:ident, ) * ] => (service_message_enum![ $( $x ),* ];);
    [ $( $x:ident ), * ] => {
        #[derive(Debug, PartialEq, Clone, Extractable)]
        #[extractable(OpcuaProtocolTypes)]
        pub enum ServiceMessage {
            None,
            ServiceFault(ServiceFault),
            $( $x($x), )*
        }

        impl Codec for ServiceMessage {
            fn encode(&self, bytes: &mut Vec<u8>) {
                match *self {
                  $(ServiceMessage::$x(ref r) => {
                        paste! {
                            let id = NodeId {
                                namespace: 0,
                                identifier: Identifier::from( ObjectId::[<$x _Encoding_DefaultBinary>] as u32)
                            };
                            CodecP::encode(&id, bytes);
                        }
                        CodecP::encode(r, bytes)
                    }, )*
                    ServiceMessage::ServiceFault(ref r) => {
                        let id = NodeId {
                            namespace: 0,
                            identifier: Identifier::from(ObjectId::ServiceFault_Encoding_DefaultBinary as u32)
                        };
                        CodecP::encode(&id, bytes);
                        CodecP::encode(r, bytes)
                    },
                    ServiceMessage::None => ()
                }
            }

            fn read(rd: &mut Reader) -> Option<Self> {
                let mut node_id = NodeId::null();
                if let Ok(()) = CodecP::read(&mut node_id, rd) {
                    if let Identifier::Numeric(id) = node_id.identifier {
                        if let Ok(obj_id) = ObjectId::try_from(id) {
                            paste! {
                            match obj_id {
                                $(ObjectId::[<$x _Encoding_DefaultBinary>] => {
                                    let mut r = $x::default();
                                    if let Ok(()) = CodecP::read(&mut r, rd) {
                                        return Some(ServiceMessage::$x(r))
                                    }
                                }, )*
                                ObjectId::ServiceFault_Encoding_DefaultBinary => {
                                    let mut service_fault = ServiceFault::default();
                                    if let Ok(()) = CodecP::read(&mut service_fault, rd) {
                                        log::warn!("Service Fault: {}", service_fault.response_header.service_result);
                                        return Some(ServiceMessage::ServiceFault(service_fault))
                                    }
                                },
                                _ => return Some(ServiceMessage::None),
                            }}
                        }
                    }
                };
                Some(ServiceMessage::None)
            }

        }
}}

service_message_enum![
    OpenSecureChannelRequest,
    OpenSecureChannelResponse,
    CloseSecureChannelRequest,
    CloseSecureChannelResponse,
    CreateSessionRequest,
    CreateSessionResponse,
    ActivateSessionRequest,
    ActivateSessionResponse,
    CloseSessionRequest,
    CloseSessionResponse,
    ReadRequest,
    ReadResponse,
    GetEndpointsRequest,
    GetEndpointsResponse,
];


#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct DecryptedBody {
    pub sequence_header: SequenceHeader,
    pub request: ServiceMessage,
    pub signature: Vec<u8>
}

impl Default for DecryptedBody {
    fn default() -> DecryptedBody {
        DecryptedBody{
            sequence_header: SequenceHeader {
                sequence_number: 0,
                request_id: 0
            },
            request: ServiceMessage::None,
            signature: vec![]
        }
    }
}

impl CodecP for DecryptedBody {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CodecP::encode(&self.sequence_header, bytes);
        CodecP::encode(&self.request, bytes);
        bytes.extend_from_slice(&self.signature);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        self.sequence_header.read(rd)?;
        self.request.read(rd)?;
        self.signature.read(rd)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MessageBody {
    pub security_header: SymmetricSecurityHeader,
    pub sequence_header: SequenceHeader,
    pub request: ServiceMessage,
    pub mac: Vec<u8>
}

impl Default for MessageBody {
    fn default() -> MessageBody {
        MessageBody{
            security_header: SymmetricSecurityHeader {token_id: 0},
            sequence_header: SequenceHeader {
                sequence_number: 0,
                request_id: 0
            },
            request: ServiceMessage::None,
            mac: vec![]
        }
    }
}

impl CodecP for MessageBody {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CodecP::encode(&self.security_header, bytes);
        CodecP::encode(&self.sequence_header, bytes);
        CodecP::encode(&self.request, bytes);
        bytes.extend_from_slice(&self.mac);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        self.security_header.read(rd)?;
        self.sequence_header.read(rd)?;
        self.request.read(rd)?;
        self.mac.read(rd)?;
        Ok(())
    }
}

impl Extractable<OpcuaProtocolTypes> for MessageBody {
    fn extract_knowledge<'a> (
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, OpcuaProtocolTypes>>,
        _: Option<OpcuaQueryMatcher>,
        source: &'a Source
    ) -> Result<(), Error> {
        let matcher = match &self.request {
            ServiceMessage::CreateSessionResponse(_) => Some(OpcuaQueryMatcher::CreateSessionResponse),
            ServiceMessage::ActivateSessionResponse(_) => Some(OpcuaQueryMatcher::ActivateSessionResponse),
            _ => None
        };
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self
        });
        self.security_header.extract_knowledge(knowledges, matcher, source)?;
        self.sequence_header.extract_knowledge(knowledges, matcher, source)?;
        self.request.extract_knowledge(knowledges, matcher, source)?;
        self.mac.extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}


/// The [`MessageDeframer`] is used to extract from a buffer of bytes ([u8]) a [`MessageFlight`].
// Maybe, some of the code of the MessageDeframer should be moved into Puffin,
// and the trait should only implement "try_deframe_one"?
pub struct MessageDeframer {
    /// Complete chunks ready to be deciphered.
    pub frames: VecDeque<UaMessage>,
    /// A fixed-size buffer containing a bunch of OPC UA messages, or only a part of one.
    buffer: Box<[u8; MAX_WIRE_SIZE]>,
    /// What part of buffer is used.
    used: usize,
}

impl Default for MessageDeframer {
    fn default() -> Self {
        Self::new()
    }
}

enum BufferContent {
    /// this enum gives the status of the prefix found in MessageDeframer.buffer:
    /// it may contain either an invalid message, a partial message or a valid chunk.
    Invalid,
    Partial,
    Valid
}

impl MessageDeframer {
    pub fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            buffer: Box::new([0u8; MAX_WIRE_SIZE]),
            used: 0,
        }
    }

    /// Read some bytes from `rd`, and add them to our internal buffer.
    /// Then if our internal buffer contains full messages, decode them all.
    pub fn read(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        // Try to do the largest reads possible.  Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        debug_assert!(self.used <= MAX_WIRE_SIZE);
        let new_bytes = rd.read(&mut self.buffer[self.used..])?;
        self.used += new_bytes;

        if new_bytes > 0 { loop {
            match self.try_deframe_one() {
                BufferContent::Invalid => {
                    self.used = 0;
                    return Err(io::Error::other("Invalid UA TCP message!"));
                }
                BufferContent::Valid => continue,
                BufferContent::Partial => break,
            }
        }}
        Ok(new_bytes)
    }

    /// Returns true if we have messages for the caller to process,
    /// either whole chunks in our output queue or a partial chunk in our buffer.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || self.used > 0
    }

    /// Try to decode an UA TCP or UA SC message off the front of the buffer,
    /// and store it in "frames". We just read the MessageHeader.
    fn try_deframe_one(&mut self) -> BufferContent {
        //log::warn!("Try deframe one UA TCP message (buffer size: {})", self.used);
        if self.used < MESSAGE_HEADER_LEN { return BufferContent::Partial }
        let mut message_start = [0u8; 3];
        message_start.clone_from_slice(&self.buffer[0..3]);
        let mut rd = codec::Reader::init(&self.buffer[0..MESSAGE_HEADER_LEN]);
        let mut message_header = MessageHeader::new(MessageType::Hello);
        let result = MessageHeader::read(&mut message_header, &mut rd);
        if let Err(_) = result {
            return BufferContent::Invalid
        }
        let message_size = message_header.message_size as usize;
        if message_size > self.used {
            return BufferContent::Partial
        }
        let message_debug = format!("{}, {} bytes",
            core::str::from_utf8(&message_start).unwrap(), message_size);
        let mut rd = codec::Reader::init(&self.buffer[0..message_size]);
        if let Some(msg) = Codec::read(&mut rd) {
            if let UaMessage::Error(ref error_message) = msg {
                log::warn!("UA TCP {}: {:?}", message_debug,
                    StatusCode::from_bits_retain(error_message.error).name());
            } else {
                log::warn!("UA TCP {}", message_debug);
            };
            let result = {
                if let UaMessage::Chunk(ref head,_) = msg {
                    if head.is_final == MessageIsFinalType::Intermediate {
                        BufferContent::Partial
                    } else {
                        BufferContent::Valid
                    }
                } else {
                    BufferContent::Valid
                }
            };
            self.frames.push_back(msg);
            self.consume(message_size);
            return result
        } else {
            log::error!("UA TCP {}: invalid message!", message_debug);
            return BufferContent::Invalid
        }
    }

    fn consume(&mut self, size: usize) {
        if size < self.used {
            self.buffer.copy_within(size..self.used, 0);
            self.used -= size;
        } else if size == self.used {
            self.used = 0;
        }
    }

}

impl ProtocolMessageDeframer<OpcuaProtocolTypes> for MessageDeframer {
    type OpaqueProtocolMessage = UaMessage;

    fn pop_frame(&mut self) -> Option<UaMessage> {
        self.frames.pop_front()
    }

    fn read(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl ProtocolMessageFlight<OpcuaProtocolTypes, Message, Message, MessageFlight>
    for MessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

/// All chunks of a complete TCP message are grouped into an [`OpaqueProtocolMessageFlight`]
/// that can be exchanged with the target (PUT)
#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct MessageFlight {
    messages: Vec<Message>,
}

impl MessageFlight {

    pub fn merge(&mut self, with: Self) {
        for message in with.messages {
            self.messages.push(message)
        }
    }

}

impl OpaqueProtocolMessageFlight<OpcuaProtocolTypes, Message> for MessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl From<Message> for MessageFlight {
    fn from(value: Message) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl Codec for MessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            Codec::encode(msg, bytes)
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let mut deframer = MessageDeframer::new();
        let mut flight = <MessageFlight as OpaqueProtocolMessageFlight<OpcuaProtocolTypes, Message>>::new();

        /* /!\ Only the first byte contains the connexion id */
        let connexion_id: u8 = Codec::read(reader).unwrap();
        if deframer.read(&mut reader.rest()).is_ok() {
            while let Some(message) = deframer.pop_frame() {
                OpaqueProtocolMessageFlight::push(&mut flight, Message{connexion_id, message});
            }
            Some(flight)
        } else {
            None
        }
    }
}


// Non-recursing dummy Comparable (opts OPC UA out of differential knowledge comparison)
crate::dummy_comparable!(ChunkType);
crate::dummy_comparable!(UaMessage);
crate::dummy_comparable!(Message);
crate::dummy_comparable!(EncryptedBody);
crate::dummy_comparable!(ServiceMessage);
crate::dummy_comparable!(DecryptedBody);
crate::dummy_comparable!(MessageFlight);
crate::dummy_comparable!(MessageBody);
crate::dummy_comparable!(crate::puffin::signature::fn_impl::SecretKey);
crate::dummy_comparable!(crate::puffin::signature::fn_impl::Certificate);

// Non-recursing dummy PartialEq: satisfies the flight-extraction bound without propagating
// PartialEq into UaMessage and every message variant. OPC UA does not rely on message equality.
impl PartialEq for Message {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}
