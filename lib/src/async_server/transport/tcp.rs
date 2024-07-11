use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    async_server::info::ServerInfo,
    core::comms::{
        buffer::SendBuffer,
        message_chunk_info::ChunkInfo,
        secure_channel::SecureChannel,
        tcp_codec::{Message, TcpCodec},
        tcp_types::HelloMessage,
    },
    server::prelude::{
        AcknowledgeMessage, Chunker, DecodingOptions, ErrorMessage, MessageChunk,
        MessageIsFinalType, StatusCode, SupportedMessage,
    },
};
use futures::StreamExt;
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_util::codec::FramedRead;

pub(crate) struct TcpTransport {
    read: FramedRead<ReadHalf<TcpStream>, TcpCodec>,
    write: WriteHalf<TcpStream>,
    send_buffer: SendBuffer,
    state: TransportState,
    pending_chunks: Vec<MessageChunk>,
    /// Client protocol version set during HELLO
    pub(crate) client_protocol_version: u32,
    /// Last decoded sequence number
    last_received_sequence_number: u32,
    info: Arc<ServerInfo>,
}

enum TransportState {
    WaitingForHello(Instant),
    Running,
    Closing,
}

#[derive(Debug, Clone)]
pub(crate) struct TransportConfig {
    pub send_buffer_size: usize,
    pub max_message_size: usize,
    pub max_chunk_count: usize,
    pub hello_timeout: Duration,
}

#[derive(Debug)]
pub(crate) struct Request {
    pub message: SupportedMessage,
    pub chunk_info: ChunkInfo,
    pub request_id: u32,
}

#[derive(Debug)]
pub enum TransportPollResult {
    OutgoingMessageSent,
    IncomingChunk,
    IncomingMessage(Request),
    IncomingHello,
    Error(StatusCode),
    Closed,
}

fn min_zero_infinite(server: u32, client: u32) -> u32 {
    if client == 0 {
        server
    } else if server == 0 {
        client
    } else {
        client.min(server)
    }
}

impl TcpTransport {
    pub fn new(
        stream: TcpStream,
        config: TransportConfig,
        decoding_options: DecodingOptions,
        info: Arc<ServerInfo>,
    ) -> Self {
        let (read, write) = tokio::io::split(stream);
        let read = FramedRead::new(read, TcpCodec::new(decoding_options));

        Self {
            read,
            write,
            send_buffer: SendBuffer::new(
                config.send_buffer_size,
                config.max_message_size,
                config.max_chunk_count,
            ),
            state: TransportState::WaitingForHello(Instant::now() + config.hello_timeout),
            pending_chunks: Vec::new(),
            last_received_sequence_number: 0,
            client_protocol_version: 0,
            info,
        }
    }

    /// Set the transport state to closing, once the final message is sent
    /// the connection will be closed.
    pub fn set_closing(&mut self) {
        self.state = TransportState::Closing;
    }

    pub fn is_closing(&self) -> bool {
        matches!(self.state, TransportState::Closing)
    }

    pub fn enqueue_error(&mut self, message: ErrorMessage) {
        self.send_buffer.write_error(message);
    }

    pub fn enqueue_message_for_send(
        &mut self,
        channel: &mut SecureChannel,
        message: SupportedMessage,
        request_id: u32,
    ) -> Result<(), StatusCode> {
        self.send_buffer.write(request_id, message, channel)?;
        Ok(())
    }

    fn process_hello(
        &mut self,
        channel: &mut SecureChannel,
        hello: HelloMessage,
    ) -> Result<(), StatusCode> {
        let endpoints = self.info.endpoints(&hello.endpoint_url, &None);

        if !endpoints.is_some_and(|e| hello.is_endpoint_url_valid(&e)) {
            error!("HELLO endpoint url is invalid");
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }
        if !hello.is_valid_buffer_sizes() {
            error!("HELLO buffer sizes are invalid");
            return Err(StatusCode::BadCommunicationError);
        }

        let server_protocol_version = 0;
        // Validate protocol version
        if hello.protocol_version > server_protocol_version {
            return Err(StatusCode::BadProtocolVersionUnsupported);
        }

        self.client_protocol_version = hello.protocol_version;

        let decoding_options = channel.decoding_options();

        // Send acknowledge
        let acknowledge = AcknowledgeMessage::new(
            server_protocol_version,
            hello.send_buffer_size,
            (self.send_buffer.send_buffer_size as u32).min(hello.receive_buffer_size),
            min_zero_infinite(
                decoding_options.max_message_size as u32,
                hello.max_message_size,
            ),
            min_zero_infinite(
                decoding_options.max_chunk_count as u32,
                hello.max_chunk_count,
            ),
        );
        self.send_buffer.revise(
            acknowledge.send_buffer_size as usize,
            acknowledge.max_message_size as usize,
            acknowledge.max_chunk_count as usize,
        );
        self.send_buffer.write_ack(acknowledge);

        self.state = TransportState::Running;

        Ok(())
    }

    pub async fn poll(&mut self, channel: &mut SecureChannel) -> TransportPollResult {
        // If we're waiting for hello, just do that. We're not sending anything until
        // we get it.
        if let TransportState::WaitingForHello(deadline) = &self.state {
            return tokio::select! {
                _ = tokio::time::sleep_until((*deadline).into()) => {
                    TransportPollResult::Error(StatusCode::BadTimeout)
                }
                r = self.wait_for_hello() => {
                    match r {
                        Ok(h) => {
                            match self.process_hello(channel, h) {
                                Ok(()) => TransportPollResult::IncomingHello,
                                Err(e) => TransportPollResult::Error(e)
                            }
                        }
                        Err(e) => {
                            TransportPollResult::Error(e)
                        }
                    }
                }
            };
        }

        // Either we've got something in the send buffer, which we can send,
        // or we're waiting for more outgoing messages.
        // We won't wait for outgoing messages while sending, since that
        // could cause the send buffer to fill up.

        // If there's nothing in the send buffer, but there are chunks available,
        // write them to the send buffer before proceeding.
        if self.send_buffer.should_encode_chunks() {
            if let Err(e) = self.send_buffer.encode_next_chunk(channel) {
                return TransportPollResult::Error(e);
            }
        }

        // If there is something in the send buffer, write to the stream.
        // If not, wait for outgoing messages.
        // Either way, listen to incoming messages while we do this.
        if self.send_buffer.can_read() {
            tokio::select! {
                r = self.send_buffer.read_into_async(&mut self.write) => {
                    if let Err(e) = r {
                        error!("write bytes task failed: {}", e);
                        return TransportPollResult::Closed;
                    }
                    TransportPollResult::OutgoingMessageSent
                }
                incoming = self.read.next() => {
                    self.handle_incoming_message(incoming, channel)
                }
            }
        } else {
            if self.is_closing() {
                return TransportPollResult::Closed;
            }
            let incoming = self.read.next().await;
            self.handle_incoming_message(incoming, channel)
        }
    }

    async fn wait_for_hello(&mut self) -> Result<HelloMessage, StatusCode> {
        match self.read.next().await {
            Some(Ok(Message::Hello(hello))) => Ok(hello),
            Some(Ok(bad_msg)) => {
                log::error!("Expected a hello message, got {:?} instead", bad_msg);
                Err(StatusCode::BadCommunicationError)
            }
            Some(Err(communication_err)) => {
                error!(
                    "Communication error while waiting for Hello message: {}",
                    communication_err
                );
                Err(StatusCode::BadCommunicationError)
            }
            None => Err(StatusCode::BadConnectionClosed),
        }
    }

    fn handle_incoming_message(
        &mut self,
        incoming: Option<Result<Message, std::io::Error>>,
        channel: &mut SecureChannel,
    ) -> TransportPollResult {
        let Some(incoming) = incoming else {
            return TransportPollResult::Closed;
        };
        match incoming {
            Ok(message) => match self.process_message(message, channel) {
                Ok(None) => TransportPollResult::IncomingChunk,
                Ok(Some(message)) => {
                    self.pending_chunks.clear();
                    TransportPollResult::IncomingMessage(message)
                }
                Err(e) => {
                    self.pending_chunks.clear();
                    TransportPollResult::Error(e)
                }
            },
            Err(err) => {
                error!("Error reading from stream {:?}", err);
                TransportPollResult::Error(StatusCode::BadConnectionClosed)
            }
        }
    }

    fn process_message(
        &mut self,
        message: Message,
        channel: &mut SecureChannel,
    ) -> Result<Option<Request>, StatusCode> {
        match message {
            Message::Chunk(chunk) => {
                let header = chunk.message_header(&channel.decoding_options())?;

                if header.is_final == MessageIsFinalType::FinalError {
                    self.pending_chunks.clear();
                    Ok(None)
                } else {
                    let chunk = channel.verify_and_remove_security(&chunk.data)?;

                    if self.pending_chunks.len() == self.send_buffer.max_chunk_count {
                        return Err(StatusCode::BadEncodingLimitsExceeded);
                    }
                    self.pending_chunks.push(chunk);

                    if header.is_final == MessageIsFinalType::Intermediate {
                        return Ok(None);
                    }

                    let chunk_info = self.pending_chunks[0].chunk_info(channel)?;

                    self.last_received_sequence_number = Chunker::validate_chunks(
                        self.last_received_sequence_number + 1,
                        channel,
                        &self.pending_chunks,
                    )?;

                    let request = Chunker::decode(&self.pending_chunks, channel, None)?;
                    Ok(Some(Request {
                        request_id: chunk_info.sequence_header.request_id,
                        chunk_info,
                        message: request,
                    }))
                }
            }
            unexpected => {
                error!("Received unexpected message: {:?}", unexpected);
                Err(StatusCode::BadUnexpectedError)
            }
        }
    }
}
