// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! The TCP transport module handles receiving and sending of binary data in chunks, handshake,
//! session creation and dispatching of messages via message handler.
//!
//! Internally it uses tokio but the facade is mostly synchronous with the exception of publish
//! responses. i.e. the client is expected to call and wait for a response to their request.
//! Publish requests are sent based on the number of subscriptions and the responses / handling are
//! left to asynchronous event handlers.
use chrono::{self, Utc};
use futures::StreamExt;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    self,
    io::AsyncWriteExt,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::{interval_at, Duration, Instant},
};

use tokio::time::timeout;
use tokio_util::codec::FramedRead;

use crate::core::{
    comms::{
        message_writer::MessageWriter,
        secure_channel::SecureChannel,
        tcp_codec::{self, TcpCodec},
    },
    prelude::*,
};
use crate::crypto::CertificateStore;
use crate::sync::*;
use crate::types::status_code::StatusCode;

use crate::server::{
    address_space::types::AddressSpace,
    comms::{secure_channel_service::SecureChannelService, transport::*},
    services::message_handler::MessageHandler,
    session::SessionManager,
    state::ServerState,
    subscriptions::subscription::TickReason,
};

/// Messages that may be sent to the writer.
#[derive(Debug)]
enum Message {
    // Message for writer to quit right now.
    Quit,
    // A supported message with a request id
    Message(u32, SupportedMessage),
}

#[derive(Clone)]
pub struct MessageSender {
    sender: UnboundedSender<Message>,
}

impl MessageSender {
    pub fn send_quit(&self) {
        let _ = self.sender.send(Message::Quit);
    }

    pub fn send_message(&self, request_id: u32, message: SupportedMessage) {
        let _ = self.sender.send(Message::Message(request_id, message));
    }
}

struct ReadState {
    /// The associated connection
    pub transport: Arc<RwLock<TcpTransport>>,
    /// Sender of responses
    pub sender: UnboundedSender<Message>,
    /// Time to wait for a HELLO from the client
    pub hello_timeout: u32,
    /// Reader from which messages will be decoded
    pub reader: OwnedReadHalf,
}

struct WriteState {
    /// The associated connection
    pub transport: Arc<RwLock<TcpTransport>>,
    /// Secure channel state
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    /// Writing portion of socket
    pub writer: OwnedWriteHalf,
    /// Write buffer (protected since it might be accessed by publish response / event activity)
    pub send_buffer: Arc<Mutex<MessageWriter>>,
}

/// This is the thing that handles input and output for the open connection associated with the
/// session.
pub struct TcpTransport {
    /// Server state, address space etc.
    server_state: Arc<RwLock<ServerState>>,
    /// Transport id (for debugging)
    transport_id: NodeId,
    /// Secure channel state
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Address space
    address_space: Arc<RwLock<AddressSpace>>,
    /// The current transport state
    transport_state: TransportState,
    /// Client address
    client_address: Option<SocketAddr>,
    /// Secure channel handler
    secure_channel_service: SecureChannelService,
    /// Message handler
    message_handler: MessageHandler,
    /// Client protocol version set during HELLO
    client_protocol_version: u32,
    /// Last decoded sequence number
    last_received_sequence_number: u32,
    /// A message may consist of one or more chunks which are stored here until complete.
    pending_chunks: Vec<MessageChunk>,
    /// Sessions associated with this connection. Normally there would be one, but potentially there could be more
    session_manager: Arc<RwLock<SessionManager>>,
}

impl Transport for TcpTransport {
    fn state(&self) -> TransportState {
        self.transport_state
    }

    // Terminates the connection and the session
    fn finish(&mut self, status_code: StatusCode) {
        if !self.is_finished() {
            debug!(
                "Transport is being placed in finished state, code {}",
                status_code
            );
            self.transport_state = TransportState::Finished(status_code);
            // Clear sessions
            let mut session_manager = trace_write_lock!(self.session_manager);
            session_manager.clear(self.address_space.clone());
        } else {
            trace!("Transport is being placed in finished state when it is already finished, ignoring code {}", status_code);
        }
    }

    fn client_address(&self) -> Option<SocketAddr> {
        self.client_address
    }

    fn session_manager(&self) -> Arc<RwLock<SessionManager>> {
        self.session_manager.clone()
    }
}

impl TcpTransport {
    pub fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        server_state: Arc<RwLock<ServerState>>,
        address_space: Arc<RwLock<AddressSpace>>,
        session_manager: Arc<RwLock<SessionManager>>,
    ) -> TcpTransport {
        let decoding_options = {
            let server_state = trace_read_lock!(server_state);
            let config = trace_read_lock!(server_state.config);
            config.decoding_options()
        };
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(
            certificate_store.clone(),
            Role::Server,
            decoding_options,
        )));

        let message_handler = MessageHandler::new(
            secure_channel.clone(),
            certificate_store,
            server_state.clone(),
            session_manager.clone(),
            address_space.clone(),
        );

        let secure_channel_service = SecureChannelService::new();
        let transport_id = NodeId::next_numeric(0);

        TcpTransport {
            server_state,
            transport_id,
            address_space,
            transport_state: TransportState::New,
            client_address: None,
            message_handler,
            secure_channel,
            secure_channel_service,
            client_protocol_version: 0,
            last_received_sequence_number: 0,
            pending_chunks: Vec::with_capacity(2),
            session_manager,
        }
    }

    /// This is the entry point for the session. This function is asynchronous - it spawns tokio
    /// tasks to handle the session execution loop so this function will returns immediately.
    pub fn run(connection: Arc<RwLock<TcpTransport>>, socket: TcpStream, looping_interval_ms: f64) {
        info!(
            "Socket info:\n  Linger - {},\n  TTL - {}",
            if let Ok(v) = socket.linger() {
                match v {
                    Some(d) => format!("{}ms", d.as_millis()),
                    None => "No linger".to_string(),
                }
            } else {
                "No Linger (err)".to_string()
            },
            if let Ok(v) = socket.ttl() {
                format!("{}", v)
            } else {
                "No TTL".to_string()
            }
        );

        // Store the address of the client
        let (send_buffer_size, receive_buffer_size) = {
            let mut connection = trace_write_lock!(connection);
            connection.client_address = Some(socket.peer_addr().unwrap());
            connection.transport_state = TransportState::WaitingHello;
            let server_state = trace_read_lock!(connection.server_state);
            (
                server_state.send_buffer_size,
                server_state.receive_buffer_size,
            )
        };

        // Spawn the tasks we need to run
        tokio::spawn(Self::spawn_session_handler_task(
            connection,
            socket,
            looping_interval_ms,
            send_buffer_size,
            receive_buffer_size,
        ));
    }

    async fn write_bytes_task(mut write_state: WriteState) -> WriteState {
        let bytes_to_write = {
            let mut send_buffer = trace_lock!(write_state.send_buffer);
            send_buffer.bytes_to_write()
        };
        let result = write_state.writer.write_all(&bytes_to_write).await;
        if let Err(err) = result {
            error!("Write IO error {:?}", err);
            let mut transport = trace_write_lock!(write_state.transport);
            transport.finish(StatusCode::BadCommunicationError);
        }
        write_state
    }

    async fn spawn_session_handler_task(
        transport: Arc<RwLock<TcpTransport>>,
        socket: TcpStream,
        looping_interval_ms: f64,
        send_buffer_size: usize,
        receive_buffer_size: usize,
    ) {
        // The reader task will send responses, the writer task will receive responses
        let (tx, rx) = unbounded_channel();
        let send_buffer = Arc::new(Mutex::new(MessageWriter::new(send_buffer_size, 0, 0)));

        let (reader, writer) = socket.into_split();
        let (hello_timeout, secure_channel) = {
            let transport = trace_read_lock!(transport);
            let server_state = trace_read_lock!(transport.server_state);
            let server_config = trace_read_lock!(server_state.config);
            info!(
                "Session transport {} started at {}",
                transport.transport_id,
                Utc::now()
            );
            (
                server_config.tcp_config.hello_timeout,
                transport.secure_channel.clone(),
            )
        };

        let read_state = ReadState {
            reader,
            hello_timeout,
            transport: transport.clone(),
            sender: tx.clone(),
        };

        // Spawn all the tasks that monitor the session - the subscriptions, finished state,
        // reading and writing.
        let final_status = tokio::select! {
            _ = Self::spawn_subscriptions_task(transport.clone(), tx.clone(), looping_interval_ms) => {
                log::trace!("Closing connection because the subscription task failed");
                Ok(())
            }
            status = Self::spawn_writing_loop_task(writer, rx, secure_channel, transport.clone(), send_buffer) => {
                log::trace!("Closing connection after the write task ended");
                status
            }
            status = Self::spawn_reading_loop_task(read_state, send_buffer_size, receive_buffer_size) => {
                log::trace!("Closing connection after the read task ended");
                status
            }
        }.err().unwrap_or(StatusCode::Good);

        log::info!("Closing connection with status {}", final_status);
        // Both the read and write halves of the tcp stream are dropped at this point,
        // and the connection is closed
        let mut transport = trace_write_lock!(transport);
        transport.finish(final_status);
    }

    fn make_debug_task_id(component: &str, transport: Arc<RwLock<TcpTransport>>) -> String {
        let transport = trace_read_lock!(transport);
        format!("{}/{}", transport.transport_id, component)
    }

    /// Spawns the writing loop task. The writing loop takes messages to send off of a queue
    /// and sends them to the stream.
    async fn spawn_writing_loop_task(
        writer: OwnedWriteHalf,
        mut receiver: UnboundedReceiver<Message>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        transport: Arc<RwLock<TcpTransport>>,
        send_buffer: Arc<Mutex<MessageWriter>>,
    ) -> Result<(), StatusCode> {
        let mut write_state = WriteState {
            transport: transport.clone(),
            writer,
            send_buffer,
            secure_channel,
        };

        // The writing task waits for messages that are to be sent
        while let Some(message) = receiver.recv().await {
            trace!("Writing loop received message: {:?}", message);
            let (request_id, response) = match message {
                Message::Quit => {
                    debug!("Server writer received a quit so it will quit");
                    return Ok(());
                }
                Message::Message(request_id, response) => {
                    if let SupportedMessage::Invalid(_) = response {
                        error!("Writer terminating - received an invalid message");
                        return Err(StatusCode::BadCommunicationError);
                    }
                    (request_id, response)
                }
            };

            {
                let secure_channel = trace_read_lock!(write_state.secure_channel);
                let mut send_buffer = trace_lock!(write_state.send_buffer);
                match response {
                    SupportedMessage::AcknowledgeMessage(ack) => {
                        send_buffer.write_ack(&ack)?;
                    }
                    msg => {
                        send_buffer.write(request_id, msg, &secure_channel)?;
                    }
                }
            }
            write_state = Self::write_bytes_task(write_state).await;
        }
        Ok(())
    }

    async fn wait_for_hello(
        reader: &mut FramedRead<OwnedReadHalf, TcpCodec>,
        hello_timeout: u32,
    ) -> Result<HelloMessage, StatusCode> {
        let duration = Duration::from_secs(u64::from(hello_timeout));
        match timeout(duration, reader.next()).await {
            // We process a timeout(stream_element(tcp_message))
            Err(_timeout) => {
                warn!("Session has been waiting for a hello for more than the timeout period and will now close");
                Err(StatusCode::BadTimeout)
            }
            Ok(Some(Ok(tcp_codec::Message::Hello(hello)))) => Ok(hello),
            Ok(Some(Ok(bad_msg))) => {
                log::error!("Expected a hello message, got {:?} instead", bad_msg);
                Err(StatusCode::BadCommunicationError)
            }
            Ok(Some(Err(communication_err))) => {
                error!(
                    "Communication error while waiting for Hello message: {}",
                    communication_err
                );
                Err(StatusCode::BadCommunicationError)
            }
            Ok(None) => Err(StatusCode::BadConnectionClosed),
        }
    }

    /// Spawns the reading loop where a reader task continuously reads messages, chunks from the
    /// input and process them. The reading task will terminate upon error.
    async fn spawn_reading_loop_task(
        read_state: ReadState,
        send_buffer_size: usize,
        receive_buffer_size: usize,
    ) -> Result<(), StatusCode> {
        let (transport, mut sender) = { (read_state.transport.clone(), read_state.sender.clone()) };

        let decoding_options = {
            let transport = trace_read_lock!(transport);
            let secure_channel = trace_read_lock!(transport.secure_channel);
            secure_channel.decoding_options()
        };

        // The reader reads frames from the codec, which are messages
        let mut framed_read =
            FramedRead::new(read_state.reader, TcpCodec::new(decoding_options.clone()));

        let hello = Self::wait_for_hello(&mut framed_read, read_state.hello_timeout).await?;
        trace_write_lock!(transport).process_hello(
            hello,
            &mut sender,
            &decoding_options,
            send_buffer_size,
            receive_buffer_size,
        )?;

        while let Some(next_msg) = framed_read.next().await {
            match next_msg {
                Ok(tcp_codec::Message::Chunk(chunk)) => {
                    log::trace!("Received message chunk: {:?}", chunk);
                    let mut transport = trace_write_lock!(transport);
                    transport.process_chunk(chunk, &mut sender)?
                }
                Ok(unexpected) => {
                    log::error!("Received unexpected message: {:?}", unexpected);
                    return Err(StatusCode::BadCommunicationError);
                }
                Err(err) => {
                    error!("Server reader error {:?}", err);
                    return Err(StatusCode::BadCommunicationError);
                }
            }
        }
        Ok(())
    }

    /// Start the subscription timer to service subscriptions
    async fn spawn_subscriptions_task(
        transport: Arc<RwLock<TcpTransport>>,
        sender: UnboundedSender<Message>,
        looping_interval_ms: f64,
    ) -> Result<(), StatusCode> {
        // Subscription events are passed sent from the monitor task to the receiver
        debug!("Starting subscription timer loop");

        // Create the monitoring timer - this monitors for publish requests and ticks the subscriptions
        let interval_duration = Duration::from_millis(looping_interval_ms as u64);

        // Creates a repeating interval future that checks subscriptions.
        let mut timer = interval_at(Instant::now(), interval_duration);

        loop {
            timer.tick().await;

            let transport = trace_read_lock!(transport);
            let session_manager = trace_read_lock!(transport.session_manager);
            let address_space = trace_read_lock!(transport.address_space);

            for (_node_id, session) in session_manager.sessions.iter() {
                let mut session = trace_write_lock!(session);
                let now = Utc::now();

                // Request queue might contain stale publish requests
                session.expire_stale_publish_requests(&now);

                // Process subscriptions
                session.tick_subscriptions(&now, &address_space, TickReason::TickTimerFired)?;

                // Check if there are publish responses to send for transmission
                if let Some(publish_responses) =
                    session.subscriptions_mut().take_publish_responses()
                {
                    for publish_response in publish_responses {
                        trace!(
                            "<-- Sending a Publish Response{}, {:?}",
                            publish_response.request_id,
                            &publish_response.response
                        );
                        // Messages will be sent by the writing task
                        sender
                            .send(Message::Message(
                                publish_response.request_id,
                                publish_response.response,
                            ))
                            .map_err(|e| {
                                error!("Unable to send publish response to writer task: {}", e);
                                StatusCode::BadUnexpectedError
                            })?;
                    }
                }
            }
        }
    }

    /// Test if the connection should abort
    pub fn is_server_abort(&self) -> bool {
        let server_state = trace_read_lock!(self.server_state);
        server_state.is_abort()
    }

    fn process_hello(
        &mut self,
        hello: HelloMessage,
        sender: &mut UnboundedSender<Message>,
        decoding_options: &DecodingOptions,
        send_buffer_size: usize,
        receive_buffer_size: usize,
    ) -> std::result::Result<(), StatusCode> {
        let server_protocol_version = 0;
        let endpoints = {
            let server_state = trace_read_lock!(self.server_state);
            server_state.endpoints(&hello.endpoint_url, &None)
        }
        .unwrap();

        trace!("Server received HELLO {:?}", hello);
        if !hello.is_endpoint_url_valid(&endpoints) {
            error!("HELLO endpoint url is invalid");
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }
        if !hello.is_valid_buffer_sizes() {
            error!("HELLO buffer sizes are invalid");
            return Err(StatusCode::BadCommunicationError);
        }

        // Validate protocol version
        if hello.protocol_version > server_protocol_version {
            return Err(StatusCode::BadProtocolVersionUnsupported);
        }

        let client_protocol_version = hello.protocol_version;

        // Send acknowledge
        let mut acknowledge = AcknowledgeMessage {
            message_header: MessageHeader::new(MessageType::Acknowledge),
            protocol_version: server_protocol_version,
            receive_buffer_size: receive_buffer_size as u32,
            send_buffer_size: send_buffer_size as u32,
            max_message_size: decoding_options.max_message_size as u32,
            max_chunk_count: decoding_options.max_chunk_count as u32,
        };
        acknowledge.message_header.message_size = acknowledge.byte_len() as u32;
        let acknowledge: SupportedMessage = acknowledge.into();

        // New state
        self.transport_state = TransportState::ProcessMessages;
        self.client_protocol_version = client_protocol_version;

        debug!("Sending ACK");
        let _ = sender.send(Message::Message(0, acknowledge));
        Ok(())
    }

    fn turn_received_chunks_into_message(
        &mut self,
        chunks: &[MessageChunk],
    ) -> std::result::Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let secure_channel = trace_read_lock!(self.secure_channel);
        self.last_received_sequence_number = Chunker::validate_chunks(
            self.last_received_sequence_number + 1,
            &secure_channel,
            chunks,
        )?;
        // Now decode
        Chunker::decode(chunks, &secure_channel, None)
    }

    fn process_chunk(
        &mut self,
        chunk: MessageChunk,
        sender: &mut UnboundedSender<Message>,
    ) -> std::result::Result<(), StatusCode> {
        let decoding_options = {
            let secure_channel = trace_read_lock!(self.secure_channel);
            secure_channel.decoding_options()
        };

        let message_header = chunk.message_header(&decoding_options)?;

        if message_header.is_final == MessageIsFinalType::FinalError {
            info!("Discarding chunks as after receiving one marked as final error");
            self.pending_chunks.clear();
            Ok(())
        } else {
            // Decrypt / verify chunk if necessary
            let chunk = {
                let mut secure_channel = trace_write_lock!(self.secure_channel);
                secure_channel.verify_and_remove_security(&chunk.data)?
            };

            // TODO check how many chunks are pending, produce error and drop connection if it exceeds
            //  supported chunk limit

            // Put the chunk on the list
            self.pending_chunks.push(chunk);

            // The final chunk will trigger turning all pending chunks into a request
            if message_header.is_final == MessageIsFinalType::Final {
                self.process_final_chunk(&message_header, sender)
            } else {
                Ok(())
            }
        }
    }

    fn process_final_chunk(
        &mut self,
        message_header: &MessageChunkHeader,
        sender: &mut UnboundedSender<Message>,
    ) -> Result<(), StatusCode> {
        // Drain pending chunks and turn them into a message
        let chunks: Vec<MessageChunk> = self.pending_chunks.drain(..).collect();
        let chunk_info = {
            let secure_channel = trace_read_lock!(self.secure_channel);
            chunks[0].chunk_info(&secure_channel)?
        };

        // Handle the request, and then send the response back to the caller
        let request = self.turn_received_chunks_into_message(&chunks)?;
        let request_id = chunk_info.sequence_header.request_id;

        let sender = MessageSender {
            sender: sender.clone(),
        };

        match message_header.message_type {
            MessageChunkType::OpenSecureChannel => self.process_open_secure_channel(
                request_id,
                &request,
                &chunk_info.security_header,
                &sender,
            ),
            MessageChunkType::CloseSecureChannel => {
                self.process_close_secure_channel(request_id, &request, &sender)
            }
            MessageChunkType::Message => self.process_message(request_id, &request, &sender),
        }
    }

    fn process_open_secure_channel(
        &mut self,
        request_id: u32,
        request: &SupportedMessage,
        security_header: &SecurityHeader,
        sender: &MessageSender,
    ) -> Result<(), StatusCode> {
        let mut secure_channel = trace_write_lock!(self.secure_channel);
        let response = self.secure_channel_service.open_secure_channel(
            &mut secure_channel,
            security_header,
            self.client_protocol_version,
            request,
        )?;
        let _ = sender.send_message(request_id, response);
        Ok(())
    }

    fn process_close_secure_channel(
        &mut self,
        request_id: u32,
        request: &SupportedMessage,
        sender: &MessageSender,
    ) -> Result<(), StatusCode> {
        let response = self.secure_channel_service.close_secure_channel(request)?;
        let _ = sender.send_message(request_id, response);
        Ok(())
    }

    fn process_message(
        &mut self,
        request_id: u32,
        request: &SupportedMessage,
        sender: &MessageSender,
    ) -> Result<(), StatusCode> {
        let _ = self
            .message_handler
            .handle_message(request_id, request, sender)?;
        Ok(())
    }
}
