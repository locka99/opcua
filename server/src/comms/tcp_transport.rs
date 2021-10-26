// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! The TCP transport module handles receiving and sending of binary data in chunks, handshake,
//! session creation and dispatching of messages via message handler.
//!
//! Internally it uses tokio but the facade is mostly synchronous with the exception of publish
//! responses. i.e. the client is expected to call and wait for a response to their request.
//! Publish requests are sent based on the number of subscriptions and the responses / handling are
//! left to asynchronous event handlers.
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
};

use chrono::{self, Utc};
use futures::StreamExt;
use tokio::{
    self,
    io::AsyncWriteExt,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::{interval_at, Duration, Instant},
};
use tokio_util::codec::FramedRead;

use opcua_core::{
    comms::{
        message_writer::MessageWriter,
        secure_channel::SecureChannel,
        tcp_codec::{self, TcpCodec},
        tcp_types::*,
    },
    prelude::*,
    RUNTIME,
};
use opcua_crypto::CertificateStore;
use opcua_types::status_code::StatusCode;

use crate::{
    address_space::types::AddressSpace,
    comms::{secure_channel_service::SecureChannelService, transport::*},
    constants,
    services::message_handler::MessageHandler,
    session::SessionManager,
    state::ServerState,
    subscriptions::{subscription::TickReason, PublishResponseEntry},
};

// TODO these need to go, and use session settings
const RECEIVE_BUFFER_SIZE: usize = std::u16::MAX as usize;
const SEND_BUFFER_SIZE: usize = std::u16::MAX as usize;
const MAX_MESSAGE_SIZE: usize = std::u16::MAX as usize;
const MAX_CHUNK_COUNT: usize = 1;

fn connection_finished(connection: Arc<RwLock<dyn Transport>>, id: &str) -> bool {
    trace!("{}", id);
    let connection = trace_read_lock_unwrap!(connection);
    let finished = connection.is_finished();
    if finished {
        info!("{} connection finished", id);
    }
    finished
}

/// Messages that may be sent to the writer.
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
    /// Bytes read in buffer
    pub bytes_read: usize,
    /// Sender of responses
    pub sender: UnboundedSender<Message>,
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
            let mut session_manager = trace_write_lock_unwrap!(self.session_manager);
            session_manager.clear();
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
    ) -> TcpTransport {
        let session_manager = Arc::new(RwLock::new(SessionManager::default()));

        let decoding_options = {
            let server_state = trace_read_lock_unwrap!(server_state);
            let config = trace_read_lock_unwrap!(server_state.config);
            config.decoding_options()
        };
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(
            certificate_store.clone(),
            Role::Server,
            decoding_options,
        )));

        let message_handler = MessageHandler::new(
            secure_channel.clone(),
            certificate_store.clone(),
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
        {
            let mut connection = trace_write_lock_unwrap!(connection);
            connection.client_address = Some(socket.peer_addr().unwrap());
            connection.transport_state = TransportState::WaitingHello;
        }

        // Spawn the tasks we need to run
        Self::spawn_session_handler_task(connection, socket, looping_interval_ms);
    }

    async fn write_bytes_task(mut write_state: WriteState) -> WriteState {
        let bytes_to_write = {
            let mut send_buffer = trace_lock_unwrap!(write_state.send_buffer);
            send_buffer.bytes_to_write()
        };
        let result = write_state.writer.write_all(&bytes_to_write).await;
        if let Err(err) = result {
            error!("Write IO error {:?}", err);
            let mut transport = trace_write_lock_unwrap!(write_state.transport);
            transport.finish(StatusCode::BadCommunicationError);
        }
        write_state
    }

    fn spawn_session_handler_task(
        transport: Arc<RwLock<TcpTransport>>,
        socket: TcpStream,
        looping_interval_ms: f64,
    ) {
        let session_start_time = Utc::now();
        info!("Session started {}", session_start_time);

        // These should really come from the session
        let (send_buffer_size, receive_buffer_size) = (SEND_BUFFER_SIZE, RECEIVE_BUFFER_SIZE);

        // The reader task will send responses, the writer task will receive responses
        let (tx, rx) = unbounded_channel();
        let send_buffer = Arc::new(Mutex::new(MessageWriter::new(send_buffer_size, 0, 0)));

        let (reader, writer) = socket.into_split();
        let secure_channel = {
            let transport = trace_read_lock_unwrap!(transport);
            transport.secure_channel.clone()
        };

        // This is set to true when the session is finished.
        let finished_flag = Arc::new(RwLock::new(false));

        // Spawn the hello timeout task, this timer waits for a hello and will abort
        // session if it doesn't occur before the timeout.
        Self::spawn_hello_timeout_task(transport.clone(), tx.clone(), session_start_time);

        // Spawn all the tasks that monitor the session - the subscriptions, finished state,
        // reading and writing.
        Self::spawn_subscriptions_task(transport.clone(), tx.clone(), looping_interval_ms);
        Self::spawn_finished_monitor_task(transport.clone(), finished_flag.clone());
        Self::spawn_writing_loop_task(writer, rx, secure_channel, transport.clone(), send_buffer);
        Self::spawn_reading_loop_task(reader, finished_flag, transport, tx, receive_buffer_size);
    }

    fn make_debug_task_id(component: &str, transport: Arc<RwLock<TcpTransport>>) -> String {
        let transport = trace_read_lock_unwrap!(transport);
        format!("{}/{}", transport.transport_id, component)
    }

    /// Spawns the finished monitor task. This checks for the session to be in a finished
    /// state and ensures the session is placed into a finished state once the transport
    /// aborts or finishes.
    fn spawn_finished_monitor_task(
        transport: Arc<RwLock<TcpTransport>>,
        finished_flag: Arc<RwLock<bool>>,
    ) {
        tokio::spawn(async move {
            let id = Self::make_debug_task_id("finished_monitor_task", transport.clone());
            register_runtime_component!(&id);

            let mut timer = interval_at(
                Instant::now(),
                Duration::from_millis(constants::HELLO_TIMEOUT_POLL_MS),
            );
            loop {
                trace!("finished_monitor_task.loop");
                let (is_server_abort, is_finished) = {
                    let transport = trace_read_lock_unwrap!(transport);
                    (transport.is_server_abort(), transport.is_finished())
                };
                if !is_finished && is_server_abort {
                    let mut finished_flag = trace_write_lock_unwrap!(finished_flag);
                    *finished_flag = true;
                }
                if is_server_abort || is_finished {
                    break;
                }
                timer.tick().await;
            }
            info!("Finished monitor task is finished");
            deregister_runtime_component!(&id);
        });
    }

    /// Spawns the writing loop task. The writing loop takes messages to send off of a queue
    /// and sends them to the stream.
    fn spawn_writing_loop_task(
        writer: OwnedWriteHalf,
        mut receiver: UnboundedReceiver<Message>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        transport: Arc<RwLock<TcpTransport>>,
        send_buffer: Arc<Mutex<MessageWriter>>,
    ) {
        let mut write_state = WriteState {
            transport: transport.clone(),
            writer,
            send_buffer,
            secure_channel,
        };

        // The writing task waits for messages that are to be sent
        tokio::spawn(async move {
            let id = Self::make_debug_task_id("server_writing_loop_task", transport.clone());
            register_runtime_component!(&id);
            loop {
                let msg = receiver.recv().await;
                if msg.is_none() {
                    continue;
                }
                let message = msg.unwrap();
                trace!("write_looping_task.take_while");
                let (request_id, response) = match message {
                    Message::Quit => {
                        debug!("Server writer received a quit so it will quit");
                        let _ = write_state.writer.shutdown().await;
                        break;
                    }
                    Message::Message(request_id, response) => {
                        let mut transport = trace_write_lock_unwrap!(write_state.transport);
                        if let SupportedMessage::Invalid(_) = response {
                            error!("Writer terminating - received an invalid message");
                            transport.finish(StatusCode::BadCommunicationError);
                            break;
                        } else if transport.is_server_abort() {
                            info!("Writer terminating - communication error (abort)");
                            transport.finish(StatusCode::BadCommunicationError);
                            break;
                        } else if transport.is_finished() {
                            info!("Writer terminating - transport is finished");
                            break;
                        }
                        (request_id, response)
                    }
                };

                {
                    let secure_channel = trace_read_lock_unwrap!(write_state.secure_channel);
                    let mut send_buffer = trace_lock_unwrap!(write_state.send_buffer);
                    match response {
                        SupportedMessage::AcknowledgeMessage(ack) => {
                            let _ = send_buffer.write_ack(&ack);
                        }
                        msg => {
                            let _ = send_buffer.write(request_id, msg, &secure_channel);
                        }
                    }
                }

                write_state = Self::write_bytes_task(write_state).await;

                let finished = {
                    let transport = trace_read_lock_unwrap!(write_state.transport);
                    transport.is_finished()
                };
                if finished {
                    info!("Writer session status is terminating");
                    let _ = write_state.writer.shutdown().await;
                    break;
                }
            }

            // Mark as finished in the case that something else didn't
            let mut transport = trace_write_lock_unwrap!(write_state.transport);
            if !transport.is_finished() {
                error!("Write bytes task is in error and is finishing the transport");
                transport.finish(StatusCode::BadCommunicationError);
            } else {
                error!("Write bytes task is in error");
            };
            trace!("Write bytes task finished");
            deregister_runtime_component!(&id);
        });
    }

    /// Creates the framed read task / future. This will read chunks from the
    /// reader and process them.
    async fn framed_read_task(
        reader: OwnedReadHalf,
        finished_flag: Arc<RwLock<bool>>,
        read_state: ReadState,
    ) {
        let (transport, mut sender) = { (read_state.transport.clone(), read_state.sender.clone()) };

        let decoding_options = {
            let transport = trace_read_lock_unwrap!(transport);
            let secure_channel = trace_read_lock_unwrap!(transport.secure_channel);
            secure_channel.decoding_options()
        };

        // The reader reads frames from the codec, which are messages
        let mut framed_read =
            FramedRead::new(reader, TcpCodec::new(finished_flag, decoding_options));
        loop {
            if connection_finished(transport.clone(), "Server reader loop") {
                break;
            }

            let next_msg = framed_read.next().await;
            if next_msg.is_none() {
                continue;
            }

            let transport_state = {
                let transport = trace_read_lock_unwrap!(transport);
                transport.transport_state
            };

            match next_msg.unwrap() {
                Ok(message) => {
                    let mut session_status_code = StatusCode::Good;
                    match transport_state {
                        TransportState::WaitingHello => {
                            if let tcp_codec::Message::Hello(hello) = message {
                                let mut transport = trace_write_lock_unwrap!(transport);
                                if let Err(err) = transport.process_hello(hello, &mut sender) {
                                    session_status_code = err;
                                }
                            } else {
                                session_status_code = StatusCode::BadCommunicationError;
                            }
                        }
                        TransportState::ProcessMessages => {
                            if let tcp_codec::Message::Chunk(chunk) = message {
                                let mut transport = trace_write_lock_unwrap!(transport);
                                if let Err(err) = transport.process_chunk(chunk, &mut sender) {
                                    session_status_code = err;
                                }
                            } else {
                                session_status_code = StatusCode::BadCommunicationError;
                            }
                        }
                        _ => {
                            error!("Server reader unknown session state, aborting");
                            session_status_code = StatusCode::BadUnexpectedError;
                        }
                    }
                    // Update the session status and drop out
                    if session_status_code.is_bad() {
                        error!(
                            "Server reader session status is {} so finishing",
                            session_status_code
                        );
                        let mut transport = trace_write_lock_unwrap!(transport);
                        transport.finish(session_status_code);
                        break;
                    }
                }
                Err(err) => {
                    // Mark as finished just in case something else didn't
                    let mut transport = trace_write_lock_unwrap!(transport);
                    if !transport.is_finished() {
                        error!(
                            "Server reader is in error and is finishing the transport. {:?}",
                            err
                        );
                        transport.finish(StatusCode::BadCommunicationError);
                    } else {
                        error!("Server reader error {:?}", err);
                    }
                    break;
                }
            }
        }
        let mut transport = trace_write_lock_unwrap!(transport);
        if !transport.is_finished() {
            error!("Server reader stopped and is finishing the transport.");
            transport.finish(StatusCode::Good);
        }
    }

    /// Spawns the reading loop where a reader task continuously reads messages, chunks from the
    /// input and process them. The reading task will terminate upon error.
    fn spawn_reading_loop_task(
        reader: OwnedReadHalf,
        finished_flag: Arc<RwLock<bool>>,
        transport: Arc<RwLock<TcpTransport>>,
        sender: UnboundedSender<Message>,
        receive_buffer_size: usize,
    ) {
        // Connection state is maintained for looping through each task
        let read_state = ReadState {
            transport: transport.clone(),
            bytes_read: 0,
            sender: sender.clone(),
        };

        tokio::spawn(async move {
            let id = Self::make_debug_task_id("server_reading_loop_task", transport.clone());
            register_runtime_component!(&id);

            Self::framed_read_task(reader, finished_flag.clone(), read_state).await;

            // Some handlers might wish to send their message and terminate, in which case this is
            // done here.
            {
                // Terminate may have been set somewhere
                let mut transport = trace_write_lock_unwrap!(transport);
                let sessions_terminated = {
                    let session_manager = transport.session_manager();
                    let session_manager = trace_read_lock_unwrap!(session_manager);
                    session_manager.sessions_terminated()
                };
                if sessions_terminated {
                    transport.finish(StatusCode::BadConnectionClosed);
                }
            };
            info!("Read loop is finished");
            debug!("Server reader task is sending a quit to the server writer");
            let _ = sender.send(Message::Quit);
            deregister_runtime_component!(&id);
        });
    }

    /// Makes the tokio task that looks for a hello timeout event, i.e. the connection is opened
    /// but no hello is received and we need to drop the session
    fn spawn_hello_timeout_task(
        transport: Arc<RwLock<TcpTransport>>,
        sender: UnboundedSender<Message>,
        session_start_time: chrono::DateTime<Utc>,
    ) {
        let hello_timeout = {
            let hello_timeout = {
                let transport = trace_read_lock_unwrap!(transport);
                let server_state = trace_read_lock_unwrap!(transport.server_state);
                let server_config = trace_read_lock_unwrap!(server_state.config);
                server_config.tcp_config.hello_timeout as i64
            };
            chrono::Duration::seconds(hello_timeout)
        };

        // Clone the connection so the take_while predicate has its own instance
        tokio::spawn(async move {
            let id = Self::make_debug_task_id("hello_timeout_task", transport.clone());
            register_runtime_component!(&id);

            let mut timer = interval_at(
                Instant::now(),
                Duration::from_millis(constants::HELLO_TIMEOUT_POLL_MS),
            );
            loop {
                trace!("hello_timeout_task.take_while");
                // Terminates when session is no longer waiting for a hello or connection is done
                {
                    let transport = trace_read_lock_unwrap!(transport);
                    let waiting_for_hello = !transport.has_received_hello();
                    if !waiting_for_hello {
                        debug!("Hello timeout timer no longer required & is going to stop");
                        break;
                    }
                }

                timer.tick().await;

                // Check if the session has waited in the hello state for more than the hello timeout period
                let transport_state = {
                    let transport = trace_read_lock_unwrap!(transport);
                    transport.state()
                };
                if transport_state == TransportState::WaitingHello {
                    // Check if the time elapsed since the session started exceeds the hello timeout
                    let now = Utc::now();
                    let duration_since_start = now.signed_duration_since(session_start_time);
                    if duration_since_start.num_milliseconds() > hello_timeout.num_milliseconds() {
                        // Check if the session has waited in the hello state for more than the hello timeout period
                        info!("Session has been waiting for a hello for more than the timeout period and will now close");
                        let mut transport = trace_write_lock_unwrap!(transport);
                        transport.finish(StatusCode::BadTimeout);

                        // Diagnostics
                        let server_state = trace_read_lock_unwrap!(transport.server_state);
                        let mut diagnostics = trace_write_lock_unwrap!(server_state.diagnostics);
                        diagnostics.on_session_timeout();

                        // Make sure sockets go down
                        let _ = sender.send(Message::Quit);
                    }
                }
            }
            info!("Hello timeout is finished");
            deregister_runtime_component!(&id);
        });
    }

    /// Start the subscription timer to service subscriptions
    fn spawn_subscriptions_task(
        transport: Arc<RwLock<TcpTransport>>,
        sender: UnboundedSender<Message>,
        looping_interval_ms: f64,
    ) {
        /// Subscription events are passed sent from the monitor task to the receiver
        #[derive(Clone, Debug)]
        enum SubscriptionEvent {
            PublishResponses(VecDeque<PublishResponseEntry>),
        }
        debug!("spawn_subscriptions_task ");

        // Make a channel for subscriptions
        let (subscription_tx, mut subscription_rx) = mpsc::unbounded_channel();

        // Create the monitoring timer - this monitors for publish requests and ticks the subscriptions
        {
            // Clone the connection so the take_while predicate has its own instance
            let interval_duration = Duration::from_millis(looping_interval_ms as u64);

            let transport = transport.clone();
            tokio::spawn(async move {
                let id = Self::make_debug_task_id("subscriptions_task_monitor", transport.clone());
                register_runtime_component!(&id);

                // Creates a repeating interval future that checks subscriptions.
                let mut timer = interval_at(Instant::now(), interval_duration);

                loop {
                    if connection_finished(transport.clone(), "subscriptions_task loop") {
                        break;
                    }

                    timer.tick().await;

                    let transport = trace_read_lock_unwrap!(transport);
                    let session_manager = trace_read_lock_unwrap!(transport.session_manager);
                    let address_space = trace_read_lock_unwrap!(transport.address_space);

                    session_manager.sessions.iter().for_each(|s| {
                        let mut session = trace_write_lock_unwrap!(s.1);
                        let now = Utc::now();

                        // Request queue might contain stale publish requests
                        session.expire_stale_publish_requests(&now);

                        // Process subscriptions
                        {
                            let _ = session.tick_subscriptions(
                                &now,
                                &address_space,
                                TickReason::TickTimerFired,
                            );
                        }

                        // Check if there are publish responses to send for transmission
                        if let Some(publish_responses) =
                            session.subscriptions_mut().take_publish_responses()
                        {
                            match subscription_tx
                                .send(SubscriptionEvent::PublishResponses(publish_responses))
                            {
                                Err(error) => {
                                    error!("Cannot send publish responses, err = {}", error)
                                }
                                Ok(_) => trace!("Sent publish responses to session task"),
                            }
                        }
                    });
                }
                info!("Subscription monitor is finished");
                deregister_runtime_component!(&id);
            });
        }

        // Create the receiving task - this takes publish responses and sends them back to the client
        {
            tokio::spawn(async move {
                let id = Self::make_debug_task_id("subscriptions_task_receiver", transport.clone());
                register_runtime_component!(&id);

                loop {
                    if connection_finished(transport.clone(), "subscriptions_task loop") {
                        break;
                    }
                    // Process publish response events
                    if let Some(subscription_event) = subscription_rx.recv().await {
                        match subscription_event {
                            SubscriptionEvent::PublishResponses(publish_responses) => {
                                trace!(
                                    "Got {} PublishResponse messages to send",
                                    publish_responses.len()
                                );
                                for publish_response in publish_responses {
                                    trace!(
                                        "<-- Sending a Publish Response{}, {:?}",
                                        publish_response.request_id,
                                        &publish_response.response
                                    );
                                    // Messages will be sent by the writing task
                                    let _ = sender.send(Message::Message(
                                        publish_response.request_id,
                                        publish_response.response,
                                    ));
                                }
                            }
                        }
                    }
                }
                info!("Subscription receiver is finished");
                deregister_runtime_component!(&id);
            });
        }
    }

    /// Test if the connection should abort
    pub fn is_server_abort(&self) -> bool {
        let server_state = trace_read_lock_unwrap!(self.server_state);
        server_state.is_abort()
    }

    fn process_hello(
        &mut self,
        hello: HelloMessage,
        sender: &mut UnboundedSender<Message>,
    ) -> std::result::Result<(), StatusCode> {
        let server_protocol_version = 0;
        let endpoints = {
            let server_state = trace_read_lock_unwrap!(self.server_state);
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
            receive_buffer_size: RECEIVE_BUFFER_SIZE as u32,
            send_buffer_size: SEND_BUFFER_SIZE as u32,
            max_message_size: MAX_MESSAGE_SIZE as u32,
            max_chunk_count: MAX_CHUNK_COUNT as u32,
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
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        self.last_received_sequence_number = Chunker::validate_chunks(
            self.last_received_sequence_number + 1,
            &secure_channel,
            chunks,
        )?;
        // Now decode
        Chunker::decode(&chunks, &secure_channel, None)
    }

    fn process_chunk(
        &mut self,
        chunk: MessageChunk,
        sender: &mut UnboundedSender<Message>,
    ) -> std::result::Result<(), StatusCode> {
        let decoding_options = {
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
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
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
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
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
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
        let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
        let response = self.secure_channel_service.open_secure_channel(
            &mut secure_channel,
            security_header,
            self.client_protocol_version,
            &request,
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
