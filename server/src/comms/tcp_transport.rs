//! The TCP transport module handles receiving and sending of binary data in chunks, handshake,
//! session creation and dispatching of messages via message handler.
//!
use std;
use std::collections::VecDeque;
use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::time::{Instant, Duration};
use std::sync::{Arc, RwLock, Mutex};

use opcua_core::prelude::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;

use chrono;
use chrono::Utc;
use futures::{Stream, Future};
use futures::future::{self, loop_fn, Loop};
use futures::sync::mpsc;
use tokio;
use tokio::net::TcpStream;
use tokio_io::AsyncRead;
use tokio_io::io;
use tokio_io::io::{ReadHalf, WriteHalf};
use tokio_timer::Interval;

use address_space::types::AddressSpace;
use comms::secure_channel_service::SecureChannelService;
use comms::transport::*;
use constants;
use state::ServerState;
use services::message_handler::MessageHandler;
use session::Session;
use subscriptions::PublishResponseEntry;
use subscriptions::subscription::TickReason;

// TODO these need to go, and use session settings
const RECEIVE_BUFFER_SIZE: usize = 1024 * 64;
const SEND_BUFFER_SIZE: usize = 1024 * 64;
const MAX_MESSAGE_SIZE: usize = 1024 * 64;

macro_rules! connection_finished_test {
    ( $connection:expr ) => {
        {
            let connection = trace_read_lock_unwrap!($connection);
            let finished = connection.is_finished();
            if finished {
                debug!("task is dropping as connection is finished");
            }
            future::ok(!finished)
        }
    }
}

/// This is the thing that handles input and output for the open connection associated with the
/// session.
pub struct TcpTransport {
    // Server state, address space etc.
    server_state: Arc<RwLock<ServerState>>,
    // Session status code - Good, BadInvalid etc.
    session_status: StatusCode,
    // Session state - open sessions, tokens etc
    session: Arc<RwLock<Session>>,
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
    client_protocol_version: UInt32,
    /// Last encoded sequence number
    last_sent_sequence_number: UInt32,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
}

struct SocketWriter {
    /// Writing portion of socket
    pub write_half: WriteHalf<TcpStream>,
    /// The send buffer
    pub buffer: Cursor<Vec<u8>>,
}

impl SocketWriter {
    pub fn new(write_half: WriteHalf<TcpStream>) -> SocketWriter {
        SocketWriter {
            write_half,
            buffer: Cursor::new(vec![0u8; SEND_BUFFER_SIZE]),
        }
    }

    pub fn clear_buffer(&mut self) {
        self.buffer.set_position(0);
    }

    pub fn encode_error_message(&mut self, status_code: StatusCode) {
        let error = ErrorMessage::from_status_code(status_code);
        let _ = error.encode(&mut self.buffer);
    }

    pub fn write(&mut self) -> std::io::Result<usize> {
        if self.buffer.position() == 0 {
            Ok(0)
        } else {
            let result = {
                let out_buf_stream = &self.buffer;
                let bytes_to_write = out_buf_stream.position() as usize;
                let buffer_slice = &out_buf_stream.get_ref()[0..bytes_to_write];

                trace!("Writing {} bytes to client", buffer_slice.len());
                // log_buffer("Writing bytes to client:", buffer_slice);

                let result = self.write_half.write(&buffer_slice);
                match result {
                    Err(err) => {
                        error!("Error writing bytes - {:?}", err);
                        Err(err)
                    }
                    Ok(bytes_written) => {
                        if bytes_to_write != bytes_written {
                            error!("Error writing bytes - bytes_to_write = {}, bytes_written = {}", bytes_to_write, bytes_written);
                        } else {
                            trace!("Bytes written = {}", bytes_written);
                        }
                        Ok(bytes_written)
                    }
                }
            };

            // AND THEN clear the buffer
            self.buffer.set_position(0);
            result
        }
    }
}

struct ConnectionState {
    /// The associated connection
    pub connection: Arc<RwLock<TcpTransport>>,
    /// The messages buffer
    pub message_buffer: MessageBuffer,
    /// Reading portion of socket
    pub reader: ReadHalf<TcpStream>,
    /// Raw bytes in buffer
    pub in_buf: Vec<u8>,
    /// Bytes read in buffer
    pub bytes_read: usize,
    /// Write buffer
    pub writer: Arc<Mutex<SocketWriter>>,
    /// Session start time
    pub session_start_time: chrono::DateTime<Utc>,
}

impl Transport for TcpTransport {
    fn state(&self) -> TransportState {
        self.transport_state
    }

    fn session_status(&self) -> StatusCode {
        self.session_status
    }

    fn set_session_status(&mut self, session_status: StatusCode) {
        self.session_status = session_status
    }

    fn session(&self) -> Arc<RwLock<Session>> {
        self.session.clone()
    }

    fn client_address(&self) -> Option<SocketAddr> {
        self.client_address
    }

    // Terminates the connection and the session
    fn terminate_session(&mut self, status_code: StatusCode) {
        self.transport_state = TransportState::Finished;
        self.set_session_status(status_code);
        let mut session = trace_write_lock_unwrap!(self.session);
        session.set_terminated();
    }

    /// Test if the connection is terminated
    fn is_session_terminated(&self) -> bool {
        if let Ok(ref session) = self.session.try_read() {
            session.terminated()
        } else {
            false
        }
    }
}

impl TcpTransport {
    pub fn new(server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, message_handler: MessageHandler) -> TcpTransport {
        let secure_channel_service = SecureChannelService::new();
        TcpTransport {
            server_state,
            session,
            session_status: Good,
            address_space,
            transport_state: TransportState::New,
            client_address: None,
            message_handler,
            secure_channel_service,
            client_protocol_version: 0,
            last_sent_sequence_number: 0,
            last_received_sequence_number: 0,
        }
    }

    /// This is the entry point for the session. This function is asynchronous - it spawns tokio
    /// tasks to handle the session execution loop so this function will returns immediately.
    pub fn run(connection: Arc<RwLock<TcpTransport>>, socket: TcpStream) {
        // Store the address of the client
        {
            let mut connection = trace_write_lock_unwrap!(connection);
            connection.client_address = Some(socket.peer_addr().unwrap());
            connection.transport_state = TransportState::WaitingHello;
        }

        // Spawn the tasks we need to run
        Self::spawn_looping_task(connection, socket);
    }

    fn spawn_looping_task(connection: Arc<RwLock<TcpTransport>>, socket: TcpStream) {
        let session_start_time = Utc::now();
        info!("Session started {}", session_start_time);

        // Make the connection state - this handles the general loop that reads bytes, writes bytes
        // turns bytes into chunks, messages, processes the messages
        let (reader, writer) = socket.split();

        // Connection state is maintained for looping through each task
        let connection_state = ConnectionState {
            connection: connection.clone(),
            message_buffer: MessageBuffer::new(RECEIVE_BUFFER_SIZE),
            bytes_read: 0,
            reader,
            in_buf: vec![0u8; RECEIVE_BUFFER_SIZE],
            writer: Arc::new(Mutex::new(SocketWriter::new(writer))),
            session_start_time,
        };

        // Spawn the hello timeout task
        Self::spawn_hello_timeout_task(&connection_state);
        // Spawn the subscription processing task
        Self::spawn_subscriptions_task(&connection_state);

        // 1. Read bytes
        // 2. Store bytes in a buffer
        // 3. Process any chunks (messages) that can be extracted from buffer
        // 4. Send outgoing messages
        // 5. Terminate if necessary
        // 6. Go to 1
        let looping_task = loop_fn(connection_state, move |connection_state| {

            // Stuff is taken out of connection state because it is partially consumed by io::read
            let connection_for_err = connection_state.connection.clone();
            let connection = connection_state.connection;
            let message_buffer = connection_state.message_buffer;
            let in_buf = connection_state.in_buf;
            let reader = connection_state.reader;
            let writer = connection_state.writer;
            let session_start_time = connection_state.session_start_time;

            // Read and process bytes from the stream
            io::read(reader, in_buf).map_err(move |err| {
                error!("Transport IO error {:?}", err);
                (connection_for_err, BadCommunicationError)
            }).map(move |(reader, in_buf, bytes_read)| {
                if bytes_read > 0 {
                    trace!("Read {} bytes", bytes_read);
                }
                // Build a new connection state
                ConnectionState {
                    connection,
                    message_buffer,
                    bytes_read,
                    reader,
                    writer,
                    in_buf,
                    session_start_time,
                }
            }).and_then(|mut connection_state| {
                let is_server_abort = {
                    let connection = trace_read_lock_unwrap!(connection_state.connection);
                    connection.is_server_abort()
                };
                if is_server_abort {
                    info!("Transport is terminating because server has aborted");
                    return Err((connection_state.connection.clone(), BadCommunicationError));
                }

                let transport_state = {
                    let connection = trace_read_lock_unwrap!(connection_state.connection);
                    connection.transport_state.clone()
                };

                if connection_state.bytes_read > 0 {
                    let mut session_status_code = Good;
                    let result = connection_state.message_buffer.store_bytes(&connection_state.in_buf[..connection_state.bytes_read]);
                    if result.is_err() {
                        session_status_code = result.unwrap_err();
                    } else {
                        let messages = result.unwrap();
                        for message in messages {
                            match transport_state {
                                TransportState::WaitingHello => {
                                    debug!("Processing HELLO");
                                    if let Message::Hello(hello) = message {
                                        let mut connection = trace_write_lock_unwrap!(connection_state.connection);
                                        let mut writer = trace_lock_unwrap!(connection_state.writer);
                                        let result = connection.process_hello(hello, &mut writer.buffer);
                                        if result.is_err() {
                                            session_status_code = result.unwrap_err();
                                        }
                                    } else {
                                        session_status_code = BadCommunicationError;
                                    }
                                }
                                TransportState::ProcessMessages => {
                                    debug!("Processing message");
                                    if let Message::MessageChunk(chunk) = message {
                                        let mut connection = trace_write_lock_unwrap!(connection_state.connection);
                                        let mut writer = trace_lock_unwrap!(connection_state.writer);
                                        let result = connection.process_chunk(chunk, &mut writer.buffer);
                                        if result.is_err() {
                                            session_status_code = result.unwrap_err();
                                        }
                                    } else {
                                        session_status_code = BadCommunicationError;
                                    }
                                }
                                _ => {
                                    error!("Unknown sesion state, aborting");
                                    session_status_code = BadUnexpectedError;
                                }
                            };
                        }
                    }
                    // Update the session status
                    {
                        let mut connection = trace_write_lock_unwrap!(connection_state.connection);
                        connection.set_session_status(session_status_code);
                    }
                }
                Ok(connection_state)
            }).and_then(|connection_state| {
                // Write anything in the out buffer
                {
                    let mut writer = trace_lock_unwrap!(connection_state.writer);
                    let _ = writer.write();
                }
                Ok(connection_state)
            }).and_then(|connection_state| {
                // Some handlers might wish to send their message and terminate, in which case this is
                // done here.
                let session_status = {
                    let mut connection = trace_write_lock_unwrap!(connection_state.connection);
                    // Terminate may have been set somewhere
                    let terminate_session = {
                        let session = trace_read_lock_unwrap!(connection.session);
                        session.terminate_session
                    };
                    if terminate_session {
                        connection.set_session_status(BadConnectionClosed);
                    }
                    // Other session status
                    connection.session_status()
                };

                // Abort the session?
                if session_status.is_good() {
                    Ok(Loop::Continue(connection_state))
                } else {
                    // As a final act, the session sends a status code to the client if one should be sent
                    match session_status {
                        Good | BadConnectionClosed => {
                            info!("Session terminating normally, session_status_code = {:?}", session_status);
                        }
                        _ => {
                            warn!("Sending session terminating error {:?}", session_status);
                            {
                                let mut writer = trace_lock_unwrap!(connection_state.writer);
                                writer.clear_buffer();
                                writer.encode_error_message(session_status);
                                let _ = writer.write();
                            }
                        }
                    }

                    let session_duration = Utc::now().signed_duration_since(connection_state.session_start_time);
                    info!("Session is finished {:?}", session_duration);

                    {
                        let mut connection = trace_write_lock_unwrap!(connection_state.connection);
                        connection.terminate_session(session_status);
                    }
                    Ok(Loop::Break(connection_state))
                }
            })
        }).map_err(move |(connection, status_code)| {
            info!("An error occurred, terminating the connection");
            {
                let mut connection = trace_write_lock_unwrap!(connection);
                connection.terminate_session(status_code);
            }
            ()
        }).map(|_| ());

        tokio::spawn(looping_task);
    }

    /// Makes the tokio task that looks for a hello timeout event, i.e. the connection is opened
    /// but no hello is received and we need to drop the session
    fn spawn_hello_timeout_task(connection_state: &ConnectionState) {
        struct HelloState {
            /// The associated connection
            pub connection: Arc<RwLock<TcpTransport>>,
            /// Session start time
            pub session_start_time: chrono::DateTime<Utc>,
            /// Hello timeout duration, i.e. how long a session is waiting for the hello before it times out
            pub hello_timeout: chrono::Duration,
        }
        let hello_timeout = {
            let hello_timeout = {
                let connection = trace_read_lock_unwrap!(connection_state.connection);
                let server_state = trace_read_lock_unwrap!(connection.server_state);
                let server_config = trace_read_lock_unwrap!(server_state.config);
                server_config.tcp_config.hello_timeout as i64
            };
            chrono::Duration::seconds(hello_timeout)
        };
        let state = HelloState {
            connection: connection_state.connection.clone(),
            hello_timeout,
            session_start_time: connection_state.session_start_time.clone(),
        };

        // Clone the connection so the take_while predicate has its own instance
        let connection_for_take_while = state.connection.clone();
        let task = Interval::new(Instant::now(), Duration::from_millis(constants::HELLO_TIMEOUT_POLL_MS))
            .take_while(move |_| {
                // Terminates when session is no longer waiting for a hello or connection is done
                let connection = trace_read_lock_unwrap!(connection_for_take_while);
                let kill_timer = connection.has_received_hello() || connection.is_finished();
                if kill_timer {
                    debug!("Hello timeout timer is being stopped");
                }
                future::ok(!kill_timer)
            })
            .for_each(move |_| {
                // Check if the session has waited in the hello state for more than the hello timeout period
                let transport_state = {
                    let connection = trace_read_lock_unwrap!(state.connection);
                    connection.state()
                };
                if transport_state == TransportState::WaitingHello {
                    // Check if the time elapsed since the session started exceeds the hello timeout
                    let now = Utc::now();
                    if now.signed_duration_since(state.session_start_time.clone()).num_milliseconds() > state.hello_timeout.num_milliseconds() {
                        // Check if the session has waited in the hello state for more than the hello timeout period
                        info!("Session has been waiting for a hello for more than the timeout period and will now close");
                        let mut connection = trace_write_lock_unwrap!(state.connection);
                        connection.terminate_session(BadTimeout);
                    }
                }
                Ok(())
            }).map_err(|_| ());
        tokio::spawn(task);
    }

    /// Start the subscription timer to service subscriptions
    fn spawn_subscriptions_task(connection_state: &ConnectionState) {
        /// Subscription events are passed sent from the monitor task to the receiver
        #[derive(Clone, Debug, PartialEq)]
        enum SubscriptionEvent {
            PublishResponses(VecDeque<PublishResponseEntry>),
        }
        debug!("spawn_subscriptions_task ");

        // Make a channel for subscriptions
        let (subscription_tx, subscription_rx) = mpsc::unbounded::<SubscriptionEvent>();

        // Create the monitoring timer - this monitors for publish requests and ticks the subscriptions
        {
            struct SubscriptionMonitorState {
                /// The associated connection
                pub connection: Arc<RwLock<TcpTransport>>,
            }

            let state = SubscriptionMonitorState {
                connection: connection_state.connection.clone(),
            };

            // Clone the connection so the take_while predicate has its own instance
            let connection_for_take_while = state.connection.clone();

            // Creates a repeating interval future that checks subscriptions.
            let interval_duration = Duration::from_millis(constants::SUBSCRIPTION_TIMER_RATE_MS);
            let task = Interval::new(Instant::now(), interval_duration)
                .take_while(move |_| {
                    connection_finished_test!(connection_for_take_while)
                })
                .for_each(move |_| {
                    let connection = trace_read_lock_unwrap!(state.connection);
                    let mut session = trace_write_lock_unwrap!(connection.session);

                    let now = Utc::now();

                    // Request queue might contain stale publish requests
                    session.expire_stale_publish_requests(&now);

                    // Process subscriptions
                    {
                        let address_space = trace_read_lock_unwrap!(connection.address_space);
                        let _ = session.tick_subscriptions(&now, &address_space, TickReason::TickTimerFired);
                    }

                    // Check if there are publish responses to send for transmission
                    if let Some(publish_responses) = session.subscriptions.take_publish_responses() {
                        match subscription_tx.unbounded_send(SubscriptionEvent::PublishResponses(publish_responses)) {
                            Err(error) => {
                                error!("Can't send publish responses, err = {}", error);
                            }
                            Ok(_) => {
                                trace!("Sent publish responses to session task");
                            }
                        }
                    }
                    Ok(())
                }).map_err(|_| ());
            tokio::spawn(task);
        }

        // Create the receiving task - this takes publish responses and sends them back to the client
        {
            struct SubscriptionReceiverState {
                /// The associated connection
                pub connection: Arc<RwLock<TcpTransport>>,
                /// Write buffer
                pub writer: Arc<Mutex<SocketWriter>>,
            }

            let state = SubscriptionReceiverState {
                connection: connection_state.connection.clone(),
                writer: connection_state.writer.clone(),
            };

            // Clone the connection so the take_while predicate has its own instance
            let connection_for_take_while = state.connection.clone();

            tokio::spawn(subscription_rx
                .take_while(move |_| {
                    connection_finished_test!(connection_for_take_while)
                })
                .for_each(move |subscription_event| {
                    // Process publish response events
                    match subscription_event {
                        SubscriptionEvent::PublishResponses(publish_responses) => {
                            trace!("Got {} PublishResponse messages to send", publish_responses.len());
                            let mut writer = trace_lock_unwrap!(state.writer);
                            for publish_response in publish_responses {
                                trace!("<-- Sending a Publish Response{}, {:?}", publish_response.request_id, &publish_response.response);
                                let mut connection = trace_write_lock_unwrap!(state.connection);
                                let _ = connection.send_response(publish_response.request_id, &publish_response.response, &mut writer.buffer);
                                let _ = writer.write();
                            }
                        }
                    }
                    Ok(())
                }));
        }
    }

    /// Test if the connection should abort
    pub fn is_server_abort(&self) -> bool {
        let server_state = trace_read_lock_unwrap!(self.server_state);
        server_state.abort
    }

    fn process_hello<W: Write>(&mut self, hello: HelloMessage, out_stream: &mut W) -> std::result::Result<(), StatusCode> {
        let server_protocol_version = 0;

        trace!("Server received HELLO {:?}", hello);
        if !hello.is_endpoint_url_valid() {
            return Err(BadTcpEndpointUrlInvalid);
        }
        if !hello.is_valid_buffer_sizes() {
            error!("HELLO buffer sizes are invalid");
            return Err(BadCommunicationError);
        }

        // Validate protocol version
        if hello.protocol_version > server_protocol_version {
            return Err(BadProtocolVersionUnsupported);
        }

        let client_protocol_version = hello.protocol_version;

        // Send acknowledge
        let mut acknowledge = AcknowledgeMessage {
            message_header: MessageHeader::new(MessageType::Acknowledge),
            protocol_version: server_protocol_version,
            receive_buffer_size: RECEIVE_BUFFER_SIZE as UInt32,
            send_buffer_size: SEND_BUFFER_SIZE as UInt32,
            max_message_size: MAX_MESSAGE_SIZE as UInt32,
            max_chunk_count: MAX_CHUNK_COUNT as UInt32,
        };
        acknowledge.message_header.message_size = acknowledge.byte_len() as UInt32;

        // New state
        self.transport_state = TransportState::ProcessMessages;
        self.client_protocol_version = client_protocol_version;

        debug!("Sending ACK");
        let _ = acknowledge.encode(out_stream);
        Ok(())
    }

    fn turn_received_chunks_into_message(&mut self, chunks: &Vec<MessageChunk>) -> std::result::Result<SupportedMessage, StatusCode> {
        let session = trace_read_lock_unwrap!(self.session);
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        self.last_received_sequence_number = Chunker::validate_chunks(self.last_received_sequence_number + 1, &session.secure_channel, chunks)?;
        // Now decode
        Chunker::decode(&chunks, &session.secure_channel, None)
    }

    fn process_chunk<W: Write>(&mut self, chunk: MessageChunk, out_stream: &mut W) -> std::result::Result<(), StatusCode> {
        let message_header = chunk.message_header()?;

        if message_header.is_final == MessageIsFinalType::Intermediate {
            panic!("We don't support intermediate chunks yet");
        } else if message_header.is_final == MessageIsFinalType::FinalError {
            info!("Discarding chunk marked in as final error");
            return Ok(());
        }

        // Decrypt / verify chunk if necessary
        let chunk = {
            let mut session = trace_write_lock_unwrap!(self.session);
            session.secure_channel.verify_and_remove_security(&chunk.data)?
        };

        let in_chunks = vec![chunk];
        let chunk_info = {
            let session = trace_read_lock_unwrap!(self.session);
            in_chunks[0].chunk_info(&session.secure_channel)?
        };
        let request_id = chunk_info.sequence_header.request_id;

        let message = self.turn_received_chunks_into_message(&in_chunks)?;
        let response = match message_header.message_type {
            MessageChunkType::OpenSecureChannel => {
                let mut session = trace_write_lock_unwrap!(self.session);
                self.secure_channel_service.open_secure_channel(&mut session.secure_channel, &chunk_info.security_header, self.client_protocol_version, &message)?
            }
            MessageChunkType::CloseSecureChannel => {
                self.secure_channel_service.close_secure_channel(&message)?
            }
            MessageChunkType::Message => {
                let response = self.message_handler.handle_message(request_id, message)?;
                if response.is_none() {
                    // No response for the message at this time
                    return Ok(());
                }
                response.unwrap()
            }
        };
        self.send_response(request_id, &response, out_stream)?;
        Ok(())
    }

    fn send_response<W: Write>(&mut self, request_id: UInt32, response: &SupportedMessage, out_stream: &mut W) -> std::result::Result<(), StatusCode> {
        // Prepare some chunks starting from the sequence number + 1
        match *response {
            SupportedMessage::Invalid(object_id) => {
                panic!("Invalid response with object_id {:?}", object_id);
            }
            _ => {
                // Send the response
                // Get the request id out of the request
                // debug!("Response to send: {:?}", response);
                let sequence_number = self.last_sent_sequence_number + 1;
                // TODO max message size, max chunk size
                let max_chunk_size = 64 * 1024;
                let out_chunks = {
                    let session = trace_read_lock_unwrap!(self.session);
                    Chunker::encode(sequence_number, request_id, 0, max_chunk_size, &session.secure_channel, response)?
                };
                self.last_sent_sequence_number = sequence_number + out_chunks.len() as UInt32 - 1;

                // Send out any chunks that form the response
                // debug!("Got some chunks to send {:?}", out_chunks);
                let mut data = vec![0u8; max_chunk_size + 1024];
                for out_chunk in &out_chunks {
                    // Encrypt and sign the chunk if necessary
                    let session = trace_read_lock_unwrap!(self.session);
                    let size = session.secure_channel.apply_security(out_chunk, &mut data);
                    if size.is_ok() {
                        let _ = out_stream.write(&data[..size.unwrap()]);
                    } else {
                        panic!("Applying security to chunk failed - {:?}", size.unwrap_err());
                    }
                }
            }
        }
        Ok(())
    }
}


