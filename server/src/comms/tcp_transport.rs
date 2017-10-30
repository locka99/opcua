//! The TCP transport module handles receiving and sending of binary data in chunks, handshake,
//! session creation and dispatching of messages via message handler.
//!
use std;
use std::net::{TcpStream, Shutdown};
use std::io::{Read, Write, Cursor, ErrorKind};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver};

use timer;
use chrono::UTC;
use time;

use opcua_types::*;
use opcua_core::prelude::*;
use opcua_core::debug::*;

use constants;
use comms::secure_channel_service::SecureChannelService;
use server_state::ServerState;
use session::Session;
use services::message_handler::MessageHandler;
use subscriptions::subscription::SubscriptionEvent;

// TODO these need to go, and use session settings
const RECEIVE_BUFFER_SIZE: usize = 1024 * 64;
const SEND_BUFFER_SIZE: usize = 1024 * 64;
const MAX_MESSAGE_SIZE: usize = 1024 * 64;

#[derive(Clone, Debug, PartialEq)]
pub enum TransportState {
    New,
    WaitingHello,
    ProcessMessages,
    Finished
}

/// This is the thing that handles input and output for the open connection associated with the
/// session.
pub struct TcpTransport {
    // Server state, address space etc.
    pub server_state: Arc<Mutex<ServerState>>,
    // Session state - open sessions, tokens etc
    pub session: Arc<Mutex<Session>>,
    /// Session state is anything related to this connection
    /// The current session state
    pub transport_state: TransportState,
    /// Secure channel handler
    pub secure_channel_service: SecureChannelService,
    /// Message handler
    message_handler: MessageHandler,
    /// Client protocol version set during HELLO
    client_protocol_version: UInt32,
    /// Last encoded sequence number
    last_sent_sequence_number: UInt32,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
}

impl TcpTransport {
    pub fn new(server_state: Arc<Mutex<ServerState>>) -> TcpTransport {
        let session = {
            let server_state = server_state.lock().unwrap();
            Arc::new(Mutex::new(Session::new(&server_state)))
        };

        let secure_channel_service = SecureChannelService::new();

        TcpTransport {
            server_state: server_state.clone(),
            session: session.clone(),
            transport_state: TransportState::New,
            message_handler: MessageHandler::new(server_state.clone(), session.clone()),
            secure_channel_service,
            client_protocol_version: 0,
            last_sent_sequence_number: 0,
            last_received_sequence_number: 0,
        }
    }

    pub fn run(&mut self, mut stream: TcpStream) {
        // ENTRY POINT TO ALL OF OPC

        let session_start_time = UTC::now();
        info!("Session started {}", session_start_time);

        let (subscription_timer, subscription_timer_guard, subscription_timer_rx) = self.start_subscription_timer();

        // Waiting for hello
        self.transport_state = TransportState::WaitingHello;

        // Hello timeout
        let hello_timeout = {
            let hello_timeout = {
                let server_state = self.server_state.lock().unwrap();
                let server_config = server_state.config.lock().unwrap();
                server_config.tcp_config.hello_timeout as i64
            };
            time::Duration::seconds(hello_timeout)
        };

        // Short timeout makes it work like a polling loop
        let polling_timeout: std::time::Duration = std::time::Duration::from_millis(50);
        let _ = stream.set_read_timeout(Some(polling_timeout));
        let _ = stream.set_nodelay(true);

        let mut in_buf = vec![0u8; RECEIVE_BUFFER_SIZE];
        let mut out_buf_stream = Cursor::new(vec![0u8; SEND_BUFFER_SIZE]);

        // Format of OPC UA TCP is defined in OPC UA Part 6 Chapter 7
        // Basic startup is a HELLO,  OpenSecureChannel, begin

        let mut session_status_code = GOOD;

        let mut message_buffer = MessageBuffer::new(RECEIVE_BUFFER_SIZE);

        loop {
            // Check for abort
            {
                let server_state = self.server_state.lock().unwrap();
                if server_state.abort {
                    break;
                }
            }

            let transport_state = self.transport_state.clone();

            // Session waits a configurable time for a hello and terminates if it fails to receive it
            let now = UTC::now();
            if transport_state == TransportState::WaitingHello {
                if now.signed_duration_since(session_start_time) > hello_timeout {
                    error!("Session timed out waiting for hello");
                    session_status_code = BAD_TIMEOUT;
                    break;
                }
            }

            // Process subscription timer events
            if let Ok(result) = subscription_timer_rx.try_recv() {
                match result {
                    SubscriptionEvent::PublishResponses(publish_responses) => {
                        trace!("Got {} PublishResponse messages to send", publish_responses.len());
                        for publish_response in publish_responses {
                            trace!("<-- Sending a Publish Response{}, {:?}", publish_response.request_id, &publish_response.response);
                            let _ = self.send_response(publish_response.request_id, &publish_response.response, &mut out_buf_stream);
                        }
                        Self::write_output(&mut out_buf_stream, &mut stream);
                    }
                }
            }

            // Try to read, using timeout as a polling mechanism
            let bytes_read_result = stream.read(&mut in_buf);
            if bytes_read_result.is_err() {
                let error = bytes_read_result.unwrap_err();
                if error.kind() == ErrorKind::TimedOut {
                    continue;
                }
                debug!("Read error - kind = {:?}, {:?}", error.kind(), error);
                break;
            }
            let bytes_read = bytes_read_result.unwrap();
            if bytes_read == 0 {
                continue;
            }

            let result = message_buffer.store_bytes(&in_buf[0..bytes_read]);
            if result.is_err() {
                session_status_code = result.unwrap_err();
                break;
            }
            let messages = result.unwrap();
            for message in messages {
                match transport_state {
                    TransportState::WaitingHello => {
                        debug!("Processing HELLO");
                        if let Message::Hello(hello) = message {
                            let result = self.process_hello(hello, &mut out_buf_stream);
                            if result.is_err() {
                                session_status_code = result.unwrap_err();
                            }
                        } else {
                            session_status_code = BAD_COMMUNICATION_ERROR;
                        }
                    }
                    TransportState::ProcessMessages => {
                        debug!("Processing message");
                        if let Message::MessageChunk(chunk) = message {
                            let result = self.process_chunk(chunk, &mut out_buf_stream);
                            if result.is_err() {
                                session_status_code = result.unwrap_err();
                            }
                        } else {
                            session_status_code = BAD_COMMUNICATION_ERROR;
                        }
                    }
                    _ => {
                        error!("Unknown sesion state, aborting");
                        session_status_code = BAD_UNEXPECTED_ERROR;
                    }
                };
            }

            // Anything to write?
            Self::write_output(&mut out_buf_stream, &mut stream);

            // Some handlers might wish to send their message and terminate, in which case this is
            // done here.
            {
                let session = self.session.lock().unwrap();
                if session.terminate_session {
                    session_status_code = BAD_CONNECTION_CLOSED;
                }
            }

            // Terminate the session?
            if !session_status_code.is_good() {
                break;
            }
        }
        drop(subscription_timer_guard);
        drop(subscription_timer);

        // As a final act, the session sends a status code to the client if one should be sent
        match session_status_code {
            GOOD | BAD_CONNECTION_CLOSED => {
                info!("Session terminating normally, session_status_code = {:?}", session_status_code);
            }
            _ => {
                warn!("Sending session terminating error {:?}", session_status_code);
                out_buf_stream.set_position(0);
                let error = ErrorMessage::from_status_code(session_status_code);
                let _ = error.encode(&mut out_buf_stream);
                Self::write_output(&mut out_buf_stream, &mut stream);
            }
        }
        // Close socket
        info!("Terminating socket");
        let _ = stream.shutdown(Shutdown::Both);

        // Session state
        self.transport_state = TransportState::Finished;

        let session_duration = UTC::now().signed_duration_since(session_start_time);
        info!("Session is finished {:?}", session_duration);

        {
            let mut session = self.session.lock().unwrap();
            session.terminated();
        }
    }

    /// Start the subscription timer to service subscriptions
    fn start_subscription_timer(&mut self) -> (timer::Timer, timer::Guard, Receiver<SubscriptionEvent>) {
        let (subscription_timer_tx, subscription_timer_rx) = mpsc::channel();

        let session = self.session.clone();
        let server_state = self.server_state.clone();

        // Creates a repeating timer that checks subscriptions. The guard is returned to the caller
        // so it can control the scope of events.
        let subscription_timer = timer::Timer::new();
        let subscription_timer_guard = subscription_timer.schedule_repeating(time::Duration::milliseconds(constants::SUBSCRIPTION_TIMER_RATE_MS), move || {
            let server_state = server_state.lock().unwrap();
            let mut session = session.lock().unwrap();

            // Request queue might contain stale publish requests
            session.expire_stale_publish_requests(&UTC::now());

            // Process subscriptions
            let _ = session.tick_subscriptions(&server_state, false);

            // Check if there are publish responses to send for transmission
            if !session.subscriptions.publish_response_queue.is_empty() {
                trace!("Sending publish responses to session thread");
                let mut publish_responses = Vec::with_capacity(session.subscriptions.publish_response_queue.len());
                publish_responses.append(&mut session.subscriptions.publish_response_queue);
                let sent = subscription_timer_tx.send(SubscriptionEvent::PublishResponses(publish_responses));
                if sent.is_err() {
                    error!("Can't send publish responses, err = {}", sent.unwrap_err());
                }
            }
        });
        (subscription_timer, subscription_timer_guard, subscription_timer_rx)
    }

    fn write_output(buffer_stream: &mut Cursor<Vec<u8>>, stream: &mut Write) {
        //
        if buffer_stream.position() == 0 {
            return;
        }

        // Scope to avoid immutable/mutable borrow issues
        {
            let bytes_to_write = buffer_stream.position() as usize;
            let buffer_slice = &buffer_stream.get_ref()[0..bytes_to_write];

            trace!("Writing {} bytes to client", buffer_slice.len());
            // log_buffer("Writing bytes to client:", buffer_slice);

            let result = stream.write(buffer_slice);
            if result.is_err() {
                error!("Error writing bytes - {:?}", result.unwrap_err());
            } else {
                let bytes_written = result.unwrap();
                if bytes_to_write != bytes_written {
                    error!("Error writing bytes - bytes_to_write = {}, bytes_written = {}", bytes_to_write, bytes_written);
                } else {
                    trace!("Bytes written = {}", bytes_written);
                }
            }
            // let _ = stream.flush();
        }
        buffer_stream.set_position(0);
    }

    fn process_hello<W: Write>(&mut self, hello: HelloMessage, out_stream: &mut W) -> std::result::Result<(), StatusCode> {
        let server_protocol_version = 0;

        trace!("Server received HELLO {:?}", hello);
        if !hello.is_endpoint_url_valid() {
            return Err(BAD_TCP_ENDPOINT_URL_INVALID);
        }
        if !hello.is_valid_buffer_sizes() {
            error!("HELLO buffer sizes are invalid");
            return Err(BAD_COMMUNICATION_ERROR);
        }

        // Validate protocol version
        if hello.protocol_version > server_protocol_version {
            return Err(BAD_PROTOCOL_VERSION_UNSUPPORTED);
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
        let session = self.session.lock().unwrap();
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        self.last_received_sequence_number = Chunker::validate_chunk_sequences(self.last_received_sequence_number + 1, &session.secure_channel, chunks)?;
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
            let mut session = self.session.lock().unwrap();
            session.secure_channel.verify_and_remove_security(&chunk.data)?
        };

        let in_chunks = vec![chunk];
        let chunk_info = {
            let session = self.session.lock().unwrap();
            in_chunks[0].chunk_info(&session.secure_channel)?
        };
        let request_id = chunk_info.sequence_header.request_id;

        let message = self.turn_received_chunks_into_message(&in_chunks)?;
        let response = match message_header.message_type {
            MessageChunkType::OpenSecureChannel => {
                let mut session = self.session.lock().unwrap();
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
                    let session = self.session.lock().unwrap();
                    Chunker::encode(sequence_number, request_id, 0, max_chunk_size, &session.secure_channel, response)?
                };
                self.last_sent_sequence_number = sequence_number + out_chunks.len() as UInt32 - 1;

                // Send out any chunks that form the response
                // debug!("Got some chunks to send {:?}", out_chunks);
                let mut data = vec![0u8; max_chunk_size + 1024];
                for out_chunk in &out_chunks {
                    // Encrypt and sign the chunk if necessary
                    let session = self.session.lock().unwrap();
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


