//! The TCP transport module handles receiving and sending of binary data in chunks, handshake,
//! session creation and dispatching of messages via message handler.
//!
use std;
use std::net::{TcpStream, Shutdown};
use std::io::{Read, Write, Cursor, ErrorKind};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver};

use timer;
use chrono::{UTC};
use time;

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::*;
use opcua_core::debug::*;

use server::ServerState;
use session::SessionState;
use comms::message_handler::*;
use subscriptions::{SubscriptionEvent};

// TODO these need to go, and use session_state settings
const RECEIVE_BUFFER_SIZE: usize = 1024 * 64;
const SEND_BUFFER_SIZE: usize = 1024 * 64;
const MAX_MESSAGE_SIZE: usize = 1024 * 64;

// Rate at which subscriptions are serviced
const SUBSCRIPTION_TIMER_RATE: i64 = 200;

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
    pub session_state: Arc<Mutex<SessionState>>,
    /// Session state is anything related to this connection
    /// The current session state
    pub transport_state: TransportState,
    /// Message handler
    message_handler: MessageHandler,
    /// Client protocol version set during HELLO
    client_protocol_version: UInt32,
    // Last secure channel id
    last_secure_channel_id: UInt32,
    // Secure channel info for the session
    secure_channel_info: SecureChannelInfo,
    /// Last encoded sequence number
    last_sent_sequence_number: UInt32,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
}

impl TcpTransport {
    pub fn new(server_state: &Arc<Mutex<ServerState>>) -> TcpTransport {
        let session_state = Arc::new(Mutex::new(SessionState::new()));
        TcpTransport {
            server_state: server_state.clone(),
            session_state: session_state.clone(),
            transport_state: TransportState::New,
            client_protocol_version: 0,
            last_secure_channel_id: 0,
            secure_channel_info: SecureChannelInfo {
                security_policy: SecurityPolicy::None,
                secure_channel_id: 0,
                token_id: 0,
            },
            message_handler: MessageHandler::new(&server_state, &session_state),
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

        let mut session_status_code = GOOD.clone();

        let mut message_buffer = MessageBuffer::new(RECEIVE_BUFFER_SIZE);

        loop {
            let transport_state = self.transport_state.clone();

            // Session waits a configurable time for a hello and terminates if it fails to receive it
            let now = UTC::now();
            if transport_state == TransportState::WaitingHello {
                if now - session_start_time > hello_timeout {
                    error!("Session timed out waiting for hello");
                    session_status_code = BAD_TIMEOUT.clone();
                    break;
                }
            }

            // Process subscription timer events
            if let Ok(result) = subscription_timer_rx.try_recv() {
                debug!("Got message from timer {:?}", result);
                match result {
                    SubscriptionEvent::PublishResponses(publish_responses) => {
                        error!("Received messages, sending them out");
                        for publish_response in publish_responses {
                            error!("SENDING MESSAGE {}, {:#?}", publish_response.request_id, &publish_response.response);
                            let _ = self.send_response(publish_response.request_id, &SupportedMessage::PublishResponse(publish_response.response), &mut out_buf_stream);
                        }
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
                session_status_code = result.unwrap_err().clone();
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
                                session_status_code = result.unwrap_err().clone();
                            }
                        } else {
                            session_status_code = BAD_COMMUNICATION_ERROR.clone();
                        }
                    }
                    TransportState::ProcessMessages => {
                        debug!("Processing message");
                        if let Message::Chunk(chunk) = message {
                            let result = self.process_chunk(chunk, &mut out_buf_stream);
                            if result.is_err() {
                                session_status_code = result.unwrap_err().clone();
                            }
                        } else {
                            session_status_code = BAD_COMMUNICATION_ERROR.clone();
                        }
                    }
                    _ => {
                        error!("Unknown sesion state, aborting");
                        session_status_code = BAD_UNEXPECTED_ERROR.clone();
                    }
                };
            }

            // Anything to write?
            TcpTransport::write_output(&mut out_buf_stream, &mut stream);
            if !session_status_code.is_good() {
                break;
            }
        }
        drop(subscription_timer_guard);
        drop(subscription_timer);

        // As a final act, the session sends a status code to the client if one should be sent
        if session_status_code == GOOD || session_status_code == BAD_CONNECTION_CLOSED {
            warn!("Sending session terminating error {:?}", session_status_code);
            out_buf_stream.set_position(0);
            let error = ErrorMessage::from_status_code(&session_status_code);
            let _ = error.encode(&mut out_buf_stream);
            TcpTransport::write_output(&mut out_buf_stream, &mut stream);
        } else {
            info!("Session terminating normally, session_status_code = {:?}", session_status_code);
        }

        // Close socket
        info!("Terminating socket");
        let _ = stream.shutdown(Shutdown::Both);

        // Session state
        self.transport_state = TransportState::Finished;

        let session_duration = UTC::now() - session_start_time;
        info!("Session is finished {:?}", session_duration)
    }

    /// Start the subscription timer to service subscriptions
    fn start_subscription_timer(&mut self) -> (timer::Timer, timer::Guard, Receiver<SubscriptionEvent>) {
        let (subscription_timer_tx, subscription_timer_rx) = mpsc::channel();

        let session_state = self.session_state.clone();
        let server_state = self.server_state.clone();

        // Creates a repeating timer that checks subscriptions. The guard is returned to the caller
        // so it can control the scope of events.
        let subscription_timer = timer::Timer::new();
        let subscription_timer_guard = subscription_timer.schedule_repeating(time::Duration::milliseconds(SUBSCRIPTION_TIMER_RATE), move || {
            // Manage subscriptions
            let mut session_state = session_state.lock().unwrap();

            // Request queue might contain stale publish requests
            if let Some(publish_responses) = session_state.expire_stale_publish_requests(&UTC::now()) {
                let _ = subscription_timer_tx.send(SubscriptionEvent::PublishResponses(publish_responses));
            }

            // Process subscriptions
            {
                let server_state = server_state.lock().unwrap();
                let address_space = server_state.address_space.lock().unwrap();
                if let Some(publish_responses) = session_state.tick_subscriptions(false, &address_space) {
                    let _ = subscription_timer_tx.send(SubscriptionEvent::PublishResponses(publish_responses));
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

            debug!("Writing bytes to client:");
            debug_buffer(buffer_slice);

            let result = stream.write(buffer_slice);
            if result.is_err() {
                error!("Error writing bytes - {:?}", result.unwrap_err());
            } else {
                let bytes_written = result.unwrap();
                if bytes_to_write != bytes_written {
                    error!("Error writing bytes - bytes_to_write = {}, bytes_written = {}", bytes_to_write, bytes_written);
                } else {
                    debug!("Bytes written = {}", bytes_written);
                }
            }
            // let _ = stream.flush();
        }
        buffer_stream.set_position(0);
    }

    fn process_hello<W: Write>(&mut self, hello: HelloMessage, out_stream: &mut W) -> std::result::Result<(), &'static StatusCode> {
        let server_protocol_version = 0;

        debug!("Server received HELLO {:?}", hello);
        if !hello.is_endpoint_url_valid() {
            return Err(&BAD_TCP_ENDPOINT_URL_INVALID);
        }
        if !hello.is_valid_buffer_sizes() {
            error!("HELLO buffer sizes are invalid");
            return Err(&BAD_COMMUNICATION_ERROR);
        }

        // Validate protocol version
        if hello.protocol_version > server_protocol_version {
            return Err(&BAD_PROTOCOL_VERSION_UNSUPPORTED);
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

        info!("Sending acknowledge {:?}", acknowledge);
        let _ = acknowledge.encode(out_stream);
        Ok(())
    }

    fn turn_received_chunks_into_message(&mut self, chunks: &Vec<Chunk>) -> std::result::Result<SupportedMessage, &'static StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        self.last_received_sequence_number = Chunker::validate_chunk_sequences(self.last_received_sequence_number, &self.secure_channel_info, chunks)?;
        // Now decode
        Chunker::decode(&chunks, &self.secure_channel_info, None)
    }

    fn process_chunk<W: Write>(&mut self, chunk: Chunk, out_stream: &mut W) -> std::result::Result<(), &'static StatusCode> {
        debug!("Got a chunk {:?}", chunk);

        if chunk.chunk_header.chunk_type == ChunkType::Intermediate {
            panic!("We don't support intermediate chunks yet");
        } else if chunk.chunk_header.chunk_type == ChunkType::FinalError {
            info!("Discarding chunk marked in as final error");
            return Ok(())
        }

        let chunk_message_type = chunk.chunk_header.message_type.clone();

        let in_chunks = vec![chunk];
        let chunk_info = in_chunks[0].chunk_info(true, &self.secure_channel_info)?;
        let request_id = chunk_info.sequence_header.request_id;

        let message = self.turn_received_chunks_into_message(&in_chunks)?;
        let response = match chunk_message_type {
            ChunkMessageType::OpenSecureChannel => {
                SupportedMessage::OpenSecureChannelResponse(TcpTransport::process_open_secure_channel(self, &message)?)
            }
            ChunkMessageType::CloseSecureChannel => {
                info!("CloseSecureChannelRequest received, session closing");
                return Err(&BAD_CONNECTION_CLOSED);
            }
            ChunkMessageType::Message => {
                self.message_handler.handle_message(request_id, message)?
            }
        };

        self.send_response(request_id, &response, out_stream)?;
        Ok(())
    }

    fn send_response<W: Write>(&mut self, request_id: UInt32, response: &SupportedMessage, out_stream: &mut W) -> std::result::Result<(), &'static StatusCode> {
        // Prepare some chunks starting from the sequence number + 1
        match response {
            &SupportedMessage::Invalid(object_id) => {
                panic!("Invalid response with object_id {:?}", object_id);
            }
            &SupportedMessage::DoNothing => {
                // DO NOTHING
            }
            _ => {
                // Send the response
                // Get the request id out of the request
                // debug!("Response to send: {:?}", response);
                let sequence_number = self.last_sent_sequence_number + 1;
                let out_chunks = Chunker::encode(sequence_number, request_id, &self.secure_channel_info, response)?;
                self.last_sent_sequence_number = sequence_number + out_chunks.len() as UInt32 - 1;

                // Send out any chunks that form the response
                // debug!("Got some chunks to send {:?}", out_chunks);
                for out_chunk in out_chunks {
                    let _ = out_chunk.encode(out_stream);
                }
            }
        }
        Ok(())
    }

    fn process_open_secure_channel(&mut self, message: &SupportedMessage) -> std::result::Result<OpenSecureChannelResponse, &'static StatusCode> {
        let request = match *message {
            SupportedMessage::OpenSecureChannelRequest(ref request) => {
                info!("Got secure channel request");
                request
            }
            _ => {
                error!("message is not an open secure channel request, got {:?}", message);
                return Err(&BAD_UNEXPECTED_ERROR);
            }
        };

        // Process the request
        let token_id: UInt32 = 1000; // TODO

        let secure_channel_id = {
            let client_protocol_version = self.client_protocol_version;
            // Must compare protocol version to the one from HELLO
            if request.client_protocol_version != client_protocol_version {
                error!("Client sent a different protocol version than it did in the HELLO - {} vs {}", request.client_protocol_version, client_protocol_version);
                return Err(&BAD_PROTOCOL_VERSION_UNSUPPORTED)
            }

            // Create secure channel info
            self.last_secure_channel_id += 1;
            self.secure_channel_info = SecureChannelInfo {
                security_policy: SecurityPolicy::None,
                secure_channel_id: self.last_secure_channel_id,
                token_id: token_id,
            };
            self.last_secure_channel_id
        };

        let now = DateTime::now();
        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_service_result(&now, &request.request_header, &GOOD),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: secure_channel_id,
                token_id: token_id,
                created_at: now.clone(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: ByteString::from_bytes(&[0u8]),
        };

        debug!("Sending OpenSecureChannelResponse {:?}", response);
        Ok(response)
    }
}


