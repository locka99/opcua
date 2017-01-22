use std;
use std::net::{TcpStream, Shutdown};
use std::io::{Read, Write, Cursor, ErrorKind};
use std::sync::{Arc, Mutex};

use chrono::{self, UTC};

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::*;
use opcua_core::debug::*;

use server::ServerState;
use handshake;
use message_handler::*;

const RECEIVE_BUFFER_SIZE: usize = 32768;
const SEND_BUFFER_SIZE: usize = 32768;
const MAX_MESSAGE_SIZE: usize = 32768;
const MAX_CHUNK_COUNT: usize = 1;

#[derive(Clone, Debug, PartialEq)]
pub enum TcpSessionState {
    New,
    WaitingHello,
    ProcessMessages,
    Finished
}

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Session state is anything associated with the session at the message / service level
#[derive(Clone)]
pub struct SessionState {
    pub session_info: Option<SessionInfo>
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_info: None,
        }
    }
}

pub struct TcpSession {
    // Server state, address space etc.
    pub server_state: ServerState,
    // Session state - open sessions, tokens etc
    pub session_state: Arc<Mutex<SessionState>>,
    /// Session state is anything related to this connection
    /// The current session state
    pub tcp_session_state: TcpSessionState,
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

impl TcpSession {
    pub fn new(server_state: &ServerState) -> TcpSession {
        let session_state = Arc::new(Mutex::new(SessionState::new()));
        TcpSession {
            server_state: server_state.clone(),
            session_state: session_state.clone(),
            tcp_session_state: TcpSessionState::New,
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

    pub fn run(mut stream: TcpStream, session: Arc<Mutex<TcpSession>>) {
        // ENTRY POINT TO ALL OF OPC

        let session_start_time = UTC::now();
        info!("Session started {}", session_start_time);

        // Waiting for hello
        {
            let mut session = session.lock().unwrap();
            session.tcp_session_state = TcpSessionState::WaitingHello;
        }

        // Hello timeout
        let hello_timeout = {
            let hello_timeout = {
                let session = session.lock().unwrap();
                let server_config = session.server_state.config.lock().unwrap();
                server_config.tcp_config.hello_timeout as i64
            };
            chrono::Duration::seconds(hello_timeout)
        };

        // Short timeout makes it work like a polling loop
        let polling_timeout: std::time::Duration = std::time::Duration::from_millis(200);
        let _ = stream.set_read_timeout(Some(polling_timeout));
        let _ = stream.set_nodelay(true);

        let mut in_buf = vec![0u8; RECEIVE_BUFFER_SIZE];
        let mut out_buf_stream = Cursor::new(vec![0u8; SEND_BUFFER_SIZE]);

        // Format of OPC UA TCP is defined in OPC UA Part 6 Chapter 7
        // Basic startup is a HELLO,  OpenSecureChannel, begin

        let mut session_status_code = GOOD.clone();

        loop {
            let session_state = {
                let session = session.lock().unwrap();
                session.tcp_session_state.clone()
            };

            // Session waits a configurable time for a hello and terminates if it fails to receive it
            let now = UTC::now();
            if session_state == TcpSessionState::WaitingHello {
                if now - session_start_time > hello_timeout {
                    error!("Session timed out waiting for hello");
                    session_status_code = BAD_TIMEOUT.clone();
                    break;
                }
            }

            // TODO this code is incredibly flimsy, assuming an entire chunk is read in one single go
            // it should change to reading bytes into a buffer, and then analysing a buffer to see if
            // there is a chunk header with a message size and bytes for the entire message. If there
            // is the chunk should be extracted and the buffer shifted up.

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

            debug!("Received bytes:");
            debug_buffer(&in_buf[0..bytes_read]);

            let mut in_buf_stream = Cursor::new(&in_buf[0..bytes_read]);
            match session_state {
                TcpSessionState::WaitingHello => {
                    debug!("Processing HELLO");
                    let result = TcpSession::process_hello(&session, &mut in_buf_stream, &mut out_buf_stream);
                    if result.is_err() {
                        session_status_code = result.unwrap_err().clone();
                    }
                },
                TcpSessionState::ProcessMessages => {
                    debug!("Processing message");
                    let result = TcpSession::process_chunk(&session, &mut in_buf_stream, &mut out_buf_stream);
                    if result.is_err() {
                        session_status_code = result.unwrap_err().clone();
                    }
                },
                _ => {
                    error!("Unknown sesion state, aborting");
                    session_status_code = BAD_UNEXPECTED_ERROR.clone();
                }
            };

            // Anything to write?
            TcpSession::write_output(&mut out_buf_stream, &mut stream);
            if !session_status_code.is_good() {
                error!("Session is aborting due to bad session status {:?}", session_status_code);
                break;
            }
        }

        // As a final act, the session sends a status code to the client if it can
        if session_status_code != GOOD {
            warn!("Sending session terminating error --\n{:?}", session_status_code);
            out_buf_stream.set_position(0);
            let error = handshake::ErrorMessage::from_status_code(&session_status_code);
            let _ = error.encode(&mut out_buf_stream);
            TcpSession::write_output(&mut out_buf_stream, &mut stream);
        }

        // Close socket
        info!("Terminating socket");
        let _ = stream.shutdown(Shutdown::Both);

        // Session state
        {
            let mut session = session.lock().unwrap();
            session.tcp_session_state = TcpSessionState::Finished;
        }

        let session_duration = UTC::now() - session_start_time;
        info!("Session is finished {:?}", session_duration)
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

    fn process_hello<R: Read, W: Write>(session: &Arc<Mutex<TcpSession>>, in_stream: &mut R, out_stream: &mut W) -> std::result::Result<(), &'static StatusCode> {
        let buffer = handshake::MessageHeader::read_bytes(in_stream);
        if buffer.is_err() {
            error!("Error processing HELLO");
            return Err(&BAD_COMMUNICATION_ERROR);
        }
        let buffer = buffer.unwrap();

        // Now make sure it's a Hello message, not something else
        if handshake::MessageHeader::message_type(&buffer[0..4]) != handshake::MessageType::Hello {
            debug!("Header is not for a HELLO");
            return Err(&BAD_COMMUNICATION_ERROR);
        }

        let server_protocol_version = 0;
        let mut client_protocol_version = 0;

        let mut message_stream = Cursor::new(buffer);
        if let Ok(hello) = handshake::HelloMessage::decode(&mut message_stream) {
            debug!("Server received HELLO {:#?}", hello);
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

            client_protocol_version = hello.protocol_version;
        }

        // Send acknowledge
        let mut acknowledge = handshake::AcknowledgeMessage {
            message_header: handshake::MessageHeader::new(handshake::MessageType::Acknowledge),
            protocol_version: server_protocol_version,
            receive_buffer_size: RECEIVE_BUFFER_SIZE as UInt32,
            send_buffer_size: SEND_BUFFER_SIZE as UInt32,
            max_message_size: MAX_MESSAGE_SIZE as UInt32,
            max_chunk_count: MAX_CHUNK_COUNT as UInt32,
        };
        acknowledge.message_header.message_size = acknowledge.byte_len() as UInt32;

        {
            let mut session = session.lock().unwrap();
            session.tcp_session_state = TcpSessionState::ProcessMessages;
            session.client_protocol_version = client_protocol_version;
        }

        info!("Sending acknowledge -- \n{:#?}", acknowledge);
        let _ = acknowledge.encode(out_stream);
        Ok(())
    }

    pub fn turn_received_chunks_into_message(session: &Arc<Mutex<TcpSession>>, chunks: &Vec<Chunk>) -> std::result::Result<SupportedMessage, &'static StatusCode> {
        let mut session = session.lock().unwrap();

        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let mut last_sequence_number = session.last_received_sequence_number;
        let mut first_chunk = true;
        for chunk in chunks {
            let chunk_info = chunk.chunk_info(first_chunk, &session.secure_channel_info)?;
            // Check the sequence id - should be larger than the last one decoded
            if chunk_info.sequence_header.sequence_number <= last_sequence_number {
                error!("Chunk has a sequence number of {} which is less than last decoded sequence number of {}", chunk_info.sequence_header.sequence_number, last_sequence_number);
                return Err(&BAD_SEQUENCE_NUMBER_INVALID);
            }
            last_sequence_number = chunk_info.sequence_header.sequence_number;

            // Validate that the last chunk is final and all previous chunks are intermediate
            // TODO

            first_chunk = false;
        }
        session.last_received_sequence_number = last_sequence_number;

        // Now decode
        Chunker::decode(&chunks, &session.secure_channel_info, None)
    }

    pub fn process_chunk<R: Read, W: Write>(session: &Arc<Mutex<TcpSession>>, in_stream: &mut R, out_stream: &mut W) -> std::result::Result<(), &'static StatusCode> {
        let result = Chunk::decode(in_stream);

        // Process the message
        let chunk = result.unwrap();
        debug!("Got a chunk {:?}", chunk);

        if chunk.chunk_header.chunk_type == ChunkType::Intermediate {
            panic!("We don't support intermediate chunks yet");
        } else if chunk.chunk_header.chunk_type == ChunkType::FinalError {
            info!("Discarding chunk marked in as final error");
            return Ok(())
        }

        let chunk_message_type = chunk.chunk_header.message_type.clone();

        let in_chunks = vec![chunk];
        let message = TcpSession::turn_received_chunks_into_message(session, &in_chunks)?;
        let response = match chunk_message_type {
            ChunkMessageType::OpenSecureChannel => {
                SupportedMessage::OpenSecureChannelResponse(TcpSession::process_open_secure_channel(&session, &message)?)
            },
            ChunkMessageType::CloseSecureChannel => {
                info!("CloseSecureChannelRequest received, session closing");
                return Err(&BAD_CONNECTION_CLOSED);
            },
            ChunkMessageType::Message => {
                let mut session = session.lock().unwrap();
                session.message_handler.handle_message(&message)?
            }
        };

        // Send the response
        {
            let mut session = session.lock().unwrap();

            // Get the request id out of the request
            let chunk_info = in_chunks[0].chunk_info(true, &session.secure_channel_info)?;
            let request_id = chunk_info.sequence_header.request_id;

            // Prepare some chunks starting from the sequence number + 1
            debug!("Response to send: {:#?}", response);

            let sequence_number = session.last_sent_sequence_number + 1;
            let out_chunks = Chunker::encode(sequence_number, request_id, &session.secure_channel_info, &response)?;
            session.last_sent_sequence_number = sequence_number + out_chunks.len() as UInt32 - 1;

            // Send out any chunks that form the response
            debug!("Got some chunks to send {:?}", out_chunks);
            for out_chunk in out_chunks {
                let _ = out_chunk.encode(out_stream);
            }
        }

        Ok(())
    }

    fn process_open_secure_channel(session: &Arc<Mutex<TcpSession>>, message: &SupportedMessage) -> std::result::Result<OpenSecureChannelResponse, &'static StatusCode> {
        let request = match *message {
            SupportedMessage::OpenSecureChannelRequest(ref request) => {
                info!("Got secure channel request");
                request
            },
            _ => {
                error!("message is not an open secure channel request, got {:?}", message);
                return Err(&BAD_UNEXPECTED_ERROR);
            }
        };

        // Process the request
        let token_id: UInt32 = 1000; // TODO

        let secure_channel_id = {
            let mut session = session.lock().unwrap();
            let client_protocol_version = session.client_protocol_version;
            // Must compare protocol version to the one from HELLO
            if request.client_protocol_version != client_protocol_version {
                error!("Client sent a different protocol version than it did in the HELLO - {} vs {}", request.client_protocol_version, client_protocol_version);
                return Err(&BAD_PROTOCOL_VERSION_UNSUPPORTED)
            }

            // Create secure channel info
            session.last_secure_channel_id += 1;
            session.secure_channel_info = SecureChannelInfo {
                security_policy: SecurityPolicy::None,
                secure_channel_id: session.last_secure_channel_id,
                token_id: token_id,
            };
            session.last_secure_channel_id
        };

        let now = DateTime::now();
        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new(&now, request.request_header.request_handle),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: secure_channel_id,
                token_id: token_id,
                created_at: now.clone(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: ByteString::null(),
        };

        debug!("Sending OpenSecureChannelResponse {:#?}", response);
        Ok(response)
    }
}

