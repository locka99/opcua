use std;
use std::net::{TcpStream, Shutdown};
use std::io::{Read, Write, Cursor};
use std::sync::{Arc, Mutex};

use chrono::{self, UTC};

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::*;
use opcua_core::services::secure_channel::*;
use opcua_core::debug::*;

use handshake;
use message_handler::*;

const RECEIVE_BUFFER_SIZE: usize = 32768;
const SEND_BUFFER_SIZE: usize = 32768;
const MAX_MESSAGE_SIZE: usize = 32768;
const MAX_CHUNK_COUNT: usize = 1;

#[derive(Clone, Debug, PartialEq)]
pub enum SessionState {
    New,
    WaitingHello,
    ProcessMessages,
    Finished
}

pub struct SessionConfig {
    /// The hello timeout setting
    pub hello_timeout: u32,
}

pub struct TcpSession {
    /// The current session state
    pub session_state: SessionState,
    //    pub incoming_queue: Ve
    //    pub outgoing_queue: Vec<Box<u8>>,
    pub session_config: SessionConfig,
    /// Message handler
    pub message_handler: MessageHandler,
    /// Client protocol version set during HELLO
    pub client_protocol_version: UInt32,
    // Last secure channel id
    pub last_secure_channel_id: UInt32,
    // Secure channel info for the session
    pub secure_channel_info: SecureChannelInfo,
    /// Last encoded sequence number
    pub last_encoded_sequence_number: Int32,
    /// Last decoded sequence number
    pub last_decoded_sequence_number: Int32,
}

impl TcpSession {
    pub fn new(session_config: SessionConfig) -> TcpSession {
        TcpSession {
            session_state: SessionState::New,
            session_config: session_config,
            client_protocol_version: 0,
            last_secure_channel_id: 0,
            secure_channel_info: SecureChannelInfo {
                security_policy: SecurityPolicy::None,
                secure_channel_id: 0,
            },
            message_handler: MessageHandler::new(),
            last_encoded_sequence_number: -1,
            last_decoded_sequence_number: -1,
        }
    }

    pub fn run(mut stream: TcpStream, session: Arc<Mutex<TcpSession>>) {
        // ENTRY POINT TO ALL OF OPC

        let session_start_time = UTC::now();
        info!("Session started {}", session_start_time);

        let hello_timeout;
        {
            let mut session = session.lock().unwrap();
            session.session_state = SessionState::WaitingHello;
            hello_timeout = chrono::Duration::seconds(session.session_config.hello_timeout as i64);
        }

        // Short timeout makes it work like a polling loop
        let polling_timeout: std::time::Duration = std::time::Duration::from_millis(200);
        stream.set_read_timeout(Some(polling_timeout));

        let mut in_buf = vec![0u8; RECEIVE_BUFFER_SIZE];
        let mut out_buf_stream = Cursor::new(vec![0u8; SEND_BUFFER_SIZE]);

        // Format of OPC UA TCP is defined in OPC UA Part 6 Chapter 7
        // Basic startup is a HELLO,  OpenSecureChannel, begin

        let mut session_status_code = GOOD.clone();

        let mut keep_alive_timeout: i32 = 0;
        let mut last_keep_alive = UTC::now();

        loop {
            let session_state = {
                let session = session.lock().unwrap();
                session.session_state.clone()
            };

            // Session waits a configurable time for a hello and terminates if it fails to receive it
            let now = UTC::now();
            if session_state == SessionState::WaitingHello {
                if now - session_start_time > hello_timeout {
                    error!("Session timed out waiting for hello");
                    session_status_code = BAD_TIMEOUT.clone();
                    break;
                }
            } else {
                // Check if the keep alive has been exceeded
                let keep_alive_duration = now - last_keep_alive;
                // TODO check if keep_alive_duration exceeds the timeout value
            }

            // Try to read, using timeout as a polling mechanism
            let bytes_read_result = stream.read(&mut in_buf);
            if bytes_read_result.is_err() {
                let error = bytes_read_result.unwrap_err();
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
                SessionState::WaitingHello => {
                    debug!("Processing HELLO");
                    let result = TcpSession::process_hello(&session, &mut in_buf_stream, &mut out_buf_stream);
                    if result.is_err() {
                        session_status_code = result.unwrap_err().clone();
                    }
                },
                SessionState::ProcessMessages => {
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
            last_keep_alive = now.clone();

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
            error.encode(&mut out_buf_stream);
            TcpSession::write_output(&mut out_buf_stream, &mut stream);
            stream.flush();
        }

        // Close socket
        info!("Terminating socket");
        let _ = stream.shutdown(Shutdown::Both);

        // Session state
        {
            let mut session = session.lock().unwrap();
            session.session_state = SessionState::Finished;
        }

        let session_duration = UTC::now() - session_start_time;
        info!("Session is finished {:?}", session_duration)
    }

    fn write_output(out_stream: &mut Cursor<Vec<u8>>, stream: &mut Write) {
        if out_stream.position() == 0 {
            return;
        }
        {
            let bytes_to_write = out_stream.position() as usize;
            let out_buf_slice = &out_stream.get_ref()[0..bytes_to_write];

            debug!("Writing bytes to client:");
            debug_buffer(out_buf_slice);

            let _ = stream.write(out_buf_slice);
        }
        out_stream.set_position(0);
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
            session.session_state = SessionState::ProcessMessages;
            session.client_protocol_version = client_protocol_version;
        }

        info!("Sending acknowledge -- \n{:#?}", acknowledge);
        acknowledge.encode(out_stream);
        Ok(())
    }

    pub fn chunks_to_message(session: &Arc<Mutex<TcpSession>>, chunks: &Vec<Chunk>) -> std::result::Result<SupportedMessage, &'static StatusCode> {
        let mut session = session.lock().unwrap();

        let chunk_info = chunks[0].chunk_info(true, Option::None)?;
        debug!("Chunker::decode chunk_info = {:?}", chunk_info);

        // Check the sequence id - should be larger than the last one decoded
        if chunk_info.sequence_header.sequence_number as Int32 <= session.last_decoded_sequence_number {
            error!("Chunk has a sequence number of {} which is less than last deoded sequence number of {}", chunk_info.sequence_header.sequence_number, session.last_decoded_sequence_number);
            return Err(&BAD_SEQUENCE_NUMBER_INVALID);
        }
        session.last_decoded_sequence_number = chunk_info.sequence_header.sequence_number as Int32;

        Chunker::decode(&chunks, None)
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
        let message = TcpSession::chunks_to_message(session, &in_chunks)?;
        let response = match chunk_message_type {
            ChunkMessageType::OpenSecureChannel => {
                SupportedMessage::OpenSecureChannelResponse(TcpSession::process_open_secure_channel(&session, &message)?)
            },
            ChunkMessageType::CloseSecureChannel => {
                SupportedMessage::CloseSecureChannelResponse(TcpSession::process_close_secure_channel(&session, &message)?)
            },
            ChunkMessageType::Message => {
                let session = session.lock().unwrap();
                session.message_handler.handle_message(&message)?
            }
        };

        {
            let mut session = session.lock().unwrap();

            let mut secure_channel_info = session.secure_channel_info.clone();
            let chunk_info = in_chunks[0].chunk_info(true, Some(&mut secure_channel_info))?;
            let request_id = chunk_info.sequence_header.request_id;

            let sequence_number = (session.last_encoded_sequence_number + 1) as UInt32;
            session.last_encoded_sequence_number = sequence_number as Int32;

            let out_chunks = Chunker::encode(sequence_number, request_id, &secure_channel_info, &response)?;
            session.secure_channel_info = secure_channel_info;

            // Send out any chunks that form the response
            debug!("Got some chunks to send {:?}", out_chunks);
            for out_chunk in out_chunks {
                out_chunk.encode(out_stream);
            }
            Ok(())
        }
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
            };
            session.last_secure_channel_id
        };

        let now = DateTime::now();
        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new(&now, request.request_header.request_handle),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                secure_channel_id: secure_channel_id,
                token_id: 0,
                created_at: now.clone(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: ByteString::null(),
        };

        debug!("Sending OpenSecureChannelResponse {:#?}", response);
        Ok(response)
    }

    fn process_close_secure_channel(session: &Arc<Mutex<TcpSession>>, message: &SupportedMessage) -> std::result::Result<CloseSecureChannelResponse, &'static StatusCode> {
        let request = match *message {
            SupportedMessage::CloseSecureChannelRequest(ref request) => {
                info!("Got close secure channel request");
                request
            },
            _ => {
                error!("message is not a close secure channel request, got {:?}", message);
                return Err(&BAD_UNEXPECTED_ERROR);
            }
        };

        let now = DateTime::now();
        let response = CloseSecureChannelResponse {
            response_header: ResponseHeader::new(&now, request.request_header.request_handle),
        };
        Ok(response)
    }
}

