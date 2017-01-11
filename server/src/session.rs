use std;
use std::net::{TcpStream, Shutdown};
use std::io::{Read, Write, Cursor};
use std::sync::{Arc, Mutex};

use chrono::{self, UTC};

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::*;
use opcua_core::debug::*;

use subscription::{Subscription};

use handshake;

const RECEIVE_BUFFER_SIZE: usize = 32768;
const SEND_BUFFER_SIZE: usize = 32768;
const MAX_MESSAGE_SIZE: usize = 16384;
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
    /// Number of subscriptions open for this session
    pub subscriptions: Vec<Subscription>,
    //    pub incoming_queue: Ve
    //    pub outgoing_queue: Vec<Box<u8>>,
    pub session_config: SessionConfig,
    /// Chunker for encoding / decoding stuff
    pub chunker: Chunker,
    /// Client protocol version set during HELLO
    pub client_protocol_version: UInt32,
    // Last secure channel id
    pub last_secure_channel_id: UInt32,
    // Secure channel info for the session
    pub secure_channel_info: SecureChannelInfo,
}

impl TcpSession {
    pub fn new(session_config: SessionConfig) -> TcpSession {
        TcpSession {
            subscriptions: Vec::new(),
            session_state: SessionState::New,
            session_config: session_config,
            chunker: Chunker::new(),
            client_protocol_version: 0,
            last_secure_channel_id: 0,
            secure_channel_info: SecureChannelInfo {
                security_policy: SecurityPolicy::None,
                secure_channel_id: 0,
            },
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
        let polling_timeout: std::time::Duration = std::time::Duration::from_millis(50);
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

            if bytes_read < 8 {
                // Abort since we're fed garbage
                error!("Got garbage bytes from caller");
                break;
            } else {
                debug!("Received bytes:");
                debug_buffer(&in_buf[0..bytes_read]);

                let mut in_buf_stream = Cursor::new(&in_buf[0..bytes_read]);
                match session_state {
                    SessionState::WaitingHello => {
                        debug!("Processing HELLO");
                        let result = TcpSession::process_hello(session.clone(), &mut in_buf_stream, &mut out_buf_stream);
                        if result.is_err() {
                            session_status_code = result.unwrap_err().clone();
                        }
                    },
                    SessionState::ProcessMessages => {
                        debug!("Processing message");
                        let result = TcpSession::process_message(session.clone(), &mut in_buf_stream, &mut out_buf_stream);
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
            }

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

    fn process_hello(session: Arc<Mutex<TcpSession>>, in_stream: &mut Read, out_stream: &mut Write) -> std::result::Result<(), &'static StatusCode> {
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
        let mut valid_hello = false;
        let mut client_protocol_version = 0;

        let mut message_stream = Cursor::new(buffer);
        if let Ok(hello) = handshake::HelloMessage::decode(&mut message_stream) {
            debug!("Server received HELLO {:?}", hello);
            if !hello.is_endpoint_url_valid() {
                return Err(&BAD_TCP_ENDPOINT_URL_INVALID);
            }
            if !hello.is_valid_buffer_sizes() {
                debug!("HELLO buffer sizes are invalid");
                return Err(&BAD_COMMUNICATION_ERROR);
            }

            // Validate protocol version
            if hello.protocol_version > server_protocol_version {
                return Err(&BAD_PROTOCOL_VERSION_UNSUPPORTED);
            }

            client_protocol_version = hello.protocol_version;
        }

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

        info!("Sending acknowledge -- \n{:?}", acknowledge);
        acknowledge.encode(out_stream);
        Ok(())
    }

    fn process_open_secure_channel(session: &Arc<Mutex<TcpSession>>, chunk: Chunk) -> std::result::Result<Vec<Chunk>, &'static StatusCode> {
        info!("Got secure channel request");
        // Get the actual request
        let chunks = vec![chunk];
        let chunk_info;

        // Get the request
        let client_protocol_version;
        let secure_channel_id;
        let request_id;
        let request: OpenSecureChannelRequest = {
            let mut session = session.lock().unwrap();

            let result = chunks[0].chunk_info(false, None);
            if result.is_err() {
                return Err(result.unwrap_err());
            }
            chunk_info = result.unwrap();

            request_id = chunk_info.sequence_header.request_id;
            client_protocol_version = session.client_protocol_version;

            // Create secure channel info
            session.last_secure_channel_id += 1;
            secure_channel_id = session.last_secure_channel_id;

            session.secure_channel_info = SecureChannelInfo {
                security_policy: SecurityPolicy::None,
                secure_channel_id: secure_channel_id,
            };

            let result = session.chunker.decode_open_secure_channel_request(&chunks);
            if result.is_err() {
                return Err(result.unwrap_err());
            }
            result.unwrap()
        };

        // Must compare protocol version to the one from HELLO
        if request.client_protocol_version != client_protocol_version {
            return Err(&BAD_PROTOCOL_VERSION_UNSUPPORTED)
        }

        let now = DateTime::now();
        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader {
                timestamp: now.clone(),
                request_handle: request.request_header.request_handle,
                service_result: GOOD.clone(),
                service_diagnostics: DiagnosticInfo::new(),
                string_table: UAString::null(),
                additional_header: ExtensionObject::null(),
            },
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                secure_channel_id: secure_channel_id,
                token_id: 0,
                created_at: now.clone(),
                revised_lifetime: 0,
            },
            server_nonce: ByteString::null(),
        };

        {
            debug!("Sending OpenSecureChannelResponse {:?}", response);
            let mut session = session.lock().unwrap();
            let secure_channel_info = session.secure_channel_info.clone();
            let chunker = &mut session.chunker;
            chunker.encode(request_id, &secure_channel_info, &SupportedMessage::OpenSecureChannelResponse(response))
        }
    }

    pub fn process_message(session: Arc<Mutex<TcpSession>>, in_stream: &mut Read, out_stream: &mut Write) -> std::result::Result<(), &'static StatusCode> {
        let result = Chunk::decode(in_stream);

        // Process the message
        let chunk = result.unwrap();
        debug!("Got a chunk {:?}", chunk);

        let result = match chunk.chunk_header.message_type {
            ChunkMessageType::OpenSecureChannel => {
                TcpSession::process_open_secure_channel(&session, chunk)
            },
            ChunkMessageType::CloseSecureChannel => {
                Err(&BAD_UNEXPECTED_ERROR)
            },
            ChunkMessageType::Message => {
                Err(&BAD_UNEXPECTED_ERROR)
            }
        };
        // Send out any chunks that form the response
        if let Ok(chunks) = result {
            debug!("Got some chunks to send {:?}", chunks);
            for ref chunk in chunks {
                chunk.encode(out_stream);
            }
            Ok(())
        } else {
            error!("Got an error instead of chunks {:?}", result);
            Err(result.unwrap_err())
        }
    }
}

