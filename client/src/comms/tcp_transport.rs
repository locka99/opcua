use std::thread;
use std::result::Result;
use std::sync::{Arc, RwLock, Mutex};
use std::io::{Read, Write};
use std::net::SocketAddr;

use tokio;
use tokio::net::TcpStream;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{ReadHalf, WriteHalf};
use futures::Future;
use futures::future::{loop_fn, Loop};
use chrono;

use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::ChannelSecurityToken;
use opcua_core::prelude::*;

use session_state::SessionState;

// TODO these need to go, and use session settings
const RECEIVE_BUFFER_SIZE: usize = 1024 * 64;
//const SEND_BUFFER_SIZE: usize = 1024 * 64;
//const MAX_MESSAGE_SIZE: usize = 1024 * 64;
const DEFAULT_SENT_SEQUENCE_NUMBER: UInt32 = 0;
const DEFAULT_RECEIVED_SEQUENCE_NUMBER: UInt32 = 0;
const DEFAULT_REQUEST_ID: UInt32 = 1000;

struct ConnectionState {
    pub endpoint_url: String,
    pub session_state: Arc<RwLock<SessionState>>,
    pub abort: bool,
    pub connected: bool,
    pub finished: bool,
    pub reader: ReadHalf<TcpStream>,
    pub writer: WriteHalf<TcpStream>,
}

/// This is the OPC UA TCP client transport layer
///
/// At its heart it is a tokio task that runs continuously reading and writing data from the connected
/// server. Requests are taken from the session state, responses are given to the session state.
///
/// Reading and writing are split so they are independent of each other.
pub struct TcpTransport {
    /// Session state
    session_state: Arc<RwLock<SessionState>>,
    /// Message buffer where portions of messages are stored to be built into chunks
    message_buffer: MessageBuffer,
    /// Last encoded sequence number
    last_sent_sequence_number: UInt32,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
    /// Flag indicating abort
    abort: bool,
    /// Secure channel information
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    /// Last request id, used to track async requests
    last_request_id: UInt32,
    /// Receive buffer for incoming bytes. Note the Arc/Mutex is a workaround of the borrow
    /// rules that complain about us reading from a mutable stream into a mutable buffer belonging
    /// to the same instance of Self. It could probably be fixed some other way.
    receive_buffer: Arc<Mutex<Vec<u8>>>,
}

impl TcpTransport {
    /// Create a new TCP transport layer for the session
    pub fn new(certificate_store: Arc<RwLock<CertificateStore>>, session_state: Arc<RwLock<SessionState>>) -> TcpTransport {
        let receive_buffer_size = {
            let session_state = trace_read_lock_unwrap!(session_state);
            session_state.receive_buffer_size
        };

        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(certificate_store, Role::Client)));

        TcpTransport {
            session_state,
            message_buffer: MessageBuffer::new(receive_buffer_size),
            last_sent_sequence_number: DEFAULT_SENT_SEQUENCE_NUMBER,
            last_received_sequence_number: DEFAULT_RECEIVED_SEQUENCE_NUMBER,
            last_request_id: DEFAULT_REQUEST_ID,
            secure_channel,
            abort: false,
            receive_buffer: Arc::new(Mutex::new(vec![0u8; RECEIVE_BUFFER_SIZE])),
        }
    }

    fn connection_task(addr: SocketAddr, endpoint_url: String, session_state: Arc<RwLock<SessionState>>) -> impl Future<Item = (), Error=()> {
        debug!("Creating a connection task to connect to {} with url {}", addr, endpoint_url);
        TcpStream::connect(&addr)
            .and_then(|socket| {
                debug!("Connected..");
                // Make a connection state
                let (reader, writer) = socket.split();
                let connection_state = ConnectionState {
                    endpoint_url,
                    session_state,
                    connected: false,
                    finished: false,
                    abort: false,
                    reader,
                    writer,
                };
                Ok(connection_state)
            })
            .and_then(|mut connection_state| {
                let msg = {
                    let session_state = trace_read_lock_unwrap!(connection_state.session_state);
                    HelloMessage::new(&connection_state.endpoint_url,
                                      session_state.send_buffer_size as UInt32,
                                      session_state.receive_buffer_size as UInt32,
                                      session_state.max_message_size as UInt32)
                };
                debug!("Sending HEL {:?}", msg);
                let _ = msg.encode(&mut connection_state.writer);
                debug!("Waiting for ACK");
                Ok(connection_state)
            })
            .and_then(|mut connection_state| {
                let ack = AcknowledgeMessage::decode(&mut connection_state.reader);
                // Process ack
                debug!("Got ACK {:?}", ack);
                Ok(connection_state)
            })
            .and_then(|mut connection_state| {
                // open_secure_channel
                Ok(connection_state)
            })
            .and_then(|mut connection_state| {
                // This is the main processing loop that receives and sends messages
                loop_fn(connection_state, move |mut connection_state| {
                    if connection_state.abort {
                        debug!("Message processing loop is terminating due to abort");
                        Ok(Loop::Break(connection_state))
                    } else {
                        // If connection broken
                        // Loop::Break(connection_state)


                        // Read / write messages
                        Ok(Loop::Continue(connection_state))
                    }
                })
            })
            .and_then(|mut connection_state| {
                // TODO clean up session state - wipe out all requests, responses
                // put session state into disconnected
                Ok(connection_state)
            })
            .map_err(move |_| {
                error!("Could not connect to host {}", addr);
            })
            .map(|_| {})
    }

    /// Connects the stream to the specified endpoint
    pub fn connect(&mut self, endpoint_url: &str) -> Result<thread::JoinHandle<()>, StatusCode> {
        if self.is_connected() {
            panic!("Should not try to connect when already connected");
        }

        use url::Url;

        // Validate and split out the endpoint we have
        let result = Url::parse(&endpoint_url);
        if result.is_err() {
            return Err(BadTcpEndpointUrlInvalid);
        }
        let url = result.unwrap();
        if url.scheme() != "opc.tcp" || !url.has_host() {
            return Err(BadTcpEndpointUrlInvalid);
        }

        debug!("Connecting to {:?}", url);
        let host = url.host_str().unwrap();
        let port = if let Some(port) = url.port() { port } else { 4840 };

        let addr = format!("{}:{}", host, port).parse::<SocketAddr>();
        if addr.is_err() {
            return Err(BadTcpEndpointUrlInvalid);
        }

        // The connection will be serviced on its own thread. When the thread terminates, the connection
        // has also terminated.
        let addr = addr.unwrap();
        let connection_task = Self::connection_task(addr, endpoint_url.to_string(), self.session_state.clone());
        let thread = thread::spawn(move || {
            tokio::run(connection_task);
        });
        Ok(thread)
    }

    /// Disconnects the stream from the server (if it is connected)
    pub fn disconnect(&mut self) {
        self.last_sent_sequence_number = DEFAULT_SENT_SEQUENCE_NUMBER;
        self.last_received_sequence_number = DEFAULT_RECEIVED_SEQUENCE_NUMBER;
        self.last_request_id = DEFAULT_REQUEST_ID;
    }

    /// Tests if the transport is connected
    pub fn is_connected(&self) -> bool {
        // The assumption is that if a read/write fails, the code that called those functions
        // will set the stream to None if it breaks.
        // TODO self.stream.is_some()
        true
    }

    /// Sets the security token info received from an issue / renew request
    pub fn set_security_token(&mut self, channel_token: ChannelSecurityToken) {
        trace!("Setting security token {:?}", channel_token);
        let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
        secure_channel.set_security_token(channel_token);
    }

    /// Test if the secure channel token needs to be renewed. The algorithm determines it needs
    /// to be renewed if the issue period has elapsed by 75% or more.
    fn should_renew_security_token(&self) -> bool {
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        if secure_channel.token_id() == 0 {
            panic!("Shouldn't be asking this question, if there is no token id at all");
        } else {
            let now = chrono::Utc::now();

            // Check if secure channel 75% close to expiration in which case send a renew
            let renew_lifetime = (secure_channel.token_lifetime() * 3) / 4;
            let created_at = secure_channel.token_created_at().into();
            let renew_lifetime = chrono::Duration::milliseconds(renew_lifetime as i64);

            // Renew the token?
            now.signed_duration_since(created_at) > renew_lifetime
        }
    }

    fn turn_received_chunks_into_message(&mut self, chunks: &Vec<MessageChunk>) -> Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        self.last_received_sequence_number = Chunker::validate_chunks(self.last_received_sequence_number + 1, &secure_channel, chunks)?;
        // Now decode
        Chunker::decode(&chunks, &secure_channel, None)
    }

    fn process_chunk(&mut self, chunk: MessageChunk) -> Result<Option<SupportedMessage>, StatusCode> {
        // trace!("Got a chunk {:?}", chunk);
        let chunk = {
            let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
            secure_channel.verify_and_remove_security(&chunk.data)?
        };
        let message_header = chunk.message_header()?;
        match message_header.is_final {
            MessageIsFinalType::Intermediate => {
                panic!("We don't support intermediate chunks yet");
            }
            MessageIsFinalType::FinalError => {
                info!("Discarding chunk marked in as final error");
                return Ok(None);
            }
            _ => {
                // Drop through
            }
        }

        // TODO test chunk message type and either push to queue, turn to message or clear
        let in_chunks = vec![chunk];
        let message = self.turn_received_chunks_into_message(&in_chunks)?;

        Ok(Some(message))
    }

    pub fn run(&mut self, non_blocking: bool, request_timeout: UInt32) -> Result<SupportedMessage, StatusCode> {
        unimplemented!("gone");


        /*

            // This loop terminates when the corresponding response comes back or a timeout occurs
            let session_status_code;
            let start = chrono::Utc::now();

            let receive_buffer = self.receive_buffer.clone();
            let mut receive_buffer = trace_lock_unwrap!(receive_buffer);

            let mut total_bytes_read = 0;

            let _ = self.stream().set_read_timeout(if non_blocking { Some(time::Duration::from_millis(100)) } else { None });

            'message_loop: while !self.abort {
                // Send pending request
                {
                    if let Some(request) = session_state.next_request() {
                        // Send the request
                        session_state.add_pending_request(request.request_handle());
                        self.async_send_request(request);
                    }
                }

                // Check for pending response
                {

                    // Check for a timeout
                    let now = chrono::Utc::now();
                    let request_duration = now.signed_duration_since(start);
                    if request_duration.num_milliseconds() >= request_timeout as i64 {
                        debug!("Time waiting {}ms exceeds timeout {}ms waiting for response ",
                               request_duration.num_milliseconds(), request_timeout);
                        session_status_code = BadTimeout;
                        break;
                    }

                    // decode response
                    loop {
                        let bytes_read_result = self.stream().read(&mut receive_buffer);
                        if let Err(error) = bytes_read_result {
                            match error.kind() {
                                ErrorKind::TimedOut => {
                                    continue;
                                }
                                ErrorKind::WouldBlock => {
                                    if total_bytes_read == 0 {
                                        // No bytes read yet
                                        continue;
                                    } else {}
                                }
                                _ => {}
                            }

                            // TODO check for broken socket. if this occurs, the code should go into an error
                            // recovery state

                            debug!("Read error - kind = {:?}, {:?}", error.kind(), error);
                            self.stream = None;
                            session_status_code = BadUnexpectedError;
                            break;
                        }
                        let bytes_read = bytes_read_result.unwrap();
                        if bytes_read == 0 {
                            continue;
                        }
                        trace!("Bytes read = {}", bytes_read);
                        total_bytes_read += bytes_read;
                        let result = self.message_buffer.store_bytes(&receive_buffer[0..bytes_read]);
                        if result.is_err() {
                            session_status_code = result.unwrap_err();
                            break;
                        }
                        let messages = result.unwrap();
                        for message in messages {
                            match message {
                                Message::MessageChunk(chunk) => {
                                    if let Some(result) = self.process_chunk(chunk)? {
                                        return Ok(result);
                                    }
                                }
                                Message::Error(error_message) => {
                                    // TODO if this is an ERROR chunk, then the client should go into an error
                                    // recovery state, dropping the connection and reestablishing it.
                                    session_status_code = if let Ok(status_code) = StatusCode::from_u32(error_message.error) {
                                        status_code
                                    } else {
                                        BadUnexpectedError
                                    };
                                    error!("Expecting a chunk, got an error message {:?}, reason \"{}\"", session_status_code, error_message.reason.as_ref());
                                    break 'message_loop;
                                }
                                message => {
                                    // This is not a regular message, or an error so what is happening?
                                    error!("Expecting a chunk, got something that was not a chunk or even an error - {:?}", message);
                                    session_status_code = BadUnexpectedError;
                                    break 'message_loop;
                                }
                            }
                        }
                    }
                }
                // TODO error recovery state
            }
            Err(session_status_code)
      */
    }

    fn next_request_id(&mut self) -> UInt32 {
        self.last_request_id += 1;
        self.last_request_id
    }

    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn async_send_request(&mut self, request: SupportedMessage, connection_state: &mut ConnectionState) -> Result<UInt32, StatusCode> {
        if !self.is_connected() {
            return Err(BadServerNotConnected);
        }

        let request_id = self.next_request_id();

        // TODO This needs to wait for up to the timeout hint in the request header for a response
        // with the same request handle to return. Other messages might arrive during that, so somehow
        // we have to deal with that situation too, e.g. queuing them up.

        trace!("Sending request");

        // Turn message to chunk(s)
        // TODO max message size and max chunk size
        let chunks = {
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
            Chunker::encode(self.last_sent_sequence_number + 1, request_id, 0, 0, &secure_channel, &request)?
        };

        // Sequence number monotonically increases per chunk
        self.last_sent_sequence_number += chunks.len() as UInt32;

        // Send chunks
        let max_chunk_size = 32768; // FIXME TODO
        let mut data = vec![0u8; max_chunk_size + 1024];
        for chunk in chunks {
            trace!("Sending chunk of type {:?}", chunk.message_header()?.message_type);
            let size = {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                secure_channel.apply_security(&chunk, &mut data)
            };
            match size {
                Ok(size) => {
                    let bytes_written_result = connection_state.writer.write(&data[..size]);
                    if let Err(error) = bytes_written_result {
                        error!("Error while writing bytes to stream, connection broken, check error {:?}", error);
                        break;
                    }
                }
                Err(err) => {
                    panic!("Applying security to chunk failed - {:?}", err);
                }
            }
        }

        trace!("Request sent");

        Ok(request_id)
    }
}