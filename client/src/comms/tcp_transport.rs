//! The OPC UA TCP transport client module. The transport is responsible for establishing a connection
//! with the server and processing requests.
//!
//! Internally this uses Tokio to process requests and responses supplied by the session via the
//! session state.
use std::thread;
use std::time;
use std::result::Result;
use std::sync::{Arc, RwLock};
use std::net::SocketAddr;

use tokio;
use tokio::net::TcpStream;
use tokio_io::AsyncRead;
use tokio_io::io::{self, ReadHalf};
use futures::Future;
use futures::future::{loop_fn, Loop};
use chrono;

use opcua_types::url::OPC_TCP_SCHEME;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::ChannelSecurityToken;
use opcua_core::prelude::*;
use opcua_core::comms::message_writer::MessageWriter;

use session_state::SessionState;

macro_rules! connection_state {( $s:expr ) => { *trace_read_lock_unwrap!($s) } }
macro_rules! set_connection_state {( $s:expr, $v:expr ) => { *trace_write_lock_unwrap!($s) = $v } }

#[derive(Copy, Clone, PartialEq, Debug)]
enum ConnectionState {
    /// No connect has been made yet
    NotStarted,
    /// Connecting
    Connecting,
    /// Connection success
    Connected,
    /// Ready to send a HELLO message to the server
    ReadyToSendHello,
    // Waiting for ACK from the server
    WaitingForAck,
    // Connection is running
    Processing,
    // Connection is finished, possibly after an error
    Finished(StatusCode),
}

struct Connection {
    /// The url to connect to
    pub endpoint_url: String,
    pub session_state: Arc<RwLock<SessionState>>,
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    /// The messages buffer
    pub receive_buffer: MessageReader,
    pub send_buffer: MessageWriter,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
    pub state: Arc<RwLock<ConnectionState>>,
    /// Raw bytes in buffer
    pub in_buf: Vec<u8>,
    pub reader: ReadHalf<TcpStream>,
}

impl Connection {
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

    fn state(&self) -> ConnectionState {
        connection_state!(self.state)
    }

    fn set_state(&self, state: ConnectionState) {
        set_connection_state!(self.state, state);
    }

    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn send_request(&mut self, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        match self.state() {
            ConnectionState::Processing => {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                self.send_buffer.write(request, &mut secure_channel)
            }
            _ => {
                panic!("Should not be calling this unless in the processing state");
            }
        }
    }
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
    /// Secure channel information
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    /// Connection state - what the connection task is doing
    connection_state: Arc<RwLock<ConnectionState>>,
}

impl TcpTransport {
    /// Create a new TCP transport layer for the session
    pub fn new(certificate_store: Arc<RwLock<CertificateStore>>, session_state: Arc<RwLock<SessionState>>) -> TcpTransport {
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(certificate_store, Role::Client)));
        TcpTransport {
            session_state,
            secure_channel,
            connection_state: Arc::new(RwLock::new(ConnectionState::NotStarted)),
        }
    }

    /// Connects the stream to the specified endpoint
    pub fn connect(&mut self, endpoint_url: &str) -> Result<(), StatusCode> {
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
        if url.scheme() != OPC_TCP_SCHEME || !url.has_host() {
            return Err(BadTcpEndpointUrlInvalid);
        }

        debug!("Connecting to {:?}", url);
        let host = url.host_str().unwrap();
        let port = if let Some(port) = url.port() { port } else { 4840 };

        let addr = {
            let addr = format!("{}:{}", host, port).parse::<SocketAddr>();
            if addr.is_err() {
                return Err(BadTcpEndpointUrlInvalid);
            }
            addr.unwrap()
        };
        assert_eq!(addr.port(), port);
        assert!(addr.is_ipv4());
        // The connection will be serviced on its own thread. When the thread terminates, the connection
        // has also terminated.
        let connection_task = Self::connection_task(addr, self.connection_state.clone(), endpoint_url.to_string(),
                                                    self.session_state.clone(), self.secure_channel.clone());
        let _ = Some(thread::spawn(move || {
            debug!("Client tokio tasks are starting for connection");
            tokio::run(connection_task);
            debug!("Client tokio tasks have stopped for connection");
        }));

        // Poll for the state to indicate connect is ready
        debug!("Waiting for a connect (or failure to connect)");
        loop {
            match connection_state!(self.connection_state) {
                ConnectionState::Processing | ConnectionState::Finished(_) => {
                    debug!("Connected");
                    break;
                }
                _ => {
                    // Still waiting for something to happen
                }
            }
            thread::sleep(time::Duration::from_millis(100))
        }

        Ok(())
    }

    /// Disconnects the stream from the server (if it is connected)
    pub fn wait_for_disconnect(&mut self) {
        debug!("Waiting for a disconnect");
        loop {
            match connection_state!(self.connection_state) {
                ConnectionState::NotStarted | ConnectionState::Finished(_) => {
                    debug!("Disconnected");
                    break;
                }
                _ => {}
            }
        }
    }

    /// Tests if the transport is connected
    pub fn is_connected(&self) -> bool {
        match connection_state!(self.connection_state) {
            ConnectionState::NotStarted | ConnectionState::Connecting | ConnectionState::Finished(_) => {
                false
            }
            _ => {
                true
            }
        }
    }

    /// Sets the security token info received from an issue / renew request
    pub fn set_security_token(&mut self, channel_token: ChannelSecurityToken) {
        trace!("Setting security token {:?}", channel_token);
        let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
        secure_channel.set_security_token(channel_token);
    }

    /// Test if the secure channel token needs to be renewed. The algorithm determines it needs
    /// to be renewed if the issue period has elapsed by 75% or more.
    pub fn should_renew_security_token(&self) -> bool {
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        if secure_channel.token_id() == 0 {
            // panic!("Shouldn't be asking this question, if there is no token id at all");
            false
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

    /// This is the main connection task for a connection.
    fn connection_task(addr: SocketAddr, connection_state: Arc<RwLock<ConnectionState>>, endpoint_url: String, session_state: Arc<RwLock<SessionState>>, secure_channel: Arc<RwLock<SecureChannel>>) -> impl Future<Item=(), Error=()> {
        debug!("Creating a connection task to connect to {} with url {}", addr, endpoint_url);

        let connection_state_for_error = connection_state.clone();

        set_connection_state!(connection_state, ConnectionState::Connecting);
        TcpStream::connect(&addr).map_err(move |err| {
            error!("Could not connect to host {}, {:?}", addr, err);
            set_connection_state!(connection_state_for_error, ConnectionState::Finished(BadCommunicationError));
            ()
        }).and_then(move |socket| {
            set_connection_state!(connection_state, ConnectionState::Connected);
            Self::spawn_looping_task(socket, connection_state, endpoint_url, session_state, secure_channel);
            Ok(())
        })
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    fn spawn_looping_task(socket: TcpStream, connection_state: Arc<RwLock<ConnectionState>>, endpoint_url: String, session_state: Arc<RwLock<SessionState>>, secure_channel: Arc<RwLock<SecureChannel>>) { //-> impl Future<Item=Connection, Error=StatusCode> {
        let (reader, writer) = socket.split();
        let (receive_buffer_size, send_buffer_size) = {
            let session_state = trace_read_lock_unwrap!(session_state);
            (session_state.receive_buffer_size(), session_state.send_buffer_size())
        };

        // We're here so we're ready to send out a hello
        set_connection_state!(connection_state, ConnectionState::ReadyToSendHello);
        let connection = Connection {
            endpoint_url,
            session_state,
            secure_channel,
            state: connection_state,
            receive_buffer: MessageReader::new(receive_buffer_size),
            send_buffer: MessageWriter::new(writer, send_buffer_size),
            last_received_sequence_number: 0,
            in_buf: Vec::new(),
            reader,
        };
        // This is the main processing loop that receives and sends messages
        let looping_task = loop_fn(connection, |connection| {
            // The io::read() consumes reader and in_buf so everything else in
            // connection state has to be taken out and put back in afterwards in the map()
            let endpoint_url = connection.endpoint_url;
            let session_state = connection.session_state;
            let secure_channel = connection.secure_channel;
            let reader = connection.reader;
            let in_buf = connection.in_buf;
            let last_received_sequence_number = connection.last_received_sequence_number;
            let receive_buffer = connection.receive_buffer;
            let send_buffer = connection.send_buffer;
            let state = connection.state;

            // Read and process bytes from the tcp stream
            io::read(reader, in_buf).map_err(move |err| {
                error!("Transport IO error {:?}", err);
                BadCommunicationError
            }).map(move |(reader, in_buf, bytes_read)| {
                // Build a new connection state
                (bytes_read, Connection {
                    endpoint_url,
                    session_state,
                    secure_channel,
                    receive_buffer,
                    send_buffer,
                    last_received_sequence_number,
                    state,
                    reader,
                    in_buf,
                })
            }).and_then(|(bytes_read, mut connection)| {
                // Store bytes the buffer and try to decode into a message
                if bytes_read > 0 {
                    debug!("Read {} bytes", bytes_read);
                    let mut session_status_code = Good;
                    let result = connection.receive_buffer.store_bytes(&connection.in_buf[..bytes_read]);
                    if result.is_err() {
                        session_status_code = result.unwrap_err();
                    } else {
                        let messages = result.unwrap();
                        for message in messages {
                            match message {
                                Message::Acknowledge(ack) => {
                                    debug!("Got ack {:?}", ack);
                                    if connection.state() != ConnectionState::WaitingForAck {
                                        error!("Got an unexpected ACK");
                                        session_status_code = BadUnexpectedError;
                                    } else {
                                        // TODO revise our sizes and other things according to the ACK
                                        connection.set_state(ConnectionState::Processing);
                                    }
                                }
                                Message::MessageChunk(chunk) => {
                                    if connection.state() != ConnectionState::Processing {
                                        error!("Got an unexpected message chunk");
                                        session_status_code = BadUnexpectedError;
                                    } else {
                                        let result = connection.process_chunk(chunk);
                                        if result.is_err() {
                                            session_status_code = result.unwrap_err();
                                        } else if let Some(response) = result.unwrap() {
                                            // Store the response
                                            let mut session_state = trace_write_lock_unwrap!(connection.session_state);
                                            session_state.store_response(response);
                                        }
                                    }
                                }
                                Message::Error(error) => {
                                    // TODO client should go into an error recovery state, dropping the connection and reestablishing it.
                                    session_status_code = if let Ok(status_code) = StatusCode::from_u32(error.error) {
                                        status_code
                                    } else {
                                        BadUnexpectedError
                                    };
                                    error!("Expecting a chunk, got an error message {:?}, reason \"{}\"", session_status_code, error.reason.as_ref());
                                }
                                _ => {
                                    panic!("Expected a recognized message");
                                }
                            }
                        }
                    }
                    if session_status_code.is_bad() {
                        connection.set_state(ConnectionState::Finished(session_status_code));
                    }
                }
                Ok(connection)
            }).and_then(|mut connection| {
                // Process any pending requests
                match connection.state() {
                    ConnectionState::ReadyToSendHello => {
                        error! {"Sending HELLO"};
                        {
                            let session_state = trace_read_lock_unwrap!(connection.session_state);
                            let result = connection.send_buffer.write_hello(
                                &connection.endpoint_url, session_state.send_buffer_size(),
                                session_state.receive_buffer_size(), session_state.max_message_size());
                        }
                        connection.set_state(ConnectionState::WaitingForAck)
                    }
                    ConnectionState::Processing => {
                        error! {"Sending Request"};
                        let request = {
                            let mut session_state = trace_write_lock_unwrap!(connection.session_state);
                            session_state.take_request()
                        };
                        if let Some((request, _)) = request {
                            let _ = connection.send_request(request);
                        }
                    }
                    _ => { /* Other states do not send stuff */ }
                }
                Ok(connection)
            }).and_then(|mut connection| {
                // Write anything in the out buffer
                let _ = connection.send_buffer.flush();
                Ok(connection)
            }).and_then(|mut connection| {
                if let ConnectionState::Finished(_) = connection.state() {
                    debug!("Message processing loop is terminating due to IO error");
                    Ok(Loop::Break(connection))
                } else if {
                    // Test if session wants to abort
                    let session_state = trace_read_lock_unwrap!(connection.session_state);
                    session_state.is_abort()
                } {
                    debug!("Message processing loop is terminating due to session abort");
                    connection.set_state(ConnectionState::Finished(BadUnexpectedError));
                    Ok(Loop::Break(connection))
                } else {
                    // Read / write messages
                    Ok(Loop::Continue(connection))
                }
            })
        }).map_err(move |e| {
            error!("Loop ended with an error {:?}", e);
            ()
        }).map(|_| {
            error!("Loop finished");
            ()
        });
        tokio::spawn(looping_task);
    }
}