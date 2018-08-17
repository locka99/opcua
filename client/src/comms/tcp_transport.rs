//! The OPC UA TCP transport client module. The transport is responsible for establishing a connection
//! with the server and processing requests.
//!
//! Internally this uses Tokio to process requests and responses supplied by the session via the
//! session state.
use std::thread;
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

#[derive(PartialEq)]
enum ConnectionState {
    // Waiting for ACK
    WaitingForAck,
    // Connection is running
    Processing,
    // Connection is aborted due to IO error
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
    pub state: ConnectionState,
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

    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn send_request(&mut self, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        match self.state {
            ConnectionState::WaitingForAck | ConnectionState::Processing => {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                self.send_buffer.write(request, &mut secure_channel)
            }
            _ => Err(BadNotConnected)
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
    /// This is the handle to the thread
    connection: Option<thread::JoinHandle<()>>,
}

impl TcpTransport {
    /// Create a new TCP transport layer for the session
    pub fn new(certificate_store: Arc<RwLock<CertificateStore>>, session_state: Arc<RwLock<SessionState>>) -> TcpTransport {
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(certificate_store, Role::Client)));
        TcpTransport {
            session_state,
            secure_channel,
            connection: None,
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
        let connection_task = Self::connection_task(addr, endpoint_url.to_string(),
                                                    self.session_state.clone(), self.secure_channel.clone());
        self.connection = Some(thread::spawn(move || {
            tokio::run(connection_task);
        }));

        Ok(())
    }

    /// Disconnects the stream from the server (if it is connected)
    pub fn wait_for_disconnect(&mut self) {
        // Wait for connection to go down
        if let Some(ref mut handle) = self.connection.as_mut() {
            // TODO send a one shot shutdown to the connection
            //handle.join();
        }
        self.connection = None;
    }

    /// Tests if the transport is connected
    pub fn is_connected(&self) -> bool {
        match self.connection {
            None => false,
            Some(ref _handle) => true, // TODO depends on try_join
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
    fn connection_task(addr: SocketAddr, endpoint_url: String, session_state: Arc<RwLock<SessionState>>, secure_channel: Arc<RwLock<SecureChannel>>) -> impl Future<Item=(), Error=()> {
        debug!("Creating a connection task to connect to {} with url {}", addr, endpoint_url);
        TcpStream::connect(&addr).map_err(move |err| {
            error!("Transport IO error {:?}", err);
            BadCommunicationError
        }).and_then(|socket| {
            debug!("Connected..");
            // Make a connection
            let (reader, writer) = socket.split();
            let (receive_buffer_size, send_buffer_size) = {
                let session_state = trace_read_lock_unwrap!(session_state);
                (session_state.receive_buffer_size(), session_state.send_buffer_size())
            };
            let connection = Connection {
                endpoint_url,
                session_state,
                secure_channel,
                state: ConnectionState::WaitingForAck,
                receive_buffer: MessageReader::new(receive_buffer_size),
                send_buffer: MessageWriter::new(writer, send_buffer_size),
                last_received_sequence_number: 0,
                in_buf: Vec::new(),
                reader,
            };
            Ok(connection)
        }).and_then(|mut connection| {
            {
                let session_state = trace_read_lock_unwrap!(connection.session_state);
                connection.send_buffer.write_hello(
                    &connection.endpoint_url, session_state.send_buffer_size(),
                    session_state.receive_buffer_size(), session_state.max_message_size());
                let _ = connection.send_buffer.flush();
            }
            Ok(connection)
        }).and_then(|connection| {
            Self::looping_task(connection)
        }).map_err(move |_| {
            error!("Could not connect to host {}", addr);
            ()
        }).map(|_| ())
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    fn looping_task(connection: Connection) -> impl Future<Item=Connection, Error=StatusCode> {
        // This is the main processing loop that receives and sends messages
        loop_fn(connection, |connection| {
            // The io::read() consumes reader and in_buf so everything else in
            // connection state has to be taken out and put back in afterwards in the map()
            let endpoint_url = connection.endpoint_url.clone();
            let session_state = connection.session_state.clone();
            let secure_channel = connection.secure_channel.clone();
            let reader = connection.reader;
            let in_buf = connection.in_buf;
            let last_received_sequence_number = connection.last_received_sequence_number;
            let receive_buffer = connection.receive_buffer;
            let send_buffer = connection.send_buffer;
            let state = connection.state;
            // Read and process bytes from the stream
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
                                    if connection.state != ConnectionState::WaitingForAck {
                                        error!("Got an unexpected ACK");
                                        session_status_code = BadUnexpectedError;
                                    } else {
                                        // TODO revise our sizes and other things according to the ACK
                                        connection.state = ConnectionState::Processing;
                                    }
                                }
                                Message::MessageChunk(chunk) => {
                                    if connection.state != ConnectionState::Processing {
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
                        connection.state = ConnectionState::Finished(session_status_code);
                    }
                }
                Ok(connection)
            }).and_then(|mut connection| {
                // Process any pending requests
                if connection.state == ConnectionState::Processing {
                    let request = {
                        let mut session_state = trace_write_lock_unwrap!(connection.session_state);
                        session_state.take_request()
                    };
                    if let Some((request, _)) = request {
                        let _ = connection.send_request(request);
                    }
                }
                Ok(connection)
            }).and_then(|mut connection| {
                // Write anything in the out buffer
                let _ = connection.send_buffer.flush();
                Ok(connection)
            }).and_then(|mut connection| {
                if let ConnectionState::Finished(_) = connection.state {
                    debug!("Message processing loop is terminating due to IO error");
                    Ok(Loop::Break(connection))
                } else if {
                    // Test if session wants to abort
                    let session_state = trace_read_lock_unwrap!(connection.session_state);
                    session_state.is_abort()
                } {
                    debug!("Message processing loop is terminating due to session abort");
                    connection.state = ConnectionState::Finished(BadUnexpectedError);
                    Ok(Loop::Break(connection))
                } else {
                    // Read / write messages
                    Ok(Loop::Continue(connection))
                }
            })
        })
    }
}