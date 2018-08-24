//! The OPC UA TCP transport client module. The transport is responsible for establishing a connection
//! with the server and processing requests.
//!
//! Internally this uses Tokio to process requests and responses supplied by the session via the
//! session state.
use std::thread;
use std::time;
use std::result::Result;
use std::sync::{Arc, RwLock, Mutex};
use std::net::SocketAddr;

use tokio;
use tokio::net::TcpStream;
use tokio_io::AsyncRead;
use tokio_io::io::{self, ReadHalf, WriteHalf};
use futures::{Future, Stream};
use futures::future::{self, loop_fn, Loop};
use futures::sync::mpsc::UnboundedReceiver;

use opcua_types::url::OPC_TCP_SCHEME;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_core::prelude::*;
use opcua_core::comms::message_writer::MessageWriter;

use session_state::SessionState;
use message_queue::MessageQueue;

macro_rules! connection_state {( $s:expr ) => { *trace_read_lock_unwrap!($s) } }
macro_rules! set_connection_state {( $s:expr, $v:expr ) => { *trace_write_lock_unwrap!($s) = $v } }

const WAIT_POLLING_TIMEOUT: u64 = 100;

#[derive(Copy, Clone, PartialEq, Debug)]
enum ConnectionState {
    /// No connect has been made yet
    NotStarted,
    /// Connecting
    Connecting,
    /// Connection success
    Connected,
    // Waiting for ACK from the server
    WaitingForAck,
    // Connection is running
    Processing,
    // Connection is finished, possibly after an error
    Finished(StatusCode),
}

struct ReadState {
    pub state: Arc<RwLock<ConnectionState>>,
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    pub message_queue: Arc<RwLock<MessageQueue>>,
    pub reader: ReadHalf<TcpStream>,
    /// The messages buffer
    pub receive_buffer: MessageReader,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
    /// Raw bytes in buffer
    pub in_buf: Vec<u8>,
}

impl ReadState {
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
}

struct WriteState {
    pub state: Arc<RwLock<ConnectionState>>,
    /// The url to connect to
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    pub message_queue: Arc<RwLock<MessageQueue>>,
    pub writer: Option<WriteHalf<TcpStream>>,
    /// The send buffer
    pub send_buffer: MessageWriter,
}

impl WriteState {
    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn send_request(&mut self, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        match connection_state!(self.state) {
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
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Connection state - what the connection task is doing
    connection_state: Arc<RwLock<ConnectionState>>,
    /// Message queue for requests / responses
    message_queue: Arc<RwLock<MessageQueue>>,
}

impl TcpTransport {
    /// Create a new TCP transport layer for the session
    pub fn new(secure_channel: Arc<RwLock<SecureChannel>>, session_state: Arc<RwLock<SessionState>>, message_queue: Arc<RwLock<MessageQueue>>) -> TcpTransport {
        TcpTransport {
            session_state,
            secure_channel,
            connection_state: Arc::new(RwLock::new(ConnectionState::NotStarted)),
            message_queue,
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
                                                    self.session_state.clone(), self.secure_channel.clone(), self.message_queue.clone());
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
            thread::sleep(time::Duration::from_millis(WAIT_POLLING_TIMEOUT))
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
            thread::sleep(time::Duration::from_millis(WAIT_POLLING_TIMEOUT))
        }
    }

    /// Tests if the transport is connected
    pub fn is_connected(&self) -> bool {
        match connection_state!(self.connection_state) {
            ConnectionState::NotStarted | ConnectionState::Connecting |
            ConnectionState::Finished(_) => false,
            _ => true,
        }
    }

    /// This is the main connection task for a connection.
    fn connection_task(addr: SocketAddr, connection_state: Arc<RwLock<ConnectionState>>, endpoint_url: String, session_state: Arc<RwLock<SessionState>>, secure_channel: Arc<RwLock<SecureChannel>>, message_queue: Arc<RwLock<MessageQueue>>) -> impl Future<Item=(), Error=()> {
        debug!("Creating a connection task to connect to {} with url {}", addr, endpoint_url);

        let connection_state_for_error = connection_state.clone();
        let connection_state_for_error2 = connection_state.clone();

        let hello = {
            let session_state = trace_read_lock_unwrap!(session_state);
            HelloMessage::new(&endpoint_url,
                              session_state.send_buffer_size(),
                              session_state.receive_buffer_size(),
                              session_state.max_message_size())
        };

        set_connection_state!(connection_state, ConnectionState::Connecting);
        TcpStream::connect(&addr).map_err(move |err| {
            error!("Could not connect to host {}, {:?}", addr, err);
            set_connection_state!(connection_state_for_error, ConnectionState::Finished(BadCommunicationError));
        }).and_then(move |socket| {
            set_connection_state!(connection_state, ConnectionState::Connected);
            let (reader, writer) = socket.split();
            Ok((connection_state, reader, writer))
        }).and_then(move |(connection_state, reader, writer)| {
            error! {"Sending HELLO"};
            io::write_all(writer, hello.to_vec()).map_err(move |err| {
                error!("Cannot send hello to server, err = {:?}", err);
                set_connection_state!(connection_state_for_error2, ConnectionState::Finished(BadCommunicationError));
            }).map(move |(writer, _)| {
                (reader, writer)
            }).and_then(|(reader, writer)| {
                Self::spawn_looping_tasks(reader, writer, connection_state, session_state, secure_channel, message_queue);
                Ok(())
            })
        })
    }

    fn read_bytes_task(connection: ReadState) -> impl Future<Item=(usize, ReadState), Error=StatusCode> {
        // The io::read() consumes reader and in_buf so everything else in
        // connection state has to be taken out and put back in afterwards in the map()
        let secure_channel = connection.secure_channel;
        let reader = connection.reader;
        let in_buf = connection.in_buf;
        let last_received_sequence_number = connection.last_received_sequence_number;
        let receive_buffer = connection.receive_buffer;
        let state = connection.state;
        let message_queue = connection.message_queue;
        io::read(reader, in_buf).map_err(move |err| {
            error!("Read IO error {:?}", err);
            BadCommunicationError
        }).map(move |(reader, in_buf, bytes_read)| {
            // Build a new connection state
            (bytes_read, ReadState {
                message_queue,
                secure_channel,
                receive_buffer,
                last_received_sequence_number,
                state,
                reader,
                in_buf,
            })
        })
    }

    fn write_bytes_task(connection: Arc<Mutex<WriteState>>) -> impl Future<Item=(), Error=()> {
        // io::write_all consumes writer which is a pain, so it is stored as an Option returned
        // afterwards
        let (bytes_to_write, writer) = {
            let mut connection = trace_lock_unwrap!(connection);
            let bytes_to_write = connection.send_buffer.bytes_to_write();
            let writer = connection.writer.take();
            (bytes_to_write, writer.unwrap())
        };
        io::write_all(writer, bytes_to_write).map_err(move |err| {
            error!("Write IO error {:?}", err);
        }).map(move |(writer, _)| {
            let mut connection = trace_lock_unwrap!(connection);
            connection.writer = Some(writer);
        })
    }

    fn spawn_reading_task(connection: ReadState) {
        // This is the main processing loop that receives and sends messages
        let looping_task = loop_fn(connection, |connection| {
            Self::read_bytes_task(connection).and_then(|(bytes_read, mut connection)| {
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
                                    if connection_state!(connection.state) != ConnectionState::WaitingForAck {
                                        error!("Got an unexpected ACK");
                                        session_status_code = BadUnexpectedError;
                                    } else {
                                        // TODO revise our sizes and other things according to the ACK
                                        set_connection_state!(connection.state, ConnectionState::Processing);
                                    }
                                }
                                Message::MessageChunk(chunk) => {
                                    if connection_state!(connection.state) != ConnectionState::Processing {
                                        error!("Got an unexpected message chunk");
                                        session_status_code = BadUnexpectedError;
                                    } else {
                                        let result = connection.process_chunk(chunk);
                                        if result.is_err() {
                                            session_status_code = result.unwrap_err();
                                        } else if let Some(response) = result.unwrap() {
                                            // Store the response
                                            let mut message_queue = trace_write_lock_unwrap!(connection.message_queue);
                                            message_queue.store_response(response);
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
                        set_connection_state!(connection.state, ConnectionState::Finished(session_status_code));
                    }
                }
                Ok(connection)
            }).and_then(|connection| {
                let state = connection_state!(connection.state);
                if let ConnectionState::Finished(_) = state {
                    debug!("Read loop is terminating due to finished state");
                    Ok(Loop::Break(connection))
                } else {
                    // Read / write messages
                    Ok(Loop::Continue(connection))
                }
            })
        }).map_err(move |e| {
            error!("Read loop ended with an error {:?}", e);
        }).map(|_| {
            error!("Read loop finished");
        });
        tokio::spawn(looping_task);
    }

    fn spawn_writing_task(receiver: UnboundedReceiver<SupportedMessage>, connection: WriteState) {
        let connection = Arc::new(Mutex::new(connection));

        // In writing, we wait on outgoing requests, encoding each and writing them out
        let looping_task = receiver
            .map(move |request| {
                (request, connection.clone())
            })
            .take_while(|(_, connection)| {
                let connection = trace_lock_unwrap!(connection);
                let state = connection_state!(connection.state);
                let take = if let ConnectionState::Finished(_) = state {
                    debug!("Write loop is terminating due to finished state");
                    false
                } else {
                    // Read / write messages
                    true
                };
                future::ok(take)
            })
            .for_each(|(request, connection)| {
                {
                    let mut connection = trace_lock_unwrap!(connection);
                    let state = connection_state!(connection.state);
                    if state == ConnectionState::Processing {
                        trace! {"Sending Request"};

                        let close_connection = if let SupportedMessage::CloseSecureChannelRequest(_) = request {
                            true
                        } else {
                            false
                        };

                        // Write it to the outgoing buffer
                        let request_handle = request.request_handle();
                        let _ = connection.send_request(request);
                        // Indicate the request was processed
                        {
                            let mut message_queue = trace_write_lock_unwrap!(connection.message_queue);
                            message_queue.request_was_processed(request_handle);
                        }

                        // Connection might be closed now
                        if close_connection {
                            info!("Received a close, so closing connection after this send");
                            set_connection_state!(connection.state, ConnectionState::Finished(Good));
                        }
                    } else {
                        // panic or not, perhaps there is a race
                    }
                }
                Self::write_bytes_task(connection)
            });

        tokio::spawn(looping_task);
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    fn spawn_looping_tasks(reader: ReadHalf<TcpStream>, writer: WriteHalf<TcpStream>, connection_state: Arc<RwLock<ConnectionState>>, session_state: Arc<RwLock<SessionState>>, secure_channel: Arc<RwLock<SecureChannel>>, message_queue: Arc<RwLock<MessageQueue>>) { //-> impl Future<Item=Connection, Error=StatusCode> {
        let (receive_buffer_size, send_buffer_size) = {
            let session_state = trace_read_lock_unwrap!(session_state);
            (session_state.receive_buffer_size(), session_state.send_buffer_size())
        };

        // Create the message receiver that will drive writes
        let receiver = {
            let mut message_queue = trace_write_lock_unwrap!(message_queue);
            message_queue.make_request_channel()
        };

        // At this stage, the HEL has been sent but the ACK has not been received
        set_connection_state!(connection_state, ConnectionState::WaitingForAck);

        // Spawn the reading task loop
        {
            let read_connection = ReadState {
                secure_channel: secure_channel.clone(),
                state: connection_state.clone(),
                receive_buffer: MessageReader::new(receive_buffer_size),
                last_received_sequence_number: 0,
                in_buf: vec![0u8; receive_buffer_size],
                reader,
                message_queue: message_queue.clone(),
            };
            Self::spawn_reading_task(read_connection);
        }

        // Spawn the writing task loop
        {
            let write_connection = WriteState {
                secure_channel,
                state: connection_state,
                send_buffer: MessageWriter::new(send_buffer_size),
                writer: Some(writer),
                message_queue: message_queue.clone(),
            };

            Self::spawn_writing_task(receiver, write_connection);
        }
    }
}