//! The OPC UA TCP transport client module. The transport is responsible for establishing a connection
//! with the server and processing requests.
//!
//! Internally this uses Tokio to process requests and responses supplied by the session via the
//! session state.
use std::net::{SocketAddr, ToSocketAddrs};
use std::result::Result;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use ::url::Url;
use futures::{Future, Stream};
use futures::future::{self};
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio;
use tokio::net::TcpStream;
use tokio_codec::FramedRead;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{self, ReadHalf, WriteHalf};
use tokio_timer::Interval;

use opcua_core::{
    comms::{
        message_writer::MessageWriter,
        tcp_codec::{Message, TcpCodec},
        wrapped_tcp_stream::WrappedTcpStream,
    },
    prelude::*,
    RUNTIME,
};
use opcua_types::{
    status_code::StatusCode,
    tcp_types::HelloMessage,
    url::OPC_TCP_SCHEME,
};

use crate::{
    callbacks::OnSessionClosed,
    comms::transport::Transport,
    message_queue::{self, MessageQueue},
    session_state::{ConnectionState, SessionState},
};

macro_rules! connection_state {( $s:expr ) => { *trace_read_lock_unwrap!($s) } }
macro_rules! set_connection_state {( $s:expr, $v:expr ) => { *trace_write_lock_unwrap!($s) = $v } }

struct ReadState {
    pub state: Arc<RwLock<ConnectionState>>,
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    pub message_queue: Arc<RwLock<MessageQueue>>,
    /// Last decoded sequence number
    last_received_sequence_number: u32,
}

impl Drop for ReadState {
    fn drop(&mut self) {
        info!("ReadState has dropped");
    }
}

impl ReadState {
    fn turn_received_chunks_into_message(&mut self, chunks: &[MessageChunk]) -> Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        self.last_received_sequence_number = Chunker::validate_chunks(self.last_received_sequence_number + 1, &secure_channel, chunks)?;
        // Now decode
        Chunker::decode(&chunks, &secure_channel, None)
    }

    fn process_chunk(&mut self, chunk: MessageChunk) -> Result<Option<SupportedMessage>, StatusCode> {
        // trace!("Got a chunk {:?}", chunk);
        let (chunk, decoding_limits) = {
            let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
            (secure_channel.verify_and_remove_security(&chunk.data)?, secure_channel.decoding_limits())
        };
        let message_header = chunk.message_header(&decoding_limits)?;
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
    pub writer: Option<WriteHalf<WrappedTcpStream>>,
    /// The send buffer
    pub send_buffer: MessageWriter,
}

impl Drop for WriteState {
    fn drop(&mut self) {
        info!("WriteState has dropped");
    }
}

impl WriteState {
    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn send_request(&mut self, request: SupportedMessage) -> Result<u32, StatusCode> {
        match connection_state!(self.state) {
            ConnectionState::Processing => {
                let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
                let request_id = self.send_buffer.next_request_id();
                self.send_buffer.write(request_id, request, &secure_channel)
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
pub(crate) struct TcpTransport {
    /// Session state
    session_state: Arc<RwLock<SessionState>>,
    /// Secure channel information
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Connection state - what the connection task is doing
    connection_state: Arc<RwLock<ConnectionState>>,
    /// Message queue for requests / responses
    message_queue: Arc<RwLock<MessageQueue>>,
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        info!("TcpTransport has dropped");
    }
}

impl Transport for TcpTransport {}

impl TcpTransport {
    const WAIT_POLLING_TIMEOUT: u64 = 100;

    /// Create a new TCP transport layer for the session
    pub fn new(secure_channel: Arc<RwLock<SecureChannel>>, session_state: Arc<RwLock<SessionState>>, message_queue: Arc<RwLock<MessageQueue>>) -> TcpTransport {
        let connection_state = {
            let session_state = trace_read_lock_unwrap!(session_state);
            session_state.connection_state()
        };
        TcpTransport {
            session_state,
            secure_channel,
            connection_state,
            message_queue,
        }
    }

    fn parse_url(url: &str) -> Result<Url, StatusCode> {
        let url = Url::parse(&url).map_err(|_| StatusCode::BadTcpEndpointUrlInvalid)?;
        if url.scheme() != OPC_TCP_SCHEME || !url.has_host() {
            Err(StatusCode::BadTcpEndpointUrlInvalid)
        } else {
            Ok(url)
        }
    }

    /// Connects the stream to the specified endpoint
    pub fn connect(&mut self, endpoint_url: &str) -> Result<(), StatusCode> {
        if self.is_connected() {
            panic!("Should not try to connect when already connected");
        }

        // Validate and split out the endpoint we have
        let url = Self::parse_url(&endpoint_url)?;

        debug!("Connecting to {:?}", url);
        let host = url.host_str().unwrap();
        let port = url.port().unwrap_or(constants::DEFAULT_OPC_UA_SERVER_PORT);

        // Resolve the host name into a socket address
        let addr = {
            let addr = format!("{}:{}", host, port);
            let addrs = addr.to_socket_addrs();
            if let Ok(mut addrs) = addrs {
                // Take the first resolved ip addr for the hostname
                if let Some(addr) = addrs.next() {
                    addr
                } else {
                    error!("Invalid address {}, does not resolve to any socket", addr);
                    return Err(StatusCode::BadTcpEndpointUrlInvalid);
                }
            } else {
                error!("Invalid address {}, cannot be parsed {:?}", addr, addrs.unwrap_err());
                return Err(StatusCode::BadTcpEndpointUrlInvalid);
            }
        };
        assert_eq!(addr.port(), port);

        // The connection will be serviced on its own thread. When the thread terminates, the connection
        // has also terminated.

        {
            let connection_task = Self::connection_task(addr, self.connection_state.clone(), endpoint_url.to_string(),
                                                        self.session_state.clone(), self.secure_channel.clone(), self.message_queue.clone());

            let connection_state = self.connection_state.clone();
            let session_state = self.session_state.clone();

            let _ = Some(thread::spawn(move || {
                debug!("Client tokio tasks are starting for connection");

                let thread_id = format!("client-connection-thread-{:?}", thread::current().id());
                register_runtime_component!(thread_id.clone());

                tokio::run(connection_task);
                debug!("Client tokio tasks have stopped for connection");

                // Tell the session that the connection is finished.
                let connection_state = connection_state!(connection_state);
                match connection_state {
                    ConnectionState::Finished(status_code) => {
                        let mut session_state = trace_write_lock_unwrap!(session_state);
                        session_state.session_closed(status_code);
                    }
                    _ => {
                        error!("Connect task is not in a finished state, state = {:?}", connection_state);
                    }
                }
                deregister_runtime_component!(thread_id);
            }));
        }

        // Poll for the state to indicate connect is ready
        debug!("Waiting for a connect (or failure to connect)");
        loop {
            match connection_state!(self.connection_state) {
                ConnectionState::Processing => {
                    debug!("Connected");
                    return Ok(());
                }
                ConnectionState::Finished(status_code) => {
                    error!("Connected failed with status {}", status_code);
                    return Err(StatusCode::BadConnectionClosed);
                }
                _ => {
                    // Still waiting for something to happen
                }
            }
            thread::sleep(Duration::from_millis(Self::WAIT_POLLING_TIMEOUT))
        }
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
            thread::sleep(Duration::from_millis(Self::WAIT_POLLING_TIMEOUT))
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

        let id = {
            let session_state = trace_read_lock_unwrap!(session_state);
            session_state.id()
        };

        let connection_task_id = format!("connection-task, {}", id);
        register_runtime_component!(connection_task_id.clone());

        set_connection_state!(connection_state, ConnectionState::Connecting);
        TcpStream::connect(&addr).map_err(move |err| {
            error!("Could not connect to host {}, {:?}", addr, err);
            set_connection_state!(connection_state_for_error, ConnectionState::Finished(StatusCode::BadCommunicationError));
        }).and_then(move |socket| {
            set_connection_state!(connection_state, ConnectionState::Connected);
            let (reader, writer) = WrappedTcpStream(socket).split();
            Ok((connection_state, reader, writer))
        }).and_then(move |(connection_state, reader, writer)| {
            debug! {"Sending HELLO"};
            io::write_all(writer, hello.encode_to_vec()).map_err(move |err| {
                error!("Cannot send hello to server, err = {:?}", err);
                set_connection_state!(connection_state_for_error2, ConnectionState::Finished(StatusCode::BadCommunicationError));
            }).map(move |(writer, _)| {
                (reader, writer)
            }).and_then(move |(reader, writer)| {
                Self::spawn_looping_tasks(reader, writer, connection_state, session_state, secure_channel, message_queue);
                deregister_runtime_component!(connection_task_id.clone());
                Ok(())
            })
        })
    }

    fn write_bytes_task(connection: Arc<Mutex<WriteState>>, and_close_connection: bool) -> impl Future<Item=(), Error=()> {
        let (bytes_to_write, writer) = {
            let mut connection = trace_lock_unwrap!(connection);
            let bytes_to_write = connection.send_buffer.bytes_to_write();
            let writer = connection.writer.take();
            (bytes_to_write, writer.unwrap())
        };

        let connection_for_and_then = connection.clone();
        io::write_all(writer, bytes_to_write).map_err(move |err| {
            error!("Write bytes task IO error {:?}", err);
        }).map(move |(writer, _)| {
            trace!("Write bytes task finished");
            // Reinstate writer
            let mut connection = trace_lock_unwrap!(connection);
            connection.writer = Some(writer);
        }).map_err(|_| {
            error!("Write bytes task error");
        }).and_then(move |_| {
            // Connection might be closed now
            if and_close_connection {
                debug!("Write bytes task received a close, so closing connection after this send");
                let mut connection = trace_lock_unwrap!(connection_for_and_then);
                let _ = connection.writer.as_mut().unwrap().shutdown();
                connection.writer = None;
                Err(())
            } else {
                trace!("Write bytes task was not told to close connection");
                Ok(())
            }
        })
    }

    fn spawn_finished_monitor_task(state: Arc<RwLock<ConnectionState>>, finished_flag: Arc<RwLock<bool>>, id: u32) {
        // This task just spins around waiting for the connection to become finished. When it
        // does it, sets a flag.

        let finished_monitor_task_id = format!("finished-monitor-task, {}", id);
        let finished_monitor_task_id_for_err = finished_monitor_task_id.clone();
        register_runtime_component!(finished_monitor_task_id.clone());

        let finished_monitor_task = Interval::new(Instant::now(), Duration::from_millis(200))
            .take_while(move |_| {
                let finished = {
                    let state = connection_state!(state);
                    if let ConnectionState::Finished(_) = state {
                        true
                    } else {
                        false
                    }
                };
                if finished {
                    // Set the flag
                    let mut finished_flag = trace_write_lock_unwrap!(finished_flag);
                    debug!("finished monitor task detects finished state and has set a finished flag");
                    *finished_flag = true;
                }
                future::ok(!finished)
            })
            .for_each(|_| Ok(()))
            .map(move |_| {
                info!("Timer for finished is finished");
                deregister_runtime_component!(finished_monitor_task_id);
            })
            .map_err(move |err| {
                error!("Timer for finished is finished with an error {:?}", err);
                deregister_runtime_component!(finished_monitor_task_id_for_err);
            });
        tokio::spawn(finished_monitor_task);
    }

    fn spawn_reading_task(reader: ReadHalf<WrappedTcpStream>, writer_tx: UnboundedSender<message_queue::Message>, finished_flag: Arc<RwLock<bool>>, _receive_buffer_size: usize, connection: ReadState, id: u32) {
        // This is the main processing loop that receives and sends messages
        let decoding_limits = {
            let secure_channel = trace_read_lock_unwrap!(connection.secure_channel);
            secure_channel.decoding_limits()
        };

        let connection = Arc::new(RwLock::new(connection));
        let connection_for_error = connection.clone();
        let connection_for_terminate = connection.clone();

        let read_task_id = format!("read-task, {}", id);
        let read_task_id_for_err = read_task_id.clone();
        register_runtime_component!(read_task_id.clone());

        // The reader reads frames from the codec, which are messages
        let framed_reader = FramedRead::new(reader, TcpCodec::new(finished_flag, decoding_limits));
        let looping_task = framed_reader.for_each(move |message| {
            let mut connection = trace_write_lock_unwrap!(connection);
            let mut session_status_code = StatusCode::Good;
            match message {
                Message::Acknowledge(ack) => {
                    debug!("Reader got ack {:?}", ack);
                    if connection_state!(connection.state) != ConnectionState::WaitingForAck {
                        error!("Reader got an unexpected ACK");
                        session_status_code = StatusCode::BadUnexpectedError;
                    } else {
                        // TODO revise our sizes and other things according to the ACK
                        set_connection_state!(connection.state, ConnectionState::Processing);
                    }
                }
                Message::Chunk(chunk) => {
                    if connection_state!(connection.state) != ConnectionState::Processing {
                        error!("Got an unexpected message chunk");
                        session_status_code = StatusCode::BadUnexpectedError;
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
                    session_status_code = if let Some(status_code) = StatusCode::from_u32(error.error) {
                        status_code
                    } else {
                        StatusCode::BadUnexpectedError
                    };
                    error!("Expecting a chunk, got an error message {}", session_status_code);
                }
                _ => {
                    panic!("Expected a recognized message");
                }
            }
            if session_status_code.is_bad() {
                error!("Reader is putting connection into a finished state with status {}", session_status_code);
                set_connection_state!(connection.state, ConnectionState::Finished(session_status_code));
                // Tell the writer to quit
                debug!("Reader is sending a quit to the writer");
                if let Err(err) = writer_tx.unbounded_send(message_queue::Message::Quit) {
                    debug!("Cannot sent quit to writer, error = {:?}", err);
                }
                Err(std::io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(())
            }
        }).map_err(move |e| {
            error!("Read loop error {:?}", e);
            let connection = trace_read_lock_unwrap!(connection_for_error);
            let state = connection_state!(connection.state);
            match state {
                ConnectionState::Finished(_) => { /* DO NOTHING */ }
                _ => {
                    set_connection_state!(connection.state, ConnectionState::Finished(StatusCode::BadCommunicationError));
                }
            }
        }).and_then(move |_| {
            let connection = trace_read_lock_unwrap!(connection_for_terminate);
            let state = connection_state!(connection.state);
            if let ConnectionState::Finished(_) = state {
                debug!("Read loop is terminating due to finished state");
                Err(())
            } else {
                // Read / write messages
                Ok(())
            }
        }).map(move |_| {
            debug!("Read loop finished");
            deregister_runtime_component!(read_task_id);
        }).map_err(move |_| {
            debug!("Read loop ended with an error");
            deregister_runtime_component!(read_task_id_for_err);
        });
        tokio::spawn(looping_task);
    }

    fn spawn_writing_task(receiver: UnboundedReceiver<message_queue::Message>, connection: WriteState, id: u32) {
        let connection = Arc::new(Mutex::new(connection));
        let connection_for_error = connection.clone();

        let write_task_id = format!("write-task, {}", id);
        let write_task_id_for_err = write_task_id.clone();
        register_runtime_component!(write_task_id.clone());

        // In writing, we wait on outgoing requests, encoding each and writing them out
        let looping_task = receiver
            .map(move |message| {
                (message, connection.clone())
            })
            .take_while(|(message, connection)| {
                trace!("Write task take while");
                let take = match message {
                    message_queue::Message::Quit => {
                        debug!("Write task received a quit");
                        false
                    }
                    message_queue::Message::SupportedMessage(_) => {
                        let connection = trace_lock_unwrap!(connection);
                        let state = connection_state!(connection.state);
                        if let ConnectionState::Finished(_) = state {
                            debug!("Write loop is terminating due to finished state");
                            false
                        } else {
                            // Read / write messages
                            true
                        }
                    }
                };
                future::ok(take)
            })
            .for_each(|(message, connection)| {
                debug!("About to write");
                let request = match message {
                    message_queue::Message::Quit => panic!(),
                    message_queue::Message::SupportedMessage(request) => request
                };
                let close_connection = {
                    let mut connection = trace_lock_unwrap!(connection);
                    let state = connection_state!(connection.state);
                    if state == ConnectionState::Processing {
                        trace! {"Sending Request"};

                        let close_connection = if let SupportedMessage::CloseSecureChannelRequest(_) = request {
                            debug!("Writer is about to send a CloseSecureChannelRequest which means it should close in a moment");
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

                        if close_connection {
                            set_connection_state!(connection.state, ConnectionState::Finished(StatusCode::Good));
                            debug!("Writer is setting the connection state to finished(good)");
                        }
                        close_connection
                    } else {
                        // panic or not, perhaps there is a race
                        error!("Writer, why is the connection state not processing?");
                        set_connection_state!(connection.state, ConnectionState::Finished(StatusCode::BadUnexpectedError));
                        true
                    }
                };
                Self::write_bytes_task(connection, close_connection)
            })
            .map(move |_| {
                debug!("Writer loop is finished");
                deregister_runtime_component!(write_task_id);
            })
            .map_err(move |_| {
                debug!("Writer loop is finished with an error");
                let connection = trace_lock_unwrap!(connection_for_error);
                set_connection_state!(connection.state, ConnectionState::Finished(StatusCode::BadCommunicationError));
                deregister_runtime_component!(write_task_id_for_err);
            });

        tokio::spawn(looping_task);
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    fn spawn_looping_tasks(reader: ReadHalf<WrappedTcpStream>, writer: WriteHalf<WrappedTcpStream>, connection_state: Arc<RwLock<ConnectionState>>, session_state: Arc<RwLock<SessionState>>, secure_channel: Arc<RwLock<SecureChannel>>, message_queue: Arc<RwLock<MessageQueue>>) {
        let (receive_buffer_size, send_buffer_size, id) = {
            let session_state = trace_read_lock_unwrap!(session_state);
            (session_state.receive_buffer_size(), session_state.send_buffer_size(), session_state.id())
        };

        // Create the message receiver that will drive writes
        let (sender, receiver) = {
            let mut message_queue = trace_write_lock_unwrap!(message_queue);
            message_queue.make_request_channel()
        };

        // At this stage, the HEL has been sent but the ACK has not been received
        set_connection_state!(connection_state, ConnectionState::WaitingForAck);

        // Abort monitor
        let finished_flag = Arc::new(RwLock::new(false));
        Self::spawn_finished_monitor_task(connection_state.clone(), finished_flag.clone(), id);

        // Spawn the reading task loop
        {
            let read_connection = ReadState {
                secure_channel: secure_channel.clone(),
                state: connection_state.clone(),
                last_received_sequence_number: 0,
                message_queue: message_queue.clone(),
            };
            Self::spawn_reading_task(reader, sender, finished_flag, receive_buffer_size, read_connection, id);
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

            Self::spawn_writing_task(receiver, write_connection, id);
        }
    }
}
