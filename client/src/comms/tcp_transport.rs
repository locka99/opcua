// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! The OPC UA TCP transport client module. The transport is responsible for establishing a connection
//! with the server and processing requests.
//!
//! Internally this uses Tokio to process requests and responses supplied by the session via the
//! session state.
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    result::Result,
    sync::{Arc, Mutex, RwLock},
    thread,
};

use futures::StreamExt;
use tokio::{
    self,
    io::{self, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{interval_at, Duration, Instant},
};
use tokio_util::codec::FramedRead;

use opcua_core::comms::message_chunk_info::ChunkInfo;
use opcua_core::{
    comms::{
        message_writer::MessageWriter,
        tcp_codec::{Message, TcpCodec},
        tcp_types::HelloMessage,
        url::hostname_port_from_url,
    },
    prelude::*,
    RUNTIME,
};
use opcua_types::status_code::StatusCode;

use crate::{
    callbacks::OnSessionClosed,
    comms::transport::Transport,
    message_queue::{self, MessageQueue},
    session_state::{ConnectionState, SessionState},
};
use tokio::io::AsyncWriteExt;

macro_rules! connection_state {
    ( $s:expr ) => {
        *trace_read_lock_unwrap!($s)
    };
}
macro_rules! set_connection_state {
    ( $s:expr, $v:expr ) => {
        *trace_write_lock_unwrap!($s) = $v
    };
}

//todo move this struct to core module
#[derive(Debug)]
struct MessageChunkWithChunkInfo {
    header: ChunkInfo,
    data_with_header: Vec<u8>,
}
struct ReadState {
    pub state: Arc<RwLock<ConnectionState>>,
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    pub message_queue: Arc<RwLock<MessageQueue>>,
    pub max_chunk_count: usize,
    /// Last decoded sequence number
    last_received_sequence_number: u32,
    chunks: HashMap<u32, Vec<MessageChunkWithChunkInfo>>,
}

impl Drop for ReadState {
    fn drop(&mut self) {
        info!("ReadState has dropped");
    }
}

impl ReadState {
    fn turn_received_chunks_into_message(
        &mut self,
        chunks: &[MessageChunk],
    ) -> Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        self.last_received_sequence_number = Chunker::validate_chunks(
            self.last_received_sequence_number + 1,
            &secure_channel,
            chunks,
        )?;
        // Now decode
        Chunker::decode(&chunks, &secure_channel, None)
    }

    fn process_chunk(
        &mut self,
        chunk: MessageChunk,
    ) -> Result<Option<SupportedMessage>, StatusCode> {
        // trace!("Got a chunk {:?}", chunk);
        let chunk = {
            let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
            secure_channel.verify_and_remove_security(&chunk.data)?
        };

        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        let chunk_info = chunk.chunk_info(&secure_channel)?;
        drop(secure_channel);
        let req_id = chunk_info.sequence_header.request_id;

        match chunk_info.message_header.is_final {
            MessageIsFinalType::Intermediate => {
                let chunks = self.chunks.entry(req_id).or_insert(Vec::new());
                debug!(
                    "receive chunk intermediate {}:{}",
                    chunk_info.sequence_header.request_id,
                    chunk_info.sequence_header.sequence_number
                );
                chunks.push(MessageChunkWithChunkInfo {
                    header: chunk_info,
                    data_with_header: chunk.data,
                });
                let chunks_len = self.chunks.len();
                if self.max_chunk_count > 0 && chunks_len > self.max_chunk_count {
                    error!("too many chunks {}> {}", chunks_len, self.max_chunk_count);
                    //remove first
                    let first_req_id = *self.chunks.iter().next().unwrap().0;
                    self.chunks.remove(&first_req_id);
                }
                return Ok(None);
            }
            MessageIsFinalType::FinalError => {
                info!("Discarding chunk marked in as final error");
                self.chunks.remove(&chunk_info.sequence_header.request_id);
                return Ok(None);
            }
            _ => {
                // Drop through
            }
        }

        let chunks = self.chunks.entry(req_id).or_insert(Vec::new());
        chunks.push(MessageChunkWithChunkInfo {
            header: chunk_info,
            data_with_header: chunk.data,
        });
        let in_chunks = Self::merge_chunks(self.chunks.remove(&req_id).unwrap())?;
        let message = self.turn_received_chunks_into_message(&in_chunks)?;

        Ok(Some(message))
    }

    fn merge_chunks(
        mut chunks: Vec<MessageChunkWithChunkInfo>,
    ) -> Result<Vec<MessageChunk>, StatusCode> {
        if chunks.len() == 1 {
            return Ok(vec![MessageChunk {
                data: chunks.pop().unwrap().data_with_header,
            }]);
        }
        chunks.sort_by(|a, b| {
            a.header
                .sequence_header
                .sequence_number
                .cmp(&b.header.sequence_header.sequence_number)
        });
        let mut ret = Vec::with_capacity(chunks.len());
        //not start with 0
        let mut expect_sequence_number = chunks
            .get(0)
            .unwrap()
            .header
            .sequence_header
            .sequence_number;
        for c in chunks {
            if c.header.sequence_header.sequence_number != expect_sequence_number {
                info!(
                    "receive wrong chunk expect seq={},got={}",
                    expect_sequence_number, c.header.sequence_header.sequence_number
                );
                continue; //may be duplicate chunk
            }
            expect_sequence_number = expect_sequence_number + 1;
            ret.push(MessageChunk {
                data: c.data_with_header,
            });
        }
        return Ok(ret);
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
    /// Use a single-threaded executor
    single_threaded_executor: bool,
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
    pub fn new(
        secure_channel: Arc<RwLock<SecureChannel>>,
        session_state: Arc<RwLock<SessionState>>,
        message_queue: Arc<RwLock<MessageQueue>>,
        single_threaded_executor: bool,
    ) -> TcpTransport {
        let connection_state = {
            let session_state = trace_read_lock_unwrap!(session_state);
            session_state.connection_state()
        };
        TcpTransport {
            session_state,
            secure_channel,
            connection_state,
            message_queue,
            single_threaded_executor,
        }
    }

    /// Connects the stream to the specified endpoint
    pub fn connect(&mut self, endpoint_url: &str) -> Result<(), StatusCode> {
        if self.is_connected() {
            panic!("Should not try to connect when already connected");
        }

        let (host, port) =
            hostname_port_from_url(&endpoint_url, constants::DEFAULT_OPC_UA_SERVER_PORT)?;

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
                error!(
                    "Invalid address {}, cannot be parsed {:?}",
                    addr,
                    addrs.unwrap_err()
                );
                return Err(StatusCode::BadTcpEndpointUrlInvalid);
            }
        };
        assert_eq!(addr.port(), port);

        // The connection will be serviced on its own thread. When the thread terminates, the connection
        // has also terminated.

        {
            let single_threaded_executor = self.single_threaded_executor;

            let (connection_state, session_state, secure_channel, message_queue) = (
                self.connection_state.clone(),
                self.session_state.clone(),
                self.secure_channel.clone(),
                self.message_queue.clone(),
            );
            let endpoint_url = endpoint_url.to_string();

            thread::spawn(move || {
                debug!("Client tokio tasks are starting for connection");

                let thread_id = format!("client-connection-thread-{:?}", thread::current().id());
                register_runtime_component!(thread_id.clone());

                let mut builder = if !single_threaded_executor {
                    tokio::runtime::Builder::new_multi_thread()
                } else {
                    tokio::runtime::Builder::new_current_thread()
                };

                builder.enable_all().build().unwrap().block_on(async {
                    Self::connection_task(
                        addr,
                        connection_state.clone(),
                        endpoint_url,
                        session_state.clone(),
                        secure_channel,
                        message_queue,
                    )
                    .await;

                    // Tell the session that the connection is finished.
                    match connection_state!(connection_state) {
                        ConnectionState::Finished(status_code) => {
                            let mut session_state = trace_write_lock_unwrap!(session_state);
                            session_state.on_session_closed(status_code);
                        }
                        connection_state => {
                            error!(
                                "Connect task is not in a finished state, state = {:?}",
                                connection_state
                            );
                        }
                    }
                    deregister_runtime_component!(thread_id);
                });

                debug!("Client tokio tasks have stopped for connection");
            });
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
            ConnectionState::NotStarted
            | ConnectionState::Connecting
            | ConnectionState::Finished(_) => false,
            _ => true,
        }
    }

    /// This is the main connection task for a connection.
    async fn connection_task(
        addr: SocketAddr,
        connection_state: Arc<RwLock<ConnectionState>>,
        endpoint_url: String,
        session_state: Arc<RwLock<SessionState>>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
    ) {
        debug!(
            "Creating a connection task to connect to {} with url {}",
            addr, endpoint_url
        );

        let connection_state_for_error = connection_state.clone();
        let connection_state_for_error2 = connection_state.clone();

        let hello = {
            let session_state = trace_read_lock_unwrap!(session_state);
            HelloMessage::new(
                &endpoint_url,
                session_state.send_buffer_size(),
                session_state.receive_buffer_size(),
                session_state.max_message_size(),
                session_state.max_chunk_count(),
            )
        };

        let id = {
            let session_state = trace_read_lock_unwrap!(session_state);
            session_state.id()
        };

        let connection_task_id = format!("connection-task, {}", id);
        register_runtime_component!(connection_task_id.clone());

        set_connection_state!(connection_state, ConnectionState::Connecting);
        match TcpStream::connect(&addr).await {
            io::Result::Err(err) => {
                error!("Could not connect to host {}, {:?}", addr, err);
                set_connection_state!(
                    connection_state_for_error,
                    ConnectionState::Finished(StatusCode::BadCommunicationError)
                );
            }
            io::Result::Ok(socket) => {
                set_connection_state!(connection_state, ConnectionState::Connected);
                let (reader, mut writer) = tokio::io::split(socket);

                debug! {"Sending HELLO"};
                match writer.write_all(&hello.encode_to_vec()).await {
                    io::Result::Err(err) => {
                        error!("Cannot send hello to server, err = {:?}", err);
                        set_connection_state!(
                            connection_state_for_error2,
                            ConnectionState::Finished(StatusCode::BadCommunicationError)
                        );
                    }
                    io::Result::Ok(_) => {
                        Self::spawn_looping_tasks(
                            reader,
                            writer,
                            connection_state,
                            session_state,
                            secure_channel,
                            message_queue,
                        );
                        deregister_runtime_component!(connection_task_id);
                    }
                };
            }
        }
    }

    async fn write_bytes_task(connection: Arc<Mutex<WriteState>>, and_close_connection: bool) {
        let (bytes_to_write, mut writer) = {
            let mut connection = trace_lock_unwrap!(connection);
            let bytes_to_write = connection.send_buffer.bytes_to_write();
            let writer = connection.writer.take();
            (bytes_to_write, writer.unwrap())
        };

        match writer.write_all(&bytes_to_write).await {
            io::Result::Err(err) => {
                error!("Write bytes task IO error {:?}", err);
            }
            io::Result::Ok(_) => {
                trace!("Write bytes task finished");
                // Reinstate writer
                let mut connection = trace_lock_unwrap!(connection);
                // Connection might be closed now
                if and_close_connection {
                    debug!(
                        "Write bytes task received a close, so closing connection after this send"
                    );
                    let _ = connection.writer.as_mut().unwrap().shutdown();
                    connection.writer = None;
                } else {
                    trace!("Write bytes task was not told to close connection");
                    connection.writer = Some(writer);
                }
            }
        }
    }

    fn spawn_finished_monitor_task(
        state: Arc<RwLock<ConnectionState>>,
        finished_flag: Arc<RwLock<bool>>,
        id: u32,
    ) {
        // This task just spins around waiting for the connection to become finished. When it
        // does it, sets a flag.

        let finished_monitor_task_id = format!("finished-monitor-task, {}", id);
        register_runtime_component!(finished_monitor_task_id.clone());

        tokio::spawn(async {
            let mut finished_monitor_task = interval_at(Instant::now(), Duration::from_millis(200));

            loop {
                finished_monitor_task.tick().await;
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
                    debug!(
                        "finished monitor task detects finished state and has set a finished flag"
                    );
                    *finished_flag = true;

                    info!("Timer for finished is finished");
                    deregister_runtime_component!(finished_monitor_task_id);
                    break;
                }
            }
        });
    }

    fn spawn_reading_task(
        reader: ReadHalf<TcpStream>,
        writer_tx: UnboundedSender<message_queue::Message>,
        finished_flag: Arc<RwLock<bool>>,
        _receive_buffer_size: usize,
        connection: ReadState,
        id: u32,
    ) {
        // This is the main processing loop that receives and sends messages
        let decoding_options = {
            let secure_channel = trace_read_lock_unwrap!(connection.secure_channel);
            secure_channel.decoding_options()
        };

        let connection = Arc::new(RwLock::new(connection));

        let read_task_id = format!("read-task, {}", id);
        register_runtime_component!(read_task_id.clone());

        let mut framed_reader =
            FramedRead::new(reader, TcpCodec::new(finished_flag, decoding_options));

        tokio::spawn(async {
            // The reader reads frames from the codec, which are messages
            loop {
                let read_next = framed_reader.next().await;
                if read_next.is_none() {
                    continue;
                }
                match read_next.unwrap() {
                    Ok(message) => {
                        let mut connection = trace_write_lock_unwrap!(connection);
                        let mut session_status_code = StatusCode::Good;
                        match message {
                            Message::Acknowledge(ack) => {
                                debug!("Reader got ack {:?}", ack);
                                if connection_state!(connection.state)
                                    != ConnectionState::WaitingForAck
                                {
                                    error!("Reader got an unexpected ACK");
                                    session_status_code = StatusCode::BadUnexpectedError;
                                } else {
                                    // TODO revise our sizes and other things according to the ACK
                                    set_connection_state!(
                                        connection.state,
                                        ConnectionState::Processing
                                    );
                                }
                            }
                            Message::Chunk(chunk) => {
                                if connection_state!(connection.state)
                                    != ConnectionState::Processing
                                {
                                    error!("Got an unexpected message chunk");
                                    session_status_code = StatusCode::BadUnexpectedError;
                                } else {
                                    match connection.process_chunk(chunk) {
                                        Ok(response) => {
                                            if let Some(response) = response {
                                                // Store the response
                                                let mut message_queue = trace_write_lock_unwrap!(
                                                    connection.message_queue
                                                );
                                                message_queue.store_response(response);
                                            }
                                        }
                                        Err(err) => session_status_code = err,
                                    };
                                }
                            }
                            Message::Error(error) => {
                                // TODO client should go into an error recovery state, dropping the connection and reestablishing it.
                                session_status_code =
                                    if let Some(status_code) = StatusCode::from_u32(error.error) {
                                        status_code
                                    } else {
                                        StatusCode::BadUnexpectedError
                                    };
                                error!(
                                    "Expecting a chunk, got an error message {}",
                                    session_status_code
                                );
                            }
                            _ => {
                                panic!("Expected a recognized message");
                            }
                        }
                        if session_status_code.is_bad() {
                            error!(
                                "Reader is putting connection into a finished state with status {}",
                                session_status_code
                            );
                            set_connection_state!(
                                connection.state,
                                ConnectionState::Finished(session_status_code)
                            );
                            // Tell the writer to quit
                            debug!("Reader is sending a quit to the writer");
                            if let Err(_) = writer_tx.send(message_queue::Message::Quit) {
                                debug!("Cannot send quit to writer");
                            }
                            break;
                        }
                    }
                    Err(err) => {
                        error!("Read loop error {:?}", err);
                        let connection = trace_read_lock_unwrap!(connection);
                        let state = connection_state!(connection.state);
                        match state {
                            ConnectionState::Finished(_) => { /* DO NOTHING */ }
                            _ => {
                                set_connection_state!(
                                    connection.state,
                                    ConnectionState::Finished(StatusCode::BadCommunicationError)
                                );
                            }
                        }
                        break;
                    }
                }
            }
            let connection = trace_read_lock_unwrap!(connection);
            let state = connection_state!(connection.state);
            if let ConnectionState::Finished(_) = state {
                debug!("Read loop is terminating due to finished state");
            }
            debug!("Read loop finished");
            deregister_runtime_component!(read_task_id);
        });
    }

    fn spawn_writing_task(
        mut receiver: UnboundedReceiver<message_queue::Message>,
        connection: WriteState,
        id: u32,
    ) {
        let connection = Arc::new(Mutex::new(connection));
        let connection_for_error = connection.clone();

        let write_task_id = format!("write-task, {}", id);
        register_runtime_component!(write_task_id.clone());

        // In writing, we wait on outgoing requests, encoding each and writing them out
        tokio::spawn(async {
            loop {
                if let Some(msg) = receiver.recv().await {
                    match msg {
                        message_queue::Message::Quit => {
                            debug!("Write task received a quit");
                            break;
                        }
                        message_queue::Message::SupportedMessage(request) => {
                            {
                                let connection = trace_lock_unwrap!(connection);
                                let state = connection_state!(connection.state);
                                if let ConnectionState::Finished(_) = state {
                                    debug!("Write loop is terminating due to finished state");
                                    break;
                                }
                            }

                            let close_connection = {
                                let mut connection = trace_lock_unwrap!(connection);
                                let state = connection_state!(connection.state);
                                if state == ConnectionState::Processing {
                                    trace!("Sending Request");

                                    let close_connection =
                                        if let SupportedMessage::CloseSecureChannelRequest(_) =
                                            request
                                        {
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
                                        let mut message_queue =
                                            trace_write_lock_unwrap!(connection.message_queue);
                                        message_queue.request_was_processed(request_handle);
                                    }

                                    if close_connection {
                                        set_connection_state!(
                                            connection.state,
                                            ConnectionState::Finished(StatusCode::Good)
                                        );
                                        debug!("Writer is setting the connection state to finished(good)");
                                    }
                                    close_connection
                                } else {
                                    // panic or not, perhaps there is a race
                                    error!("Writer, why is the connection state not processing?");
                                    set_connection_state!(
                                        connection.state,
                                        ConnectionState::Finished(StatusCode::BadUnexpectedError)
                                    );
                                    true
                                }
                            };

                            Self::write_bytes_task(connection, close_connection).await
                        }
                    };
                }
            }
            debug!("Writer loop is finished");
            deregister_runtime_component!(write_task_id);
        });
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    async fn spawn_looping_tasks(
        reader: ReadHalf<TcpStream>,
        writer: WriteHalf<TcpStream>,
        connection_state: Arc<RwLock<ConnectionState>>,
        session_state: Arc<RwLock<SessionState>>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
    ) {
        let (receive_buffer_size, send_buffer_size, id, max_message_size, max_chunk_count) = {
            let session_state = trace_read_lock_unwrap!(session_state);
            (
                session_state.receive_buffer_size(),
                session_state.send_buffer_size(),
                session_state.id(),
                session_state.max_message_size(),
                session_state.max_chunk_count(),
            )
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
                max_chunk_count,
                last_received_sequence_number: 0,
                message_queue: message_queue.clone(),
                chunks: HashMap::new(),
            };
            Self::spawn_reading_task(
                reader,
                sender,
                finished_flag,
                receive_buffer_size,
                read_connection,
                id,
            );
        }

        // Spawn the writing task loop
        {
            let write_connection = WriteState {
                secure_channel,
                state: connection_state,
                send_buffer: MessageWriter::new(
                    send_buffer_size,
                    max_message_size,
                    max_chunk_count,
                ),
                writer: Some(writer),
                message_queue,
            };

            Self::spawn_writing_task(receiver, write_connection, id);
        }
    }
}
