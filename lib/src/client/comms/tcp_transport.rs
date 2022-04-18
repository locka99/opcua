// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! The OPC UA TCP transport client module. The transport is responsible for establishing a connection
//! with the server and processing requests.
//!
//! Internally this uses Tokio to process requests and responses supplied by the session via the
//! session state.
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    result::Result,
    sync::Arc,
    thread,
};

use futures::StreamExt;
use tokio::{
    self,
    io::{self, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{interval, Duration},
};
use tokio_util::codec::FramedRead;

use crate::core::{
    comms::{
        message_chunk_info::ChunkInfo,
        message_writer::MessageWriter,
        tcp_codec::{Message, TcpCodec},
        tcp_types::HelloMessage,
        url::hostname_port_from_url,
    },
    prelude::*,
    RUNTIME,
};
use crate::sync::*;
use crate::types::status_code::StatusCode;
use crate::{deregister_runtime_component, register_runtime_component};

use crate::client::{
    callbacks::OnSessionClosed,
    comms::transport::Transport,
    message_queue::{self, MessageQueue},
    session::session_state::{ConnectionState, ConnectionStateMgr, SessionState},
};

//todo move this struct to core module
#[derive(Debug)]
struct MessageChunkWithChunkInfo {
    header: ChunkInfo,
    data_with_header: Vec<u8>,
}

struct ReadState {
    pub state: ConnectionStateMgr,
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
        let secure_channel = trace_read_lock!(self.secure_channel);
        self.last_received_sequence_number = Chunker::validate_chunks(
            self.last_received_sequence_number + 1,
            &secure_channel,
            chunks,
        )?;
        // Now decode
        Chunker::decode(chunks, &secure_channel, None)
    }

    fn process_chunk(
        &mut self,
        chunk: MessageChunk,
    ) -> Result<Option<SupportedMessage>, StatusCode> {
        // trace!("Got a chunk {:?}", chunk);
        let chunk = {
            let mut secure_channel = trace_write_lock!(self.secure_channel);
            secure_channel.verify_and_remove_security(&chunk.data)?
        };

        let secure_channel = trace_read_lock!(self.secure_channel);
        let chunk_info = chunk.chunk_info(&secure_channel)?;
        drop(secure_channel);
        let req_id = chunk_info.sequence_header.request_id;

        match chunk_info.message_header.is_final {
            MessageIsFinalType::Intermediate => {
                let chunks = self.chunks.entry(req_id).or_insert_with(Vec::new);
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

        let chunks = self.chunks.entry(req_id).or_insert_with(Vec::new);
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
            expect_sequence_number += 1;
            ret.push(MessageChunk {
                data: c.data_with_header,
            });
        }
        Ok(ret)
    }
}

struct WriteState {
    pub state: ConnectionStateMgr,
    /// The url to connect to
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    pub message_queue: Arc<RwLock<MessageQueue>>,
    pub writer: WriteHalf<TcpStream>,
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
        match self.state.state() {
            ConnectionState::Processing => {
                let secure_channel = trace_read_lock!(self.secure_channel);
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
    connection_state: ConnectionStateMgr,
    /// Message queue for requests / responses
    message_queue: Arc<RwLock<MessageQueue>>,
    /// Tokio runtime
    runtime: Arc<Mutex<tokio::runtime::Runtime>>,
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
            let session_state = trace_read_lock!(session_state);
            session_state.connection_state()
        };

        let runtime = {
            let mut builder = if !single_threaded_executor {
                tokio::runtime::Builder::new_multi_thread()
            } else {
                tokio::runtime::Builder::new_current_thread()
            };

            builder.enable_all().build().unwrap()
        };

        TcpTransport {
            session_state,
            secure_channel,
            connection_state,
            message_queue,
            runtime: Arc::new(Mutex::new(runtime)),
        }
    }

    /// Connects the stream to the specified endpoint
    pub fn connect(&self, endpoint_url: &str) -> Result<(), StatusCode> {
        if self.is_connected() {
            panic!("Should not try to connect when already connected");
        }

        let (host, port) =
            hostname_port_from_url(endpoint_url, constants::DEFAULT_OPC_UA_SERVER_PORT)?;

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

        let connection_task = {
            let (connection_state, session_state, secure_channel, message_queue) = (
                self.connection_state.clone(),
                self.session_state.clone(),
                self.secure_channel.clone(),
                self.message_queue.clone(),
            );
            let endpoint_url = endpoint_url.to_string();

            let id = format!("client-connection-thread-{:?}", thread::current().id());
            Self::connection_task(
                id,
                addr,
                connection_state,
                endpoint_url,
                session_state,
                secure_channel,
                message_queue,
            )
        };

        let runtime = self.runtime.clone();
        thread::spawn(move || {
            debug!("Client tokio tasks are starting for connection");
            let runtime = trace_lock!(runtime);
            runtime.block_on(async move {
                connection_task.await;
                debug!("Client tokio tasks have stopped for connection");
            });
        });

        // Poll for the state to indicate connect is ready
        debug!("Waiting for a connect (or failure to connect)");
        loop {
            match self.connection_state.state() {
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
    pub fn wait_for_disconnect(&self) {
        debug!("Waiting for a disconnect");
        loop {
            if self.connection_state.is_finished() {
                debug!("Disconnected");
                break;
            }
            thread::sleep(Duration::from_millis(Self::WAIT_POLLING_TIMEOUT))
        }
    }

    /// Tests if the transport is connected
    pub fn is_connected(&self) -> bool {
        self.connection_state.is_connected()
    }

    /// This is the main connection task for a connection.
    async fn connection_task(
        id: String,
        addr: SocketAddr,
        connection_state: ConnectionStateMgr,
        endpoint_url: String,
        session_state: Arc<RwLock<SessionState>>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
    ) {
        register_runtime_component!(&id);

        debug!(
            "Creating a connection task to connect to {} with url {}",
            addr, endpoint_url
        );

        let hello = {
            let session_state = trace_read_lock!(session_state);
            HelloMessage::new(
                &endpoint_url,
                session_state.send_buffer_size(),
                session_state.receive_buffer_size(),
                session_state.max_message_size(),
                session_state.max_chunk_count(),
            )
        };

        let id = {
            let session_state = trace_read_lock!(session_state);
            session_state.id()
        };

        let id = format!("connection-task, {}", id);
        register_runtime_component!(&id);

        connection_state.set_state(ConnectionState::Connecting);

        match TcpStream::connect(&addr).await {
            io::Result::Err(err) => {
                error!("Could not connect to host {}, {:?}", addr, err);
                connection_state.set_finished(StatusCode::BadCommunicationError);
            }
            io::Result::Ok(socket) => {
                connection_state.set_state(ConnectionState::Connected);
                let (reader, mut writer) = tokio::io::split(socket);

                debug! {"Sending HELLO"};
                match writer.write_all(&hello.encode_to_vec()).await {
                    io::Result::Err(err) => {
                        error!("Cannot send hello to server, err = {:?}", err);
                        connection_state.set_finished(StatusCode::BadCommunicationError);
                    }
                    io::Result::Ok(_) => {
                        Self::spawn_looping_tasks(
                            reader,
                            writer,
                            connection_state.clone(),
                            session_state.clone(),
                            secure_channel,
                            message_queue,
                        );
                        deregister_runtime_component!(&id);
                    }
                };
                // Wait for connection state to be closed
                let mut timer = interval(Duration::from_millis(10));
                loop {
                    timer.tick().await;
                    {
                        if connection_state.is_finished() {
                            debug!(
                                "Connection state is finished so dropping out of connection task"
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Tell the session that the connection is finished.
        match connection_state.state() {
            ConnectionState::Finished(status_code) => {
                let mut session_state = trace_write_lock!(session_state);
                session_state.on_session_closed(status_code);
            }
            connection_state => {
                error!(
                    "Connect task is not in a finished state, state = {:?}",
                    connection_state
                );
            }
        }
        deregister_runtime_component!(&id);
    }

    async fn write_bytes_task(
        mut write_state: WriteState,
        and_close_connection: bool,
    ) -> WriteState {
        let bytes_to_write = write_state.send_buffer.bytes_to_write();
        let write_result = write_state.writer.write_all(&bytes_to_write).await;
        match write_result {
            io::Result::Err(err) => {
                error!("Write bytes task IO error {:?}", err);
            }
            io::Result::Ok(_) => {
                trace!("Write bytes task finished");
                // Connection might be closed now
                if and_close_connection {
                    debug!(
                        "Write bytes task received a close, so closing connection after this send"
                    );
                    let _ = write_state.writer.shutdown();
                } else {
                    trace!("Write bytes task was not told to close connection");
                }
            }
        }
        write_state
    }

    fn spawn_finished_monitor_task(
        connection_state: ConnectionStateMgr,
        finished_flag: Arc<RwLock<bool>>,
        id: u32,
    ) {
        // This task just spins around waiting for the connection to become finished. When it
        // does it, sets a flag.
        tokio::spawn(async move {
            let id = format!("finished-monitor-task, {}", id);
            register_runtime_component!(&id);
            let mut timer = interval(Duration::from_millis(200));
            loop {
                timer.tick().await;
                if connection_state.is_finished() {
                    // Set the flag
                    let mut finished_flag = trace_write_lock!(finished_flag);
                    debug!(
                        "finished monitor task detects finished state and has set a finished flag"
                    );
                    *finished_flag = true;
                    break;
                }
            }
            info!("Timer for finished is finished");
            deregister_runtime_component!(&id);
        });
    }

    fn shutdown_writer_from_reader(
        status_code: StatusCode,
        connection_state: ConnectionStateMgr,
        writer_tx: &UnboundedSender<message_queue::Message>,
    ) {
        if connection_state.conditional_set_finished(status_code) {
            error!(
                "Reader has put connection into a finished state with status {}",
                status_code
            );
        }
        // Tell the writer to quit
        debug!("Sending a quit to the writer");
        let _ = writer_tx.send(message_queue::Message::Quit);
    }

    fn spawn_reading_task(
        reader: ReadHalf<TcpStream>,
        writer_tx: UnboundedSender<message_queue::Message>,
        finished_flag: Arc<RwLock<bool>>,
        _receive_buffer_size: usize,
        mut read_state: ReadState,
        id: u32,
    ) {
        // This is the main processing loop that receives and sends messages
        let decoding_options = {
            let secure_channel = trace_read_lock!(read_state.secure_channel);
            secure_channel.decoding_options()
        };

        let mut framed_read =
            FramedRead::new(reader, TcpCodec::new(finished_flag, decoding_options));

        tokio::spawn(async move {
            let id = format!("read-task, {}", id);
            register_runtime_component!(&id);
            // The reader reads frames from the codec, which are messages
            loop {
                let next_msg = framed_read.next().await;
                if next_msg.is_none() {
                    continue;
                }
                match next_msg.unwrap() {
                    Ok(message) => {
                        let mut session_status_code = StatusCode::Good;
                        match message {
                            Message::Acknowledge(ack) => {
                                debug!("Reader got ack {:?}", ack);
                                if read_state.state.state() != ConnectionState::WaitingForAck {
                                    error!("Reader got an unexpected ACK");
                                    session_status_code = StatusCode::BadUnexpectedError;
                                } else {
                                    // TODO revise our sizes and other things according to the ACK
                                    read_state.state.set_state(ConnectionState::Processing);
                                }
                            }
                            Message::Chunk(chunk) => {
                                if read_state.state.state() != ConnectionState::Processing {
                                    error!("Got an unexpected message chunk");
                                    session_status_code = StatusCode::BadUnexpectedError;
                                } else {
                                    match read_state.process_chunk(chunk) {
                                        Ok(response) => {
                                            if let Some(response) = response {
                                                // Store the response
                                                let mut message_queue =
                                                    trace_write_lock!(read_state.message_queue);
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
                            Self::shutdown_writer_from_reader(
                                session_status_code,
                                read_state.state.clone(),
                                &writer_tx,
                            );
                            break;
                        }
                    }
                    Err(err) => {
                        error!("Read loop error {:?}", err);
                        Self::shutdown_writer_from_reader(
                            StatusCode::BadCommunicationError,
                            read_state.state.clone(),
                            &writer_tx,
                        );
                        break;
                    }
                }
            }
            debug!(
                "Read loop finished, connection state = {:?}",
                read_state.state.state()
            );
            deregister_runtime_component!(&id);
        });
    }

    fn spawn_writing_task(
        mut receiver: UnboundedReceiver<message_queue::Message>,
        mut write_state: WriteState,
        id: u32,
    ) {
        // In writing, we wait on outgoing requests, encoding each and writing them out
        tokio::spawn(async move {
            let id = format!("write-task, {}", id);
            register_runtime_component!(&id);
            loop {
                match receiver.recv().await {
                    Some(msg) => {
                        match msg {
                            message_queue::Message::Quit => {
                                debug!("Writer {} received a quit", id);
                                break;
                            }
                            message_queue::Message::SupportedMessage(request) => {
                                if write_state.state.is_finished() {
                                    debug!("Write loop is terminating due to finished state");
                                    break;
                                }
                                let close_connection = {
                                    if write_state.state.state() == ConnectionState::Processing {
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
                                        let _ = write_state.send_request(request);
                                        // Indicate the request was processed
                                        {
                                            let mut message_queue =
                                                trace_write_lock!(write_state.message_queue);
                                            message_queue.request_was_processed(request_handle);
                                        }

                                        if close_connection {
                                            write_state.state.set_finished(StatusCode::Good);
                                            debug!("Writer is setting the connection state to finished(good)");
                                        }
                                        close_connection
                                    } else {
                                        // panic or not, perhaps there is a race
                                        error!(
                                            "Writer, why is the connection state not processing?"
                                        );
                                        write_state
                                            .state
                                            .set_finished(StatusCode::BadUnexpectedError);
                                        true
                                    }
                                };

                                write_state =
                                    Self::write_bytes_task(write_state, close_connection).await;
                            }
                        };
                    }
                    None => {}
                }
            }
            debug!("Writer loop {} is finished", id);
            deregister_runtime_component!(&id);
        });
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    fn spawn_looping_tasks(
        reader: ReadHalf<TcpStream>,
        writer: WriteHalf<TcpStream>,
        connection_state: ConnectionStateMgr,
        session_state: Arc<RwLock<SessionState>>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
    ) {
        let (receive_buffer_size, send_buffer_size, id, max_message_size, max_chunk_count) = {
            let session_state = trace_read_lock!(session_state);
            (
                session_state.receive_buffer_size(),
                session_state.send_buffer_size(),
                session_state.id(),
                session_state.max_message_size(),
                session_state.max_chunk_count(),
            )
        };

        // At this stage, the HEL has been sent but the ACK has not been received
        connection_state.set_state(ConnectionState::WaitingForAck);

        // Abort monitor
        let finished_flag = Arc::new(RwLock::new(false));
        Self::spawn_finished_monitor_task(connection_state.clone(), finished_flag.clone(), id);

        // Create the message receiver that will drive writes
        let (sender, receiver) = {
            let mut message_queue = trace_write_lock!(message_queue);
            message_queue.make_request_channel()
        };

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
            let write_state = WriteState {
                secure_channel,
                state: connection_state,
                send_buffer: MessageWriter::new(
                    send_buffer_size,
                    max_message_size,
                    max_chunk_count,
                ),
                writer,
                message_queue,
            };
            Self::spawn_writing_task(receiver, write_state, id);
        }
    }
}
