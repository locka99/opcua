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
    io::{AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::mpsc::UnboundedReceiver,
    time::Duration,
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
};
use crate::sync::*;
use crate::types::status_code::StatusCode;

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
    pub framed_read: FramedRead<ReadHalf<TcpStream>, TcpCodec>,
}

impl Drop for ReadState {
    fn drop(&mut self) {
        info!("ReadState has dropped");
    }
}

impl ReadState {
    fn new(
        connection_state: ConnectionStateMgr,
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
        session_state: &SessionState,
        framed_read: FramedRead<ReadHalf<TcpStream>, TcpCodec>,
    ) -> Self {
        ReadState {
            secure_channel,
            state: connection_state,
            max_chunk_count: session_state.max_chunk_count(),
            last_received_sequence_number: 0,
            message_queue,
            chunks: HashMap::new(),
            framed_read,
        }
    }
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
                    // TODO this code should return an error to be safe
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
    /// The url to connect to
    pub secure_channel: Arc<RwLock<SecureChannel>>,
    pub message_queue: Arc<RwLock<MessageQueue>>,
    pub writer: WriteHalf<TcpStream>,
    /// The send buffer
    pub send_buffer: MessageWriter,
    pub receiver: UnboundedReceiver<message_queue::Message>,
}

impl Drop for WriteState {
    fn drop(&mut self) {
        info!("WriteState has dropped");
    }
}

impl WriteState {
    fn new(
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
        writer: WriteHalf<TcpStream>,
        session_state: &SessionState,
    ) -> Self {
        let receiver = {
            let mut queue = trace_write_lock!(message_queue);
            queue.clear();
            queue.make_request_channel()
        };
        WriteState {
            secure_channel,
            send_buffer: MessageWriter::new(
                session_state.send_buffer_size(),
                session_state.max_message_size(),
                session_state.max_chunk_count(),
            ),
            writer,
            message_queue,
            receiver,
        }
    }
    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn send_request(&mut self, request: SupportedMessage) -> Result<u32, StatusCode> {
        let secure_channel = trace_read_lock!(self.secure_channel);
        let request_id = self.send_buffer.next_request_id();
        self.send_buffer.write(request_id, request, &secure_channel)
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
        single_threaded_executor: bool,
    ) -> TcpTransport {
        let connection_state = {
            let session_state = trace_read_lock!(session_state);
            session_state.connection_state()
        };

        let message_queue = {
            let session_state = trace_read_lock!(session_state);
            session_state.message_queue.clone()
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
        debug_assert!(!self.is_connected(), "Should not try to connect when already connected");
        let (host, port) =
            hostname_port_from_url(endpoint_url, crate::core::constants::DEFAULT_OPC_UA_SERVER_PORT)?;

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
        let endpoint_url = endpoint_url.to_string();

        let (connection_state,
            session_state,
            secure_channel,
            message_queue,
        ) = (self.connection_state.clone(),
             self.session_state.clone(),
             self.secure_channel.clone(),
             self.message_queue.clone(), );

        let (connection_status_sender,
            connection_status_receiver) = std::sync::mpsc::channel();
        let conn_task = Self::connection_task(
            addr,
            connection_state.clone(),
            endpoint_url,
            session_state.clone(),
            secure_channel,
            message_queue,
        );
        let runtime = self.runtime.clone();
        thread::spawn(move || {
            trace_lock!(runtime).block_on(async move {
                let conn_result = conn_task.await;
                let mut status = conn_result.as_ref().err().copied().unwrap_or(StatusCode::Good);
                let _ = connection_status_sender.send(if status.is_bad() { Err(status) } else { Ok(()) });
                if let Ok((read, write)) = conn_result {
                    status = Self::spawn_looping_tasks(read, write).await.err().unwrap_or(StatusCode::Good);
                }
                connection_state.set_finished(status);
                trace_write_lock!(session_state).on_session_closed(status);
            });
        });
        connection_status_receiver.recv().expect("channel should never be dropped here")
    }

    /// Disconnects the stream from the server (if it is connected)
    pub fn wait_for_disconnect(&self) {
        debug!("Waiting for a disconnect");
        loop {
            trace!("Still waiting for a disconnect");
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
        addr: SocketAddr,
        connection_state: ConnectionStateMgr,
        endpoint_url: String,
        session_state: Arc<RwLock<SessionState>>,
        secure_channel: Arc<RwLock<SecureChannel>>,
        message_queue: Arc<RwLock<MessageQueue>>,
    ) -> Result<(ReadState, WriteState), StatusCode> {
        debug!(
            "Creating a connection task to connect to {} with url {}",
            addr, endpoint_url
        );

        connection_state.set_state(ConnectionState::Connecting);
        let socket = TcpStream::connect(&addr).await.map_err(|err| {
            error!("Could not connect to host {}, {:?}", addr, err);
            StatusCode::BadCommunicationError
        })?;
        connection_state.set_state(ConnectionState::Connected);
        let (reader, writer) = tokio::io::split(socket);

        let (hello, mut read_state, mut write_state) = {
            let session_state = trace_read_lock!(session_state);
            let hello = HelloMessage::new(
                &endpoint_url,
                session_state.send_buffer_size(),
                session_state.receive_buffer_size(),
                session_state.max_message_size(),
                session_state.max_chunk_count(),
            );
            let decoding_options = trace_read_lock!(secure_channel).decoding_options();
            let framed_read = FramedRead::new(reader, TcpCodec::new(decoding_options));
            let read_state = ReadState::new(
                connection_state.clone(),
                secure_channel.clone(),
                message_queue.clone(),
                &session_state,
                framed_read,
            );
            let write_state = WriteState::new(
                secure_channel.clone(),
                message_queue.clone(),
                writer,
                &session_state,
            );
            (hello, read_state, write_state)
        };

        write_state.writer.write_all(&hello.encode_to_vec()).await.map_err(|err| {
            error!("Cannot send hello to server, err = {:?}", err);
            StatusCode::BadCommunicationError
        })?;
        connection_state.set_state(ConnectionState::WaitingForAck);
        match read_state.framed_read.next().await {
            Some(Ok(Message::Acknowledge(ack))) => {
                // TODO revise our sizes and other things according to the ACK
                log::trace!("Received acknowledgement: {:?}", ack)
            }
            other => {
                error!("Unexpected error while waiting for server ACK. Expected ACK, got {:?}", other);
                return Err(StatusCode::BadConnectionClosed);
            }
        };
        connection_state.set_state(ConnectionState::Processing);
        Ok((read_state, write_state))
    }

    async fn write_bytes_task(
        write_state: &mut WriteState,
    ) -> Result<(), StatusCode> {
        let bytes_to_write = write_state.send_buffer.bytes_to_write();
        write_state.writer.write_all(&bytes_to_write).await.map_err(|e| {
            error!("write bytes task failed: {}", e);
            StatusCode::BadCommunicationError
        })
    }

    async fn spawn_reading_task(mut read_state: ReadState) -> Result<(), StatusCode> {
        // This is the main processing loop that receives and sends messages
        trace!("Starting reading loop");
        while let Some(next_msg) = read_state.framed_read.next().await {
            log::trace!("Reading loop received message: {:?}", next_msg);
            match next_msg {
                Ok(message) => {
                    let mut session_status_code = StatusCode::Good;
                    match message {
                        Message::Acknowledge(ack) => {
                            debug!("Reader got an unexpected ack {:?}", ack);
                            session_status_code = StatusCode::BadUnexpectedError;
                        }
                        Message::Chunk(chunk) => {
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
                        m => {
                            error!("Expected a recognized message, got {:?}", m);
                            break;
                        }
                    }
                    if session_status_code.is_bad() {
                        return Err(session_status_code);
                    }
                }
                Err(err) => {
                    error!("Read loop error {:?}", err);
                    return Err(StatusCode::BadConnectionClosed);
                }
            }
        }
        debug!("Read loop finished, connection state = {:?}", read_state.state.state());
        Ok(())
    }

    async fn spawn_writing_task(mut write_state: WriteState) -> Result<(), StatusCode> {
        // In writing, we wait on outgoing requests, encoding each and writing them out
        trace!("Starting writing loop");
        while let Some(msg) = write_state.receiver.recv().await {
            trace!("Writing loop received message: {:?}", msg);
            match msg {
                message_queue::Message::Quit => {
                    debug!("Writer received a quit");
                    return Ok(());
                }
                message_queue::Message::SupportedMessage(request) => {
                    trace!("Sending Request: {:?}", request);
                    let close_connection = matches!(request, SupportedMessage::CloseSecureChannelRequest(_));
                    if close_connection {
                        debug!("Writer is about to send a CloseSecureChannelRequest which means it should close in a moment");
                    }

                    // Write it to the outgoing buffer
                    let request_handle = request.request_handle();
                    write_state.send_request(request)?;
                    // Indicate the request was processed
                    {
                        let mut message_queue =
                            trace_write_lock!(write_state.message_queue);
                        message_queue.request_was_processed(request_handle);
                    }
                    Self::write_bytes_task(&mut write_state).await?;
                    if close_connection {
                        debug!("Writer is setting the connection state to finished(good)");
                        return Ok(());
                    }
                }
            };
        }
        Ok(())
    }

    /// This is the main processing loop for the connection. It writes requests and reads responses
    /// over the socket to the server.
    async fn spawn_looping_tasks(read_state: ReadState, write_state: WriteState) -> Result<(), StatusCode> {
        log::trace!("Spawning read and write loops");
        // Spawn the reading task loop
        let read_loop = Self::spawn_reading_task(read_state);
        // Spawn the writing task loop
        let write_loop = Self::spawn_writing_task(write_state);
        tokio::select! {
            status = read_loop => {
                log::debug!("Closing connection because the read loop terminated");
                status
            }
            status = write_loop => {
                log::debug!("Closing connection because the write loop terminated");
                status
            }
        }
        // Both the read and write halves are dropped at this point, and the connection is closed
    }
}
