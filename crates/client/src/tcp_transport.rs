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
    time,
};

use futures::StreamExt;
use parking_lot::RwLock;
use tokio::{
    self,
    io::{AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::mpsc::UnboundedReceiver,
};
use tokio_util::codec::FramedRead;

use opcua_core::types::status_code::StatusCode;
use opcua_core::{
    comms::{
        message_chunk_info::ChunkInfo,
        message_writer::MessageWriter,
        tcp_codec::{Message, TcpCodec},
        tcp_types::HelloMessage,
        url::hostname_port_from_url,
    },
    constants::DEFAULT_OPC_UA_SERVER_PORT,
    prelude::*,
};

use crate::{
    callbacks::OnSessionClosed,
    message_queue::{self, MessageQueue},
    session::session_state::{ConnectionState, SessionState},
};

// TODO: move this struct to core module
#[derive(Debug)]
struct MessageChunkWithChunkInfo {
    header: ChunkInfo,
    data_with_header: Vec<u8>,
}

struct ReadState {
    pub state: Arc<RwLock<ConnectionState>>,
    pub max_chunk_count: usize,
    last_received_sequence_number: u32,
    chunks: HashMap<u32, Vec<MessageChunkWithChunkInfo>>,
    pub framed_read: FramedRead<ReadHalf<TcpStream>, TcpCodec>,
}

impl ReadState {
    fn new(
        connection_state: Arc<RwLock<ConnectionState>>,
        max_chunk_count: usize,
        framed_read: FramedRead<ReadHalf<TcpStream>, TcpCodec>,
    ) -> Self {
        ReadState {
            state: connection_state,
            max_chunk_count,
            last_received_sequence_number: 0,
            chunks: HashMap::new(),
            framed_read,
        }
    }

    fn turn_received_chunks_into_message(
        &mut self,
        chunks: &[MessageChunk],
        secure_channel: &SecureChannel,
    ) -> Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        self.last_received_sequence_number = Chunker::validate_chunks(
            self.last_received_sequence_number + 1,
            secure_channel,
            chunks,
        )?;
        // Now decode
        Chunker::decode(chunks, secure_channel, None)
    }

    fn process_chunk(
        &mut self,
        chunk: MessageChunk,
        secure_channel: &mut SecureChannel,
    ) -> Result<Option<SupportedMessage>, StatusCode> {
        // trace!("Got a chunk {:?}", chunk);
        let chunk = { secure_channel.verify_and_remove_security(&chunk.data)? };

        let chunk_info = chunk.chunk_info(&secure_channel)?;
        let req_id = chunk_info.sequence_header.request_id;

        match chunk_info.message_header.is_final {
            MessageIsFinalType::Intermediate => {
                let chunks = self.chunks.entry(req_id).or_default();
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

        let chunks = self.chunks.entry(req_id).or_default();
        chunks.push(MessageChunkWithChunkInfo {
            header: chunk_info,
            data_with_header: chunk.data,
        });
        let in_chunks = merge_chunks(self.chunks.remove(&req_id).unwrap())?;
        let message = self.turn_received_chunks_into_message(&in_chunks, secure_channel)?;

        Ok(Some(message))
    }
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

struct WriteState {
    pub writer: WriteHalf<TcpStream>,
    pub send_buffer: MessageWriter,
    pub receiver: UnboundedReceiver<message_queue::Message>,
}

impl WriteState {
    fn new(
        receiver: UnboundedReceiver<message_queue::Message>,
        writer: WriteHalf<TcpStream>,
        send_buffer_size: usize,
        max_message_size: usize,
        max_chunk_count: usize,
    ) -> Self {
        WriteState {
            send_buffer: MessageWriter::new(send_buffer_size, max_message_size, max_chunk_count),
            writer,
            receiver,
        }
    }
    /// Sends the supplied request asynchronously. The returned value is the request id for the
    /// chunked message. Higher levels may or may not find it useful.
    fn send_request(
        &mut self,
        request: SupportedMessage,
        secure_channel: &SecureChannel,
    ) -> Result<u32, StatusCode> {
        let request_id = self.send_buffer.next_request_id();
        self.send_buffer.write(request_id, request, secure_channel)
    }
}

const WAIT_POLLING_TIMEOUT: u64 = 100;

/// Connects the stream to the specified endpoint
pub async fn connect(
    endpoint_url: &str,
    session_state: Arc<RwLock<SessionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
    connection_state: Arc<RwLock<ConnectionState>>,
) -> Result<(), StatusCode> {
    debug_assert!(
        !connection_state.read().is_connected(),
        "Should not try to connect when already connected"
    );
    let (host, port) = hostname_port_from_url(endpoint_url, DEFAULT_OPC_UA_SERVER_PORT)?;

    // Resolve the host name into a socket address
    let addr = {
        let addr = format!("{host}:{port}");
        let addrs = addr.to_socket_addrs();
        if let Ok(mut addrs) = addrs {
            // Take the first resolved ip addr for the hostname
            if let Some(addr) = addrs.next() {
                addr
            } else {
                log::error!("Invalid address {addr}, does not resolve to any socket");
                return Err(StatusCode::BadTcpEndpointUrlInvalid);
            }
        } else {
            error!(
                "Invalid address {addr}, cannot be parsed {:?}",
                addrs.unwrap_err()
            );
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }
    };
    assert_eq!(addr.port(), port);
    let endpoint_url = endpoint_url.to_string();

    let session_state = session_state.clone();

    let conn_task = connection_task(
        addr,
        endpoint_url,
        connection_state.clone(),
        message_queue.clone(),
        session_state.read().send_buffer_size(),
        session_state.read().receive_buffer_size(),
        session_state.read().max_message_size(),
        session_state.read().max_chunk_count(),
        session_state.read().secure_channel.decoding_options(),
    );
    let conn_result = conn_task.await;
    let status = conn_result
        .as_ref()
        .err()
        .copied()
        .unwrap_or(StatusCode::Good);

    if status.is_bad() {
        return Err(status);
    }
    if let Ok((read, write)) = conn_result {
        log::debug!("Spawn looping tasks");
        tokio::spawn(async move {
            if let Err(status) =
                looping_tasks(read, write, session_state.clone(), message_queue).await
            {
                log::debug!("looping tasks stoped with {status:?}");
                *connection_state.write() = ConnectionState::Finished(status);
                session_state.write().on_session_closed(status);
            }
            log::debug!("looping tasks stoped");
        });
    }
    Ok(())
}

/// Disconnects the stream from the server (if it is connected)
pub async fn wait_for_disconnect(connection_state: &Arc<RwLock<ConnectionState>>) {
    log::debug!("Waiting for a disconnect");
    loop {
        trace!("Still waiting for a disconnect");
        if connection_state.read().is_finished() {
            log::debug!("Disconnected");
            break;
        }
        tokio::time::sleep(time::Duration::from_millis(WAIT_POLLING_TIMEOUT)).await;
    }
}

/// This is the main connection task for a connection.
async fn connection_task(
    addr: SocketAddr,
    endpoint_url: String,
    connection_state: Arc<RwLock<ConnectionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
    send_buffer_size: usize,
    receive_buffer_size: usize,
    max_message_size: usize,
    max_chunk_count: usize,
    decoding_options: DecodingOptions,
) -> Result<(ReadState, WriteState), StatusCode> {
    log::debug!("Creating a connection task to connect to {addr} with url {endpoint_url}");

    *connection_state.write() = ConnectionState::Connecting;
    let socket = TcpStream::connect(&addr).await.map_err(|err| {
        log::error!("Could not connect to host {addr}: {err:?}");
        StatusCode::BadCommunicationError
    })?;
    log::debug!("Connected to {addr}");
    *connection_state.write() = ConnectionState::Connected;
    let (reader, writer) = tokio::io::split(socket);

    let (hello, mut read_state, mut write_state) = {
        let hello = HelloMessage::new(
            &endpoint_url,
            send_buffer_size,
            receive_buffer_size,
            max_message_size,
            max_chunk_count,
        );
        let framed_read = FramedRead::new(reader, TcpCodec::new(decoding_options));
        let read_state = ReadState::new(connection_state.clone(), max_chunk_count, framed_read);

        let receiver = {
            message_queue.write().clear();
            message_queue.write().make_request_channel()
        };

        let write_state = WriteState::new(
            receiver,
            writer,
            send_buffer_size,
            max_message_size,
            max_chunk_count,
        );
        (hello, read_state, write_state)
    };

    write_state
        .writer
        .write_all(&hello.encode_to_vec())
        .await
        .map_err(|err| {
            log::error!("Cannot send hello to server: {err:?}");
            StatusCode::BadCommunicationError
        })?;
    *connection_state.write() = ConnectionState::WaitingForAck;
    log::debug!("Wait for acknowledge messsage");
    match read_state.framed_read.next().await {
        Some(Ok(Message::Acknowledge(ack))) => {
            // TODO revise our sizes and other things according to the ACK
            log::trace!("Received acknowledgement: {:?}", ack)
        }
        other => {
            log::error!(
                "Unexpected error while waiting for server ACK. Expected ACK, got {other:?}"
            );
            return Err(StatusCode::BadConnectionClosed);
        }
    };
    *connection_state.write() = ConnectionState::Processing;
    Ok((read_state, write_state))
}

/// This is the main processing loop for the connection. It writes requests and reads responses
/// over the socket to the server.
async fn looping_tasks(
    read_state: ReadState,
    write_state: WriteState,
    session_state: Arc<RwLock<SessionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
) -> Result<(), StatusCode> {
    log::trace!("Spawning read and write loops");
    // Spawn the reading task loop
    let read_loop = reading_task(read_state, session_state.clone(), message_queue.clone());
    // Spawn the writing task loop
    let write_loop = writing_task(write_state, session_state.clone(), message_queue.clone());
    tokio::select! {
        status = read_loop => {
            log::debug!("Closing connection because the read loop terminated");
            return status;
        }
        status = write_loop => {
            log::debug!("Closing connection because the write loop terminated");
            return status;
        }
    }
}

async fn reading_task(
    mut read_state: ReadState,
    session_state: Arc<RwLock<SessionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
) -> Result<(), StatusCode> {
    // This is the main processing loop that receives and sends messages
    log::trace!("Starting reading loop");

    while let Some(next_msg) = read_state.framed_read.next().await {
        log::trace!("Reading loop received message: {:?}", next_msg);

        let message = match next_msg {
            Ok(message) => message,
            Err(err) => {
                log::error!("Read loop error {:?}", err);
                return Err(StatusCode::BadConnectionClosed);
            }
        };

        let mut session_status_code = StatusCode::Good;
        match message {
            Message::Acknowledge(ack) => {
                log::debug!("Reader got an unexpected ack {:?}", ack);
                session_status_code = StatusCode::BadUnexpectedError;
            }
            Message::Chunk(chunk) => {
                match read_state.process_chunk(chunk, &mut session_state.write().secure_channel) {
                    Ok(response) => {
                        if let Some(response) = response {
                            // Store the response
                            message_queue.write().store_response(response);
                        }
                    }
                    Err(err) => session_status_code = err,
                };
            }
            Message::Error(error) => {
                // TODO client should go into an error recovery state, dropping the connection and reestablishing it.
                session_status_code =
                    StatusCode::from_u32(error.error).unwrap_or(StatusCode::BadUnexpectedError);
                log::error!("Expecting a chunk, got an error message {session_status_code}");
            }
            m => {
                log::error!("Expected a recognized message, got {m:?}");
                break;
            }
        }
        if session_status_code.is_bad() {
            return Err(session_status_code);
        }
    }
    debug!(
        "Read loop finished, connection state = {:?}",
        read_state.state
    );
    Ok(())
}

async fn writing_task(
    mut write_state: WriteState,
    session_state: Arc<RwLock<SessionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
) -> Result<(), StatusCode> {
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
                let close_connection =
                    matches!(request, SupportedMessage::CloseSecureChannelRequest(_));
                if close_connection {
                    debug!("Writer is about to send a CloseSecureChannelRequest which means it should close in a moment");
                }

                // Write it to the outgoing buffer
                let request_handle = request.request_handle();
                write_state.send_request(request, &session_state.read().secure_channel)?;
                // Indicate the request was processed
                message_queue.write().request_was_processed(request_handle);
                write_bytes(&mut write_state).await?;
                if close_connection {
                    debug!("Writer is setting the connection state to finished(good)");
                    return Ok(());
                }
            }
        };
    }
    Ok(())
}

async fn write_bytes(write_state: &mut WriteState) -> Result<(), StatusCode> {
    let bytes_to_write = write_state.send_buffer.bytes_to_write();
    log::trace!("write {} bytes", bytes_to_write.len());
    write_state
        .writer
        .write_all(&bytes_to_write)
        .await
        .map_err(|e| {
            error!("write bytes task failed: {}", e);
            StatusCode::BadCommunicationError
        })
}
