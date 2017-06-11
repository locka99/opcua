use std::net::{TcpStream};
use std::result::Result;
use std::sync::{Arc, Mutex};
use std::io::{Read, ErrorKind};

use chrono::*;

use opcua_core::prelude::*;

use session::*;

pub struct TcpTransport {
    /// Session state
    session_state: Arc<Mutex<SessionState>>,
    /// Currently open stream or none
    stream: Option<TcpStream>,
    /// Message buffer where portions of messages are stored to be built into chunks
    message_buffer: MessageBuffer,
    /// Last encoded sequence number
    last_sent_sequence_number: UInt32,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
    /// Last request id, used to track async requests
    last_request_id: UInt32,
    /// Secure channel information
    pub secure_channel_token: SecureChannelToken,
}

impl TcpTransport {
    pub fn new(session_state: Arc<Mutex<SessionState>>) -> TcpTransport {
        let receive_buffer_size = {
            let session_state = session_state.lock().unwrap();
            session_state.receive_buffer_size
        };

        TcpTransport {
            session_state: session_state,
            stream: None,
            message_buffer: MessageBuffer::new(receive_buffer_size),
            last_sent_sequence_number: 0,
            last_received_sequence_number: 0,
            last_request_id: 1000,
            secure_channel_token: SecureChannelToken::new(),
        }
    }

    pub fn connect(&mut self) -> Result<(), StatusCode> {
        use url::{Url};

        let session_state = self.session_state.lock().unwrap();

        // Validate and split out the endpoint we have
        let result = Url::parse(&session_state.endpoint_url);
        if result.is_err() {
            return Err(BAD_TCP_ENDPOINT_URL_INVALID);
        }
        let url = result.unwrap();
        if url.scheme() != "opc.tcp" || !url.has_host() {
            return Err(BAD_TCP_ENDPOINT_URL_INVALID);
        }

        debug!("Connecting to {:?}", url);
        let host = url.host_str().unwrap();
        let port = if url.port().is_some() { url.port().unwrap() } else { 4840 };

        let stream = TcpStream::connect((host, port));
        if stream.is_err() {
            error!("Could not connect to host {}:{}", host, port);
            return Err(BAD_NOT_CONNECTED);
        }

        debug!("Connected...");

        self.stream = Some(stream.unwrap());
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn stream(&mut self) -> &mut TcpStream {
        self.stream.as_mut().unwrap()
    }

    fn turn_received_chunks_into_message(&mut self, chunks: &Vec<Chunk>) -> Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        self.last_received_sequence_number = Chunker::validate_chunk_sequences(self.last_received_sequence_number + 1, &self.secure_channel_token, chunks)?;
        // Now decode
        Chunker::decode(&chunks, &self.secure_channel_token, None)
    }

    fn process_chunk(&mut self, chunk: Chunk) -> Result<Option<SupportedMessage>, StatusCode> {
        debug!("Got a chunk {:?}", chunk);

        if chunk.chunk_header.chunk_type == ChunkType::Intermediate {
            panic!("We don't support intermediate chunks yet");
        } else if chunk.chunk_header.chunk_type == ChunkType::FinalError {
            info!("Discarding chunk marked in as final error");
            return Ok(None)
        }

        let chunk_message_type = chunk.chunk_header.message_type.clone();
        let in_chunks = vec![chunk];
        let message = self.turn_received_chunks_into_message(&in_chunks)?;

        Ok(Some(message))
    }

    fn wait_for_response(&mut self, request_id: UInt32, request_timeout: UInt32) -> Result<SupportedMessage, StatusCode> {
        // This loop terminates when the corresponding response comes back or a timeout occurs

        let mut receive_buffer = {
            let session_state = self.session_state.lock().unwrap();
            Box::new(Vec::with_capacity(session_state.receive_buffer_size))
        };

        debug!("Waiting for a response for request id {}", request_id);

        let start = UTC::now();
        loop {
            let now = UTC::now();
            let request_duration = now.signed_duration_since(start);
            if request_duration.num_milliseconds() > request_timeout as i64 {
                debug!("Time expired waiting for response from request id {}", request_id);
                break;
            }

            // decode response
            let bytes_read = {
                let stream = self.stream();
                let bytes_read_result = stream.read(&mut receive_buffer);
                if bytes_read_result.is_err() {
                    let error = bytes_read_result.unwrap_err();
                    if error.kind() == ErrorKind::TimedOut {
                        continue;
                    }
                    debug!("Read error - kind = {:?}, {:?}", error.kind(), error);
                    return Err(BAD_TCP_INTERNAL_ERROR);
                }
                bytes_read_result.unwrap()
            };
            if bytes_read == 0 {
                continue;
            }

            let messages = self.message_buffer.store_bytes(&receive_buffer[0..bytes_read])?;
            for message in messages {
                debug!("Processing message");
                if let Message::Chunk(chunk) = message {
                    let result = self.process_chunk(chunk)?;
                    if result.is_some() {
                        // TODO check the response request_handle to see if it matches our request
                        return Ok(result.unwrap())
                    }
                } else {
                    // This is not a regular message, so what is happening?
                    error!("Expecting a chunk, got something that was not a chunk {:?}", message);
                    return Err(BAD_UNEXPECTED_ERROR);
                }
            }
        }

        Err(BAD_TIMEOUT)
    }

    pub fn send_request(&mut self, request: SupportedMessage) -> Result<SupportedMessage, StatusCode> {
        // let request_timeout = request_header.timeout_hint;
        let request_timeout = 5; // TODO

        let request_id = self.next_request_id();
        self.async_send_request(request_id, request)?;
        self.wait_for_response(request_id, request_timeout)
    }

    fn next_request_id(&mut self) -> UInt32 {
        self.last_request_id += 1;
        self.last_request_id
    }

    pub fn async_send_request(&mut self, request_id: UInt32, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        if !self.is_connected() {
            return Err(BAD_NOT_CONNECTED);
        }

        // TODO This needs to wait for up to the timeout hint in the request header for a response
        // with the same request handle to return. Other messages might arrive during that, so somehow
        // we have to deal with that situation too, e.g. queuing them up.

        // Turn message to chunk(s)
        let chunks = Chunker::encode(self.last_sent_sequence_number + 1, request_id, &self.secure_channel_token, &request)?;

        // Sequence number monotonically increases per chunk
        self.last_sent_sequence_number += chunks.len() as UInt32;

        // Send chunks
        let stream = self.stream();
        for chunk in chunks {
            let _ = chunk.encode(stream)?;
        }

        Ok(request_id)
    }

    pub fn disconnect(&mut self) {
        if self.stream.is_some() {
            self.stream = None;
        }
    }

    pub fn send_hello(&mut self) -> Result<(), StatusCode> {
        let session_state = self.session_state.clone();
        let session_state = session_state.lock().unwrap();

        let mut stream = self.stream();
        let hello = HelloMessage::new(&session_state.endpoint_url,
                                      session_state.send_buffer_size as UInt32,
                                      session_state.receive_buffer_size as UInt32,
                                      session_state.max_message_size as UInt32);
        let _ = hello.encode(stream)?;

        // Listen for ACK

        Ok(())
    }
}