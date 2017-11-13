use std::net::TcpStream;
use std::result::Result;
use std::sync::{Arc, Mutex};
use std::io::{Read, ErrorKind};

use chrono::UTC;

use opcua_core::prelude::*;

use session::SessionState;

// TODO these need to go, and use session settings
const RECEIVE_BUFFER_SIZE: usize = 1024 * 64;
//const SEND_BUFFER_SIZE: usize = 1024 * 64;
//const MAX_MESSAGE_SIZE: usize = 1024 * 64;

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
    /// Secure channel information
    secure_channel: SecureChannel,
    /// Last request id, used to track async requests
    last_request_id: UInt32,
}

impl TcpTransport {
    pub fn new(certificate_store: Arc<Mutex<CertificateStore>>, session_state: Arc<Mutex<SessionState>>) -> TcpTransport {
        let receive_buffer_size = {
            let session_state = session_state.lock().unwrap();
            session_state.receive_buffer_size
        };

        let secure_channel = SecureChannel::new(certificate_store);

        TcpTransport {
            session_state,
            stream: None,
            message_buffer: MessageBuffer::new(receive_buffer_size),
            last_sent_sequence_number: 0,
            last_received_sequence_number: 0,
            last_request_id: 1000,
            secure_channel,
        }
    }

    pub fn hello(&mut self, endpoint_url: &str) -> Result<(), StatusCode> {
        let msg = {
            let session_state = self.session_state.clone();
            let session_state = session_state.lock().unwrap();
            HelloMessage::new(endpoint_url,
                              session_state.send_buffer_size as UInt32,
                              session_state.receive_buffer_size as UInt32,
                              session_state.max_message_size as UInt32)
        };
        debug!("Sending HEL {:?}", msg);
        let stream = self.stream();
        let _ = msg.encode(stream)?;

        // Listen for ACK
        debug!("Waiting for ack");
        let ack = AcknowledgeMessage::decode(stream)?;

        // Process ack
        debug!("Got ACK {:?}", ack);

        Ok(())
    }

    pub fn connect(&mut self, endpoint_url: &str) -> Result<(), StatusCode> {
        use url::Url;

        // let session_state = self.session_state.lock().unwrap();

        // Validate and split out the endpoint we have
        let result = Url::parse(&endpoint_url);
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
            return Err(BAD_SERVER_NOT_CONNECTED);
        }

        debug!("Connected...");

        self.stream = Some(stream.unwrap());
        Ok(())
    }

    pub fn disconnect(&mut self) {
        if self.stream.is_some() {
            self.stream = None;
        }
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn stream(&mut self) -> &mut TcpStream {
        self.stream.as_mut().unwrap()
    }

    fn turn_received_chunks_into_message(&mut self, chunks: &Vec<MessageChunk>) -> Result<SupportedMessage, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        self.last_received_sequence_number = Chunker::validate_chunk_sequences(self.last_received_sequence_number + 1, &self.secure_channel, chunks)?;
        // Now decode
        Chunker::decode(&chunks, &self.secure_channel, None)
    }

    fn process_chunk(&mut self, chunk: MessageChunk) -> Result<Option<SupportedMessage>, StatusCode> {
        trace!("Got a chunk {:?}", chunk);

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

    fn wait_for_response(&mut self, request_id: UInt32, request_timeout: UInt32) -> Result<SupportedMessage, StatusCode> {
        // This loop terminates when the corresponding response comes back or a timeout occurs

        debug!("Waiting for a response for request id {}", request_id);
        // TODO buffer size
        let mut in_buf = vec![0u8; RECEIVE_BUFFER_SIZE];

        let session_status_code;
        let start = UTC::now();
        'message_loop: loop {
            // Check for a timeout
            let now = UTC::now();
            let request_duration = now.signed_duration_since(start);
            if request_duration.num_milliseconds() > request_timeout as i64 {
                debug!("Time waiting {}ms exceeds timeout {}ms waiting for response from request id {}", request_duration.num_milliseconds(), request_timeout, request_id);
                session_status_code = BAD_TIMEOUT;
                break;
            }

            // TODO this is practically cut and pasted from server loop and should be common to both

            // decode response
            let bytes_read_result = self.stream().read(&mut in_buf);
            if bytes_read_result.is_err() {
                let error = bytes_read_result.unwrap_err();
                if error.kind() == ErrorKind::TimedOut {
                    continue;
                }

                // TODO check for broken socket. if this occurs, the code should go into an error
                // recovery state

                debug!("Read error - kind = {:?}, {:?}", error.kind(), error);
                session_status_code = BAD_UNEXPECTED_ERROR;
                break;
            }
            let bytes_read = bytes_read_result.unwrap();
            if bytes_read == 0 {
                continue;
            }
            trace!("Bytes read = {}", bytes_read);

            // TODO this is practically cut and pasted from server loop and should be common to both
            let result = self.message_buffer.store_bytes(&in_buf[0..bytes_read]);
            if result.is_err() {
                session_status_code = result.unwrap_err();
                break;
            }
            let messages = result.unwrap();
            for message in messages {
                if let Message::MessageChunk(chunk) = message {
                    let result = self.process_chunk(chunk)?;
                    if result.is_some() {
                        // TODO check the response request_handle to see if it matches our request
                        return Ok(result.unwrap());
                    }
                } else {
                    // TODO if this is an ERROR chunk, then the client should go into an error
                    // recovery state, dropping the connection and reestablishing it.

                    // This is not a regular message, so what is happening?
                    error!("Expecting a chunk, got something that was not a chunk {:?}", message);
                    session_status_code = BAD_UNEXPECTED_ERROR;
                    break 'message_loop;
                }
            }
            // TODO error recovery state
        }
        Err(session_status_code)
    }

    pub fn send_request(&mut self, request: SupportedMessage) -> Result<SupportedMessage, StatusCode> {
        // let request_timeout = request_header.timeout_hint;
        trace!("Sending a request");
        let request_timeout = 5000; // TODO
        let request_id = self.async_send_request(request)?;
        self.wait_for_response(request_id, request_timeout)
    }

    fn next_request_id(&mut self) -> UInt32 {
        self.last_request_id += 1;
        self.last_request_id
    }

    pub fn async_send_request(&mut self, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        if !self.is_connected() {
            return Err(BAD_SERVER_NOT_CONNECTED);
        }

        let request_id = self.next_request_id();

        // TODO This needs to wait for up to the timeout hint in the request header for a response
        // with the same request handle to return. Other messages might arrive during that, so somehow
        // we have to deal with that situation too, e.g. queuing them up.

        trace!("Sending request");

        // Turn message to chunk(s)
        // TODO max message size and max chunk size
        let chunks = Chunker::encode(self.last_sent_sequence_number + 1, request_id, 0, 0, &self.secure_channel, &request)?;

        // Sequence number monotonically increases per chunk
        self.last_sent_sequence_number += chunks.len() as UInt32;

        // Send chunks
        let stream = self.stream();
        for chunk in chunks {
            trace!("Sending chunk of type {:?}", chunk.message_header()?.message_type);
            let _ = chunk.encode(stream)?;
        }

        trace!("Request sent");

        Ok(request_id)
    }
}