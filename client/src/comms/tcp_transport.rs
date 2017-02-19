use std::net::{TcpStream};
use std::result::Result;

use opcua_core::comms::*;
use opcua_core::types::*;

use session::*;

pub struct TcpTransport {
    stream: Option<TcpStream>,
}

impl TcpTransport {
    pub fn new() -> TcpTransport {
        TcpTransport {
            stream: None,
        }
    }

    pub fn connect(&mut self, session_state: &mut SessionState) -> Result<(), &'static StatusCode> {
        use url::{Url};

        // Validate and split out the endpoint we have
        let result = Url::parse(&session_state.endpoint_url);
        if result.is_err() {
            return Err(&BAD_TCP_ENDPOINT_URL_INVALID);
        }
        let url = result.unwrap();
        if url.scheme() != "opc.tcp" || !url.has_host() {
            return Err(&BAD_TCP_ENDPOINT_URL_INVALID);
        }

        debug!("Connecting to {:?}", url);
        let host = url.host_str().unwrap();
        let port = if url.port().is_some() { url.port().unwrap() } else { 4840 };

        let stream = TcpStream::connect((host, port));
        if stream.is_err() {
            error!("Could not connect to host {}:{}", host, port);
            return Err(&BAD_NOT_CONNECTED);
        }
        self.stream = Some(stream.unwrap());
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn stream(&mut self) -> &mut TcpStream {
        self.stream.as_mut().unwrap()
    }

    pub fn send_request(&mut self, request_handle: UInt32, request_timeout: UInt32, request: SupportedMessage) -> Result<SupportedMessage, &'static StatusCode> {
        if !self.is_connected() {
            return Err(&BAD_NOT_CONNECTED);
        }
        /// This needs to wait for up to the timeout hint in the request header for a response
        /// with the same request handle to return. Other messages might arrive during that, so somehow
        /// we have to deal with that situation too, e.g. queuing them up.

        // Turn message to chunks
        // Send chunks

        // while ! timeout
        // receive chunks
        // decode response
        // if response.request_handle == request_handle {
        //  return Ok()
        // else
        //  async_callback(message)


        Err(&BAD_NOT_IMPLEMENTED)
    }

    pub fn async_send_request(&mut self, request: SupportedMessage) -> Result<(), &'static StatusCode> {
        if !self.is_connected() {
            return Err(&BAD_NOT_CONNECTED);
        }

        // Turn message to chunks
        // Send chunks

        Err(&BAD_NOT_IMPLEMENTED)
    }


    pub fn disconnect(&mut self) {
        if self.stream.is_some() {
            self.stream = None;
        }
    }

    pub fn send_hello(&mut self, session_state: &mut SessionState) -> Result<(), &'static StatusCode> {
        let stream = self.stream.as_mut().unwrap();
        let hello = HelloMessage::new(&session_state.endpoint_url,
                                      session_state.send_buffer_size as UInt32,
                                      session_state.receive_buffer_size as UInt32,
                                      session_state.max_message_size as UInt32);
        let _ = hello.encode(stream)?;

        // Listen for ACK

        Ok(())
    }
}