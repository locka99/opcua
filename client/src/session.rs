use std::result::Result;

use opcua_core::comms::*;
use opcua_core::types::*;
use opcua_core::services::*;

use comms::*;

pub struct SessionState {
    /// The endpoint url
    pub endpoint_url: String,
    /// The request timeout is how long the session will wait from sending a request expecting a response
    /// if no response is received the client will terminate.
    pub request_timeout: u32,
    /// Session timeout in milliseconds
    pub session_timeout: u32,
    /// Size of the send buffer
    pub send_buffer_size: usize,
    /// Size of the
    pub receive_buffer_size: usize,
    /// Maximum message size
    pub max_message_size: usize,
    /// The next handle to assign to a request
    next_request_handle: UInt32,
    /// The authentication token negotiated with the server (if any)
    authentication_token: NodeId,
    /// Secure channel information
    secure_channel_info: SecureChannelInfo,
    /// Last encoded sequence number
    last_sent_sequence_number: UInt32,
    /// Last decoded sequence number
    last_received_sequence_number: UInt32,
}

impl SessionState {}

pub struct Session {
    /// Runtime state of the session, reset if disconnected
    pub session_state: SessionState,
    /// Transport layer
    transport: TcpTransport,
}

impl Session {
    pub fn new(endpoint_url: &str) -> Session {
        Session {
            session_state: SessionState {
                endpoint_url: endpoint_url.to_string(),
                session_timeout: 60 * 1000,
                request_timeout: 10 * 1000,
                send_buffer_size: 65536,
                receive_buffer_size: 65536,
                max_message_size: 65536,
                next_request_handle: 1,
                authentication_token: NodeId::null(),
                secure_channel_info: SecureChannelInfo::new(),
                last_sent_sequence_number: 0,
                last_received_sequence_number: 0,
            },
            transport: TcpTransport::new()
        }
    }

    pub fn connect(&mut self) -> Result<(), &'static StatusCode> {
        let session_state = &mut self.session_state;

        let _ = self.transport.connect(session_state)?;
        let _ = self.transport.send_hello(session_state)?;
        // Send create session
        // Send activate session

        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.transport.disconnect();
    }

    /// Synchronously browses the nodes specified in the list of browse descriptions
    pub fn browse(&mut self) {
        // Send browse_request
    }

    /// Construct a request header for the session
    fn make_request_header(&mut self) -> RequestHeader {
        let session_state = &mut self.session_state;
        let request_header = RequestHeader {
            authentication_token: session_state.authentication_token.clone(),
            timestamp: DateTime::now(),
            request_handle: session_state.next_request_handle,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: session_state.request_timeout,
            additional_header: ExtensionObject::null(),
        };
        session_state.next_request_handle += 1;
        request_header
    }

    pub fn get_endpoints(&mut self) -> Result<Vec<EndpointDescription>, &'static StatusCode> {
        let request = GetEndpointsRequest {
            request_header: self.make_request_header(),
            endpoint_url: UAString::from_str(&self.session_state.endpoint_url),
            locale_ids: None,
            profile_uris: None,
        };

        let request_handle = request.request_header.request_handle;
        let request_timeout = request.request_header.timeout_hint;

        let response = self.transport.send_request(request_handle, request_timeout, SupportedMessage::GetEndpointsRequest(request))?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            Err(&BAD_UNKNOWN_RESPONSE)
        }
        else {
            Err(&BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Synchronously browses a single node
    pub fn browse_node(&mut self) {
        // Send browse request for one node
    }

    /// Synchronously reads values from the server
    pub fn read(&mut self) {
        // Read a bunch of values
    }

    /// Synchronously writes values to the server
    pub fn write(&mut self) {
        // Write to a bunch of values
    }
}