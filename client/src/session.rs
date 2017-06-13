use std::result::Result;
use std::sync::{Arc, Mutex};

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
    pub last_request_handle: UInt32,
    /// The authentication token negotiated with the server (if any)
    pub authentication_token: NodeId,
}

impl SessionState {}

pub struct Session {
    /// Runtime state of the session, reset if disconnected
    session_state: Arc<Mutex<SessionState>>,
    /// Transport layer
    transport: TcpTransport,
}

impl Session {
    pub fn new(endpoint_url: &str) -> Session {
        let session_state = Arc::new(Mutex::new(SessionState {
            endpoint_url: endpoint_url.to_string(),
            session_timeout: 60 * 1000,
            request_timeout: 10 * 1000,
            send_buffer_size: 65536,
            receive_buffer_size: 65536,
            max_message_size: 65536,
            last_request_handle: 1,
            authentication_token: NodeId::null(),
        }));
        let transport = TcpTransport::new(session_state.clone());
        Session {
            session_state: session_state,
            transport: transport,
        }
    }

    pub fn connect(&mut self) -> Result<(), StatusCode> {
        let _ = self.transport.connect()?;
        let _ = self.transport.send_hello()?;

        // send getendpoints
        let endpoints = self.get_endpoints()?;
        debug!("Endpoints = {:?}", endpoints);

        // Send create session
        // Send activate session

        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.transport.disconnect();
    }

    pub fn get_endpoints(&mut self) -> Result<Option<Vec<EndpointDescription>>, StatusCode> {
        debug!("Fetching end points...");

        let session_state = self.session_state.clone();
        let session_state = session_state.lock().unwrap();

        let request = GetEndpointsRequest {
            request_header: self.make_request_header(),
            endpoint_url: UAString::from_str(&session_state.endpoint_url),
            locale_ids: None,
            profile_uris: None,
        };

        let response = self.transport.send_request(SupportedMessage::GetEndpointsRequest(request))?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            Ok(response.endpoints)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Synchronously browses the nodes specified in the list of browse descriptions
    pub fn browse(&mut self, nodes_to_browse: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        let request = BrowseRequest {
            request_header: self.make_request_header(),
            view: ViewDescription {
                view_id: NodeId::null(),
                timestamp: DateTime::now(),
                view_version: 0,
            },
            requested_max_references_per_node: 1000,
            nodes_to_browse: Some(nodes_to_browse.to_vec())
        };
        let response = self.transport.send_request(SupportedMessage::BrowseRequest(request))?;
        if let SupportedMessage::BrowseResponse(response) = response {
            Ok(response.results)
        }
        else {
            Err(BAD_NOT_IMPLEMENTED)
        }
    }

    /// Synchronously Read attributes from one or more nodes on the server
    pub fn read_nodes(&mut self, nodes_to_read: &[ReadValueId]) -> Result<Option<Vec<DataValue>>, StatusCode> {
        let request = ReadRequest {
            request_header: self.make_request_header(),
            max_age: 1f64,
            timestamps_to_return: TimestampsToReturn::Server,
            nodes_to_read: Some(nodes_to_read.to_vec()),
        };
        let response = self.transport.send_request(SupportedMessage::ReadRequest(request))?;
        if let SupportedMessage::ReadResponse(response) = response {
            Ok(response.results)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Synchronously writes values to the server
    pub fn write_value(&mut self, nodes_to_write: &[WriteValue]) -> Result<Option<Vec<StatusCode>>, StatusCode> {
        let request = WriteRequest {
            request_header: self.make_request_header(),
            nodes_to_write: Some(nodes_to_write.to_vec()),
        };
        let response = self.transport.send_request(SupportedMessage::WriteRequest(request))?;
        if let SupportedMessage::WriteResponse(response) = response {
            Ok(response.results)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Construct a request header for the session
    fn make_request_header(&mut self) -> RequestHeader {
        let mut session_state = self.session_state.lock().unwrap();
        session_state.last_request_handle += 1;
        let request_header = RequestHeader {
            authentication_token: session_state.authentication_token.clone(),
            timestamp: DateTime::now(),
            request_handle: session_state.last_request_handle,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: session_state.request_timeout,
            additional_header: ExtensionObject::null(),
        };
        request_header
    }
}