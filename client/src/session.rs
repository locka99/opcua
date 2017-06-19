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
    /// Channel token
    pub channel_token: Option<ChannelSecurityToken>,
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
            channel_token: None
        }));
        let transport = TcpTransport::new(session_state.clone());
        Session {
            session_state: session_state,
            transport: transport,
        }
    }

    /// Connects to the server (if possible) using the configured session arguments
    pub fn connect(&mut self) -> Result<(), StatusCode> {
        let _ = self.transport.connect()?;
        let _ = self.transport.hello()?;
        let _ = self.open_secure_channel()?;
        Ok(())
    }

    /// Connects to the server and activates a session
    pub fn connect_and_activate_session(&mut self) -> Result<(), StatusCode> {
        let _ = self.connect()?;
        let _ = self.create_session()?;
        let _ = self.activate_session()?;
        Ok(())
    }

    /// Disconnect from the server
    pub fn disconnect(&mut self) {
        let _ = self.close_secure_channel();
        self.transport.disconnect();
    }

    /// Sends an OpenSecureChannel request to the server
    pub fn open_secure_channel(&mut self) -> Result<(), StatusCode> {
        let request = OpenSecureChannelRequest {
            request_header: self.make_request_header(),
            client_protocol_version: 0,
            request_type: SecurityTokenRequestType::Issue,
            security_mode: MessageSecurityMode::None,
            client_nonce: ByteString::from_bytes(&[0]),
            requested_lifetime: 60000,
        };
        let response = self.send_request(SupportedMessage::OpenSecureChannelRequest(request))?;
        if let SupportedMessage::OpenSecureChannelResponse(response) = response {
            {
                let session_state = self.session_state.clone();
                let mut session_state = session_state.lock().unwrap();
                session_state.channel_token = Some(response.security_token);
                // TODO tell TCP channel about the channel token info so it can sign, sign+encrypt
                // messages using the token
            }
            Ok(())
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends a CloseSecureChannel request to the server
    pub fn close_secure_channel(&mut self) -> Result<(), StatusCode> {
        let request = CloseSecureChannelRequest {
            request_header: self.make_request_header(),
        };
        let response = self.send_request(SupportedMessage::CloseSecureChannelRequest(request))?;
        if let SupportedMessage::CloseSecureChannelResponse(_) = response {
            Ok(())
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends a CreateSession request to the server
    pub fn create_session(&mut self) -> Result<(), StatusCode> {
        let request = CreateSessionRequest {
            request_header: self.make_request_header(),
            client_description: ApplicationDescription {
                application_uri: UAString::null(),
                product_uri: UAString::null(),
                application_name: LocalizedText::new("", "Rust OPCUA Client"),
                application_type: ApplicationType::Client,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            },
            server_uri: UAString::null(),
            endpoint_url: UAString::null(),
            session_name: UAString::from_str("Rust OPCUA Client"),
            client_nonce: ByteString::null(),
            client_certificate: ByteString::null(),
            requested_session_timeout: 0f64,
            max_response_message_size: 0,
        };
        let response = self.send_request(SupportedMessage::CreateSessionRequest(request))?;
        if let SupportedMessage::CreateSessionResponse(response) = response {
            let session_state = self.session_state.clone();
            let mut session_state = session_state.lock().unwrap();
            session_state.authentication_token = response.authentication_token;
            Ok(())
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends an ActivateSession request to the server
    pub fn activate_session(&mut self) -> Result<(), StatusCode> {
        let request = ActivateSessionRequest {
            request_header: self.make_request_header(),
            client_signature: SignatureData {
                algorithm: UAString::null(),
                signature: ByteString::null(),
            },
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary.as_node_id(), AnonymousIdentityToken::new()),
            user_token_signature: SignatureData {
                algorithm: UAString::null(),
                signature: ByteString::null(),
            },
        };
        debug!("ActivateSessionRequest = {:#?}", request);
        let response = self.send_request(SupportedMessage::ActivateSessionRequest(request))?;
        if let SupportedMessage::ActivateSessionResponse(response) = response {
            debug!("ActivateSessionResponse = {:#?}", response);
            Ok(())
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends a GetEndpoints request to the server
    pub fn get_endpoints(&mut self) -> Result<Option<Vec<EndpointDescription>>, StatusCode> {
        debug!("Fetching end points...");
        let endpoint_url = {
            let session_state = self.session_state.clone();
            let session_state = session_state.lock().unwrap();
            UAString::from_str(&session_state.endpoint_url)
        };

        let request = GetEndpointsRequest {
            request_header: self.make_request_header(),
            endpoint_url: endpoint_url,
            locale_ids: None,
            profile_uris: None,
        };

        let response = self.send_request(SupportedMessage::GetEndpointsRequest(request))?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            Ok(response.endpoints)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends a Browse request to the server
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
        let response = self.send_request(SupportedMessage::BrowseRequest(request))?;
        if let SupportedMessage::BrowseResponse(response) = response {
            Ok(response.results)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends a Read request to the server
    pub fn read_nodes(&mut self, nodes_to_read: &[ReadValueId]) -> Result<Option<Vec<DataValue>>, StatusCode> {
        debug!("read_nodes requested to read nodes {:?}", nodes_to_read);
        let request = ReadRequest {
            request_header: self.make_request_header(),
            max_age: 1f64,
            timestamps_to_return: TimestampsToReturn::Server,
            nodes_to_read: Some(nodes_to_read.to_vec()),
        };
        debug!("ReadRequest = {:#?}", request);
        let response = self.send_request(SupportedMessage::ReadRequest(request))?;
        if let SupportedMessage::ReadResponse(response) = response {
            debug!("ReadResponse = {:#?}", response);
            Ok(response.results)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Sends a Write request to the server
    pub fn write_value(&mut self, nodes_to_write: &[WriteValue]) -> Result<Option<Vec<StatusCode>>, StatusCode> {
        let request = WriteRequest {
            request_header: self.make_request_header(),
            nodes_to_write: Some(nodes_to_write.to_vec()),
        };
        let response = self.send_request(SupportedMessage::WriteRequest(request))?;
        if let SupportedMessage::WriteResponse(response) = response {
            Ok(response.results)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Checks if secure channel token needs to be renewed and renews it
    fn ensure_secure_channel_token(&mut self) -> Result<(), StatusCode> {
        // TODO check if secure channel 75% close to expiration in which case send a renew
        Ok(())
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

    pub fn send_request(&mut self, request: SupportedMessage) -> Result<SupportedMessage, StatusCode> {
        // Make sure secure channel token hasn't expired
        let _ = self.ensure_secure_channel_token();
        // Send the request
        self.transport.send_request(request)
    }
}