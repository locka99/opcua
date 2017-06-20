use std::result::Result;
use std::sync::{Arc, Mutex};

use chrono;

use opcua_core::comms::*;
use opcua_core::types::*;
use opcua_core::services::*;

use comms::*;

pub struct SessionState {
    /// Endpoint, filled in during connect
    pub endpoint: Option<EndpointDescription>,
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
    /// The endpoint url
    pub endpoint_url: String,
    /// Security policy
    pub security_policy: SecurityPolicy,
    /// Runtime state of the session, reset if disconnected
    session_state: Arc<Mutex<SessionState>>,
    /// Transport layer
    transport: TcpTransport,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.is_connected() {
            self.disconnect();
        }
    }
}

impl Session {
    pub fn new(endpoint_url: &str, security_policy: SecurityPolicy) -> Session {
        let session_state = Arc::new(Mutex::new(SessionState {
            endpoint: None,
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
            endpoint_url: endpoint_url.to_string(),
            security_policy: security_policy,
        }
    }

    /// Connects to the server (if possible) using the configured session arguments
    pub fn connect(&mut self) -> Result<(), StatusCode> {
        let _ = self.transport.connect(&self.endpoint_url)?;
        let _ = self.transport.hello(&self.endpoint_url)?;
        let _ = self.open_secure_channel()?;
        Ok(())
    }

    /// Connects to the server and activates a session
    pub fn connect_and_activate_session(&mut self) -> Result<(), StatusCode> {
        let _ = self.connect()?;

        // Find a matching end point
        let endpoints = self.get_endpoints()?.unwrap();
        {
            let session_state = self.session_state.clone();
            let mut session_state = session_state.lock().unwrap();
            session_state.endpoint = Self::find_matching_endpoint(&endpoints, &self.endpoint_url, self.security_policy);
            if session_state.endpoint.is_none() {
                error!("Cannot find a matching endpoint for url and policy");
                return Err(BAD_TCP_ENDPOINT_URL_INVALID);
            }
        }

        let _ = self.create_session()?;
        let _ = self.activate_session()?;
        Ok(())
    }

    /// Disconnect from the server
    pub fn disconnect(&mut self) {
        let _ = self.close_secure_channel();
        self.transport.disconnect();
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Sends an OpenSecureChannel request to the server
    pub fn open_secure_channel(&mut self) -> Result<(), StatusCode> {
        self.issue_or_renew_secure_channel(SecurityTokenRequestType::Issue)
    }

    /// Sends a CloseSecureChannel request to the server
    pub fn close_secure_channel(&mut self) -> Result<(), StatusCode> {
        let request = CloseSecureChannelRequest {
            request_header: self.make_request_header(),
        };
        // We do not wait for a response because there may not be one. Just return
        let _ = self.async_send_request(SupportedMessage::CloseSecureChannelRequest(request));
        Ok(())
    }

    /// Sends a CreateSession request to the server
    pub fn create_session(&mut self) -> Result<(), StatusCode> {
        let endpoint_url = {
            let session_state = self.session_state.clone();
            let mut session_state = session_state.lock().unwrap();
            if session_state.endpoint.is_none() {
                error!("Cannot create a session because no endpoint has been discovered and set!");
                return Err(BAD_TCP_ENDPOINT_URL_INVALID);
            }
            session_state.endpoint.as_ref().unwrap().endpoint_url.clone()
        };

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
            endpoint_url: endpoint_url,
            session_name: UAString::from_str("Rust OPCUA Client"),
            client_nonce: ByteString::null(),
            client_certificate: ByteString::null(),
            requested_session_timeout: 0f64,
            max_response_message_size: 0,
        };
        let response = self.send_request(SupportedMessage::CreateSessionRequest(request))?;
        if let SupportedMessage::CreateSessionResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
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
        // Anonymous only for time being
        let user_identity_token = {
            let session_state = self.session_state.clone();
            let mut session_state = session_state.lock().unwrap();
            if session_state.endpoint.is_none() {
                error!("Cannot activate a session because no endpoint has been discovered and set!");
                return Err(BAD_TCP_ENDPOINT_URL_INVALID);
            }
            let endpoint = session_state.endpoint.as_ref().unwrap();
            let policy_id = endpoint.find_policy_id(UserTokenType::Anonymous);
            if policy_id.is_none() {
                error!("Cannot find anonymous policy id for this endpoint, cannot connect");
                return Err(BAD_SECURITY_POLICY_REJECTED);
            }
            AnonymousIdentityToken {
                policy_id: policy_id.unwrap(),
            }
        };

        debug!("Identity token for activate = {:#?}", user_identity_token);
        let user_identity_token = ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary.as_node_id(), user_identity_token);

        let request = ActivateSessionRequest {
            request_header: self.make_request_header(),
            client_signature: SignatureData {
                algorithm: UAString::null(),
                signature: ByteString::null(),
            },
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: user_identity_token,
            user_token_signature: SignatureData {
                algorithm: UAString::null(),
                signature: ByteString::null(),
            },
        };
        debug!("ActivateSessionRequest = {:#?}", request);
        let response = self.send_request(SupportedMessage::ActivateSessionRequest(request))?;
        if let SupportedMessage::ActivateSessionResponse(response) = response {
            debug!("ActivateSessionResponse = {:#?}", response);
            Self::process_service_result(&response.response_header)?;
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
            UAString::from_str(&self.endpoint_url)
        };

        let request = GetEndpointsRequest {
            request_header: self.make_request_header(),
            endpoint_url: endpoint_url,
            locale_ids: None,
            profile_uris: None,
        };

        let response = self.send_request(SupportedMessage::GetEndpointsRequest(request))?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
            Ok(response.endpoints)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Find matching endpoint
    pub fn find_matching_endpoint(endpoints: &[EndpointDescription], endpoint_url: &str, security_policy: SecurityPolicy) -> Option<EndpointDescription> {
        if security_policy == SecurityPolicy::Unknown {
            panic!("Can't match against unknown security policy");
        }
        for e in endpoints.iter() {
            if security_policy != SecurityPolicy::from_uri(e.security_policy_uri.as_ref()) {
                continue;
            }
            if url_matches_except_host(e.endpoint_url.as_ref(), endpoint_url).is_ok() {
                return Some(e.clone())
            }
        }
        None
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
            Self::process_service_result(&response.response_header)?;
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
            Self::process_service_result(&response.response_header)?;
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
            Self::process_service_result(&response.response_header)?;
            Ok(response.results)
        } else {
            Err(BAD_UNKNOWN_RESPONSE)
        }
    }

    /// Checks if secure channel token needs to be renewed and renews it
    fn ensure_secure_channel_token(&mut self) -> Result<(), StatusCode> {
        let renew_token = {
            let mut session_state = self.session_state.lock().unwrap();
            if let Some(ref channel_token) = session_state.channel_token {
                let now = chrono::UTC::now();

                // Check if secure channel 75% close to expiration in which case send a renew
                let renew_lifetime = (channel_token.revised_lifetime * 3) / 4;
                let created_at = channel_token.created_at.as_chrono();
                let renew_lifetime = chrono::Duration::milliseconds(renew_lifetime as i64);

                // Renew the token?
                now.signed_duration_since(created_at) > renew_lifetime
            } else {
                false
            }
        };
        if renew_token {
            self.issue_or_renew_secure_channel(SecurityTokenRequestType::Renew)
        } else {
            Ok(())
        }
    }

    /// Process the service result, i.e. where the request "succeed" but the response
    /// contains a failure status code.
    fn process_service_result(response_header: &ResponseHeader) -> Result<(), StatusCode> {
        if response_header.service_result.is_bad() {
            Err(response_header.service_result)
        } else {
            Ok(())
        }
    }

    /// Construct a request header for the session
    fn make_request_header(&mut self) -> RequestHeader {
        let (authentication_token, request_handle, timeout_hint) = {
            let mut session_state = self.session_state.lock().unwrap();
            session_state.last_request_handle += 1;
            (session_state.authentication_token.clone(), session_state.last_request_handle, session_state.request_timeout)
        };
        let request_header = RequestHeader {
            authentication_token: authentication_token,
            timestamp: DateTime::now(),
            request_handle: request_handle,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: timeout_hint,
            additional_header: ExtensionObject::null(),
        };
        request_header
    }

    fn issue_or_renew_secure_channel(&mut self, request_type: SecurityTokenRequestType) -> Result<(), StatusCode> {
        // TODO
        let requested_lifetime = 60000;

        let request = OpenSecureChannelRequest {
            request_header: self.make_request_header(),
            client_protocol_version: 0,
            request_type: request_type,
            security_mode: MessageSecurityMode::None,
            client_nonce: ByteString::from_bytes(&[0]),
            requested_lifetime: requested_lifetime,
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

    pub fn send_request(&mut self, request: SupportedMessage) -> Result<SupportedMessage, StatusCode> {
        // Make sure secure channel token hasn't expired
        let _ = self.ensure_secure_channel_token();
        // Send the request
        self.transport.send_request(request)
    }

    pub fn async_send_request(&mut self, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        // Make sure secure channel token hasn't expired
        let _ = self.ensure_secure_channel_token();
        // Send the request
        self.transport.async_send_request(request)
    }
}