use std;

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::{ResponseHeader, SecurityTokenRequestType};

pub struct SecureChannel {
    // Secure channel info for the session
    pub secure_channel_token: SecureChannelToken,
    // Issued flag
    issued: bool,
    // Renew count, debugging
    renew_count: usize,
    // Last secure channel id
    last_secure_channel_id: UInt32,
    /// Last token id number
    last_token_id: UInt32,
}

impl SecureChannel {
    pub fn new() -> SecureChannel {
        SecureChannel {
            last_secure_channel_id: 0,
            secure_channel_token: SecureChannelToken::new(),
            issued: false,
            renew_count: 0,
            last_token_id: 0,
        }
    }

    pub fn open_secure_channel(&mut self, client_protocol_version: UInt32, message: &SupportedMessage) -> std::result::Result<OpenSecureChannelResponse, StatusCode> {
        let request: &OpenSecureChannelRequest = match *message {
            SupportedMessage::OpenSecureChannelRequest(ref request) => {
                info!("Got secure channel request");
                request
            }
            _ => {
                error!("message is not an open secure channel request, got {:?}", message);
                return Err(BAD_UNEXPECTED_ERROR);
            }
        };

        // Must compare protocol version to the one from HELLO
        if request.client_protocol_version != client_protocol_version {
            error!("Client sent a different protocol version than it did in the HELLO - {} vs {}",
                   request.client_protocol_version,
                   client_protocol_version);
            return Err(BAD_PROTOCOL_VERSION_UNSUPPORTED);
        }

        // Test the request type
        match request.request_type {
            SecurityTokenRequestType::Issue => {
                debug!("Request type == Issue");
                if self.renew_count > 0 {
                    // TODO check to see if renew has been called before or not
                    // error
                    error!("Asked to issue token on session that has called renew before");
                }
            },
            SecurityTokenRequestType::Renew => {
                debug!("Request type == Renew");

                // Check for a duplicate nonce. It is invalid for the renew to use the same nonce
                // as was used for last issue/renew
                if request.client_nonce.as_ref() == &self.secure_channel_token.their_nonce {
                    return Err(BAD_NONCE_INVALID);
                }

                if !self.issued {
                    // TODO check to see if the secure channel has been issued before or not
                    error!("Asked to renew token on session that has never issued token");
                    return Err(BAD_UNEXPECTED_ERROR)
                }
                self.renew_count += 1;
            }
        }

        // Check the requested security mode
        match request.security_mode {
            MessageSecurityMode::None | MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt => {
                debug!("Message security mode == {:?}", request.security_mode);
            },
            _ => {
                return Err(BAD_SECURITY_MODE_REJECTED);
            }
        }

        // Process the request
        self.issued = true;
        self.last_token_id += 1;
        self.last_secure_channel_id += 1;

        // Create a new secure channel info
        self.secure_channel_token  = {
            let mut secure_channel_token = SecureChannelToken::new();
            secure_channel_token.token_id = self.last_token_id;
            secure_channel_token.security_mode = request.security_mode;
            secure_channel_token.secure_channel_id = self.last_secure_channel_id;
            secure_channel_token.security_mode = request.security_mode;
            if secure_channel_token.set_their_nonce(&request.client_nonce).is_ok() {
                secure_channel_token.create_random_nonce();
            } else {
                debug!("Didn't receive a valid client nonce for this secure channel request so no crypto support");
                // TODO if crypto is enabled, then this is an error
            }
            secure_channel_token
        };

        let now = DateTime::now();
        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_service_result(&now,                                                                &request.request_header,
                                                                GOOD),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: self.secure_channel_token.secure_channel_id,
                token_id: self.secure_channel_token.token_id,
                created_at: now.clone(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: self.secure_channel_token.nonce_as_byte_string(),
        };

        debug!("Sending OpenSecureChannelResponse {:?}", response);
        Ok(response)
    }

    pub fn close_secure_channel(&mut self, _: &SupportedMessage) -> std::result::Result<CloseSecureChannelResponse, StatusCode> {
        info!("CloseSecureChannelRequest received, session closing");
        Err(BAD_CONNECTION_CLOSED)
    }
}