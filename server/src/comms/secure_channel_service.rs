use std;

use opcua_types::*;
use opcua_core::comms::*;

pub struct SecureChannelService {
    // Secure channel info for the session
    pub secure_channel: SecureChannel,
    // Issued flag
    issued: bool,
    // Renew count, debugging
    renew_count: usize,
    // Last secure channel id
    last_secure_channel_id: UInt32,
    /// Last token id number
    last_token_id: UInt32,
}

impl SecureChannelService {
    pub fn new() -> SecureChannelService {
        SecureChannelService {
            last_secure_channel_id: 0,
            secure_channel: SecureChannel::new(),
            issued: false,
            renew_count: 0,
            last_token_id: 0,
        }
    }

    pub fn open_secure_channel(&mut self, client_protocol_version: UInt32, message: &SupportedMessage) -> std::result::Result<SupportedMessage, StatusCode> {
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
            error!("Client sent a different protocol version than it did in the HELLO - {} vs {}", request.client_protocol_version, client_protocol_version);
            return Ok(ServiceFault::new_supported_message(&request.request_header, BAD_PROTOCOL_VERSION_UNSUPPORTED));
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
            }
            SecurityTokenRequestType::Renew => {
                debug!("Request type == Renew");

                // Check for a duplicate nonce. It is invalid for the renew to use the same nonce
                // as was used for last issue/renew
                if request.client_nonce.as_ref() == &self.secure_channel.their_nonce[..] {
                    return Ok(ServiceFault::new_supported_message(&request.request_header, BAD_NONCE_INVALID));
                }

                if !self.issued {
                    // TODO check to see if the secure channel has been issued before or not
                    error!("Asked to renew token on session that has never issued token");
                    return Err(BAD_UNEXPECTED_ERROR);
                }
                self.renew_count += 1;
            }
        }

        // Check the requested security mode
        debug!("Message security mode == {:?}", request.security_mode);
        match request.security_mode {
            MessageSecurityMode::None | MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt => {
                // TODO validate NONCE
            }
            _ => {
                return Ok(ServiceFault::new_supported_message(&request.request_header, BAD_SECURITY_MODE_REJECTED));
            }
        }

        // Process the request
        self.issued = true;
        self.last_token_id += 1;
        self.last_secure_channel_id += 1;

        // Create a new secure channel info
        self.secure_channel = {
            let mut secure_channel = SecureChannel::new();
            secure_channel.token_id = self.last_token_id;
            secure_channel.security_mode = request.security_mode;
            secure_channel.secure_channel_id = self.last_secure_channel_id;
            let nonce_result = secure_channel.set_their_nonce(&request.client_nonce);
            if nonce_result.is_ok() {
                secure_channel.create_random_nonce();
            } else {
                return Ok(ServiceFault::new_supported_message(&request.request_header, nonce_result.unwrap_err()));
            }
            if secure_channel.signing_enabled() || secure_channel.encryption_enabled() {
                secure_channel.derive_keys();
            }
            secure_channel
        };

        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: self.secure_channel.secure_channel_id,
                token_id: self.secure_channel.token_id,
                created_at: DateTime::now(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: ByteString::from_bytes(&self.secure_channel.nonce),
        };

        debug!("Sending OpenSecureChannelResponse {:?}", response);
        Ok(SupportedMessage::OpenSecureChannelResponse(response))
    }

    pub fn close_secure_channel(&mut self, _: &SupportedMessage) -> std::result::Result<SupportedMessage, StatusCode> {
        info!("CloseSecureChannelRequest received, session closing");
        Err(BAD_CONNECTION_CLOSED)
    }
}