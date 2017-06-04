use std;

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::ResponseHeader;

pub struct SecureChannel {
    // Secure channel info for the session
    pub secure_channel_info: SecureChannelInfo,
    // Last secure channel id
    last_secure_channel_id: UInt32,
    /// Last token id number
    last_token_id: UInt32,
}

impl SecureChannel {
    pub fn new() -> SecureChannel {
        SecureChannel {
            last_secure_channel_id: 0,
            secure_channel_info: SecureChannelInfo::new(),
            last_token_id: 0,
        }
    }

    pub fn process_open_secure_channel(&mut self, client_protocol_version: UInt32, message: &SupportedMessage) -> std::result::Result<OpenSecureChannelResponse, StatusCode> {
        let request = match *message {
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

        // Create secure channel info
        self.secure_channel_info = SecureChannelInfo::new();

        // Process the request
        self.last_token_id += 1;
        self.secure_channel_info.token_id = self.last_token_id;
        self.last_secure_channel_id += 1;
        self.secure_channel_info.secure_channel_id = self.last_secure_channel_id;
        // self.secure_channel_info.security_policy = request.

        if self.secure_channel_info
               .set_their_nonce(&request.client_nonce)
               .is_ok() {
            self.secure_channel_info.create_random_nonce();
        } else {
            debug!("Didn't receive a valid client nonce for this secure channel request so no crypto support");
            // TODO if crypto is enabled, then this is an error
        }

        let now = DateTime::now();
        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_service_result(&now,
                                                                &request.request_header,
                                                                GOOD),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: self.secure_channel_info.secure_channel_id,
                token_id: self.secure_channel_info.token_id,
                created_at: now.clone(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: self.secure_channel_info.nonce_as_byte_string(),
        };

        debug!("Sending OpenSecureChannelResponse {:?}", response);
        Ok(response)
    }
}