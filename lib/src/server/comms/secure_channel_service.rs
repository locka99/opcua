// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::result::Result;

use crate::core::{comms::prelude::*, supported_message::SupportedMessage};

use crate::crypto::SecurityPolicy;
use crate::types::{status_code::StatusCode, *};

struct SecureChannelState {
    // Issued flag
    issued: bool,
    // Renew count, debugging
    renew_count: usize,
    // Last secure channel id
    last_secure_channel_id: u32,
    /// Last token id number
    last_token_id: u32,
}

impl SecureChannelState {
    pub fn new() -> SecureChannelState {
        SecureChannelState {
            last_secure_channel_id: 0,
            issued: false,
            renew_count: 0,
            last_token_id: 0,
        }
    }

    pub fn create_secure_channel_id(&mut self) -> u32 {
        self.last_secure_channel_id += 1;
        self.last_secure_channel_id
    }

    pub fn create_token_id(&mut self) -> u32 {
        self.last_token_id += 1;
        self.last_token_id
    }
}

pub struct SecureChannelService {
    // Secure channel info for the session
    secure_channel_state: SecureChannelState,
}

impl SecureChannelService {
    pub fn new() -> SecureChannelService {
        SecureChannelService {
            secure_channel_state: SecureChannelState::new(),
        }
    }

    pub fn open_secure_channel(
        &mut self,
        secure_channel: &mut SecureChannel,
        security_header: &SecurityHeader,
        client_protocol_version: u32,
        message: &SupportedMessage,
    ) -> Result<SupportedMessage, StatusCode> {
        let request = match message {
            SupportedMessage::OpenSecureChannelRequest(request) => {
                trace!("Got secure channel request {:?}", request);
                request
            }
            _ => {
                error!(
                    "message is not an open secure channel request, got {:?}",
                    message
                );
                return Err(StatusCode::BadUnexpectedError);
            }
        };

        let security_header = match security_header {
            SecurityHeader::Asymmetric(security_header) => security_header,
            _ => {
                error!("Secure channel request message does not have asymmetric security header");
                return Err(StatusCode::BadUnexpectedError);
            }
        };

        // Must compare protocol version to the one from HELLO
        if request.client_protocol_version != client_protocol_version {
            error!(
                "Client sent a different protocol version than it did in the HELLO - {} vs {}",
                request.client_protocol_version, client_protocol_version
            );
            return Ok(ServiceFault::new(
                &request.request_header,
                StatusCode::BadProtocolVersionUnsupported,
            )
            .into());
        }

        // Test the request type
        let secure_channel_id = match request.request_type {
            SecurityTokenRequestType::Issue => {
                trace!("Request type == Issue");
                // check to see if renew has been called before or not
                if self.secure_channel_state.renew_count > 0 {
                    error!("Asked to issue token on session that has called renew before");
                }
                self.secure_channel_state.create_secure_channel_id()
            }
            SecurityTokenRequestType::Renew => {
                trace!("Request type == Renew");

                // Check for a duplicate nonce. It is invalid for the renew to use the same nonce
                // as was used for last issue/renew. It doesn't matter when policy is none.
                if secure_channel.security_policy() != SecurityPolicy::None
                    && request.client_nonce.as_ref() == secure_channel.remote_nonce()
                {
                    error!("Client reused a nonce for a renew");
                    return Ok(ServiceFault::new(
                        &request.request_header,
                        StatusCode::BadNonceInvalid,
                    )
                    .into());
                }

                // check to see if the secure channel has been issued before or not
                if !self.secure_channel_state.issued {
                    error!("Asked to renew token on session that has never issued token");
                    return Err(StatusCode::BadUnexpectedError);
                }
                self.secure_channel_state.renew_count += 1;
                secure_channel.secure_channel_id()
            }
        };

        // Check the requested security mode
        debug!("Message security mode == {:?}", request.security_mode);
        match request.security_mode {
            MessageSecurityMode::None
            | MessageSecurityMode::Sign
            | MessageSecurityMode::SignAndEncrypt => {
                // TODO validate NONCE
            }
            _ => {
                error!("Security mode is invalid");
                return Ok(ServiceFault::new(
                    &request.request_header,
                    StatusCode::BadSecurityModeRejected,
                )
                .into());
            }
        }

        // Process the request
        self.secure_channel_state.issued = true;

        // Create a new secure channel info
        let security_mode = request.security_mode;
        secure_channel.set_security_mode(security_mode);
        secure_channel.set_token_id(self.secure_channel_state.create_token_id());
        secure_channel.set_secure_channel_id(secure_channel_id);
        secure_channel.set_remote_cert_from_byte_string(&security_header.sender_certificate)?;

        match secure_channel.set_remote_nonce_from_byte_string(&request.client_nonce) {
            Ok(_) => secure_channel.create_random_nonce(),
            Err(err) => {
                error!("Was unable to set their nonce, check logic");
                return Ok(ServiceFault::new(&request.request_header, err).into());
            }
        }

        let security_policy = secure_channel.security_policy();
        if security_policy != SecurityPolicy::None
            && (security_mode == MessageSecurityMode::Sign
                || security_mode == MessageSecurityMode::SignAndEncrypt)
        {
            secure_channel.derive_keys();
        }

        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: secure_channel.secure_channel_id(),
                token_id: secure_channel.token_id(),
                created_at: DateTime::now(),
                revised_lifetime: request.requested_lifetime,
            },
            server_nonce: secure_channel.local_nonce_as_byte_string(),
        };
        Ok(response.into())
    }

    pub fn close_secure_channel(
        &mut self,
        _: &SupportedMessage,
    ) -> Result<SupportedMessage, StatusCode> {
        info!("CloseSecureChannelRequest received, session closing");
        Err(StatusCode::BadConnectionClosed)
    }
}
