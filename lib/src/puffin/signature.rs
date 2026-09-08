use fn_impl::*;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::define_signature;
use crate::prelude::MessageType;
use crate::puffin::messages::{Message, UaMessage};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{
    AcknowledgeMessage, ErrorMessage, HelloMessage, MessageHeader, ReverseHelloMessage, UAString};

/// These modules contain all the concrete implementations of function symbols.
#[path = "."]
pub mod fn_impl {
    pub mod fn_constants;
    pub use fn_constants::*;

    pub mod fn_uasc;
    pub use fn_uasc::*;

    pub mod fn_services;
    pub use fn_services::*;
}


/// UA TCP sub-protocol:

/// Reverse Hello
pub fn fn_server_hello (
    connexion: &u8,
    server_uri:  &UAString,
    endpoint_url: &UAString,
) -> Result<Message, FnError> {
    let mut msg = ReverseHelloMessage {
        message_header: MessageHeader::new(MessageType::Reverse),
        server_uri: server_uri.clone(),
        endpoint_url: endpoint_url.clone()
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(Message{
        connexion_id: *connexion,
        message: UaMessage::Reverse(msg)
    })
}

/// Hello
pub fn fn_client_hello (
    connexion: &u8,
    endpoint_url: &UAString,
    send_buffer_size: &u32,
    receive_buffer_size: &u32
) -> Result<Message, FnError> {
    let mut msg = HelloMessage {
        message_header: MessageHeader::new(MessageType::Hello),
        protocol_version: 0,
        send_buffer_size: *send_buffer_size,
        receive_buffer_size: *receive_buffer_size,
        max_message_size: 0,  // 0: Client has no limit
        max_chunk_count: 0,   // 0: Client has no limit
        endpoint_url: endpoint_url.clone()
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(Message{
        connexion_id: *connexion,
        message: UaMessage::Hello(msg)
    })
}

/// Acknowledge
pub fn fn_acknowledge (
    connexion: &u8,
    receive_buffer_size: &u32,
    send_buffer_size: &u32,
) -> Result<Message, FnError> {
    let mut msg = AcknowledgeMessage {
        message_header: MessageHeader::new(MessageType::Acknowledge),
        protocol_version: 0,
        receive_buffer_size: *receive_buffer_size,
        send_buffer_size: *send_buffer_size,
        max_message_size: 0,  // 0: Server has no limit
        max_chunk_count: 0,   // 0: Server has no limit
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(Message{
        connexion_id: *connexion,
        message: UaMessage::Acknowledge(msg)
    })
}

/// Error
pub fn fn_error (
    connexion: &u8,
    error_code: &u32,
    reason: &UAString
) -> Result<Message, FnError> {
    let mut msg = ErrorMessage {
        message_header: MessageHeader::new(MessageType::Error),
        error: *error_code,
        reason: reason.clone(),
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(Message{
        connexion_id: *connexion,
        message: UaMessage::Error(msg)
    })
}


define_signature! {
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    fn_true
    fn_false

    fn_tcp_1
    fn_tcp_2

    fn_seq_0
    fn_seq_1
    fn_seq_2
    fn_seq_3
    fn_seq_4
    fn_seq_5
    fn_seq_6
    fn_seq_7
    fn_seq_8
    fn_seq_9
    fn_seq_10
    fn_succ

    fn_open
    fn_close
    fn_intermediate
    fn_final
    fn_abort

    fn_null_cert
    fn_alice_cert
    fn_bob_cert            // server's public cert: the client legitimately NEEDS it to open a channel
                           // (encrypt-to / thumbprint), and may fuzz sending a wrong one -> keep gen-able.
    fn_mallory_cert
    fn_oscar_cert

    fn_alice_sk
    fn_bob_sk [no_gen]     // server's PRIVATE key: the attacker (always the client) must NEVER hold or
                           // forge it. Never used in any trace; no_gen bars the fuzzer from emitting it.
    fn_mallory_sk
    fn_oscar_sk

    fn_security_policy_none
    fn_aes128sha256_rsa_oaep
    fn_basic256sha256
    fn_aes256sha256_rsa_pss
    fn_basic128_rsa_15
    fn_basic256

    fn_issue
    fn_renew
    fn_mode_none
    fn_mode_sign
    fn_sa_token_zero

    fn_no_nonce
    fn_channel_nonce_1
    fn_channel_nonce_2
    fn_session_nonce_1

    // UA TCP messages:
    fn_server_hello
    fn_client_hello
    fn_acknowledge
    fn_error

    fn_default_size
    fn_size_8192
    fn_bob_endpoint
    fn_oscar_uri
    fn_oscar_endpoint


    // UA SC messages:
    fn_header
    fn_sequence_header
    fn_service
    fn_service_size
    fn_body
    fn_open_header
    fn_no_bytes
    fn_data_to_sign
    fn_data_to_encrypt
    fn_sign [opaque]
    fn_asym_header
    fn_asym_encrypt [opaque]
    fn_asym_decrypt [opaque]
    fn_decrypted_body
    fn_open_message
    fn_channel_token
    fn_get_channel_token [get]
    fn_get_server_nonce [get]
    fn_client_mac_key [opaque]
    fn_msg_header
    fn_data_to_mac
    fn_mac [opaque]
    fn_message

    fn_request_header
    fn_response_header
    fn_client_open
    fn_server_open
    fn_client_close
    fn_server_close

    //services
    fn_create_request
    fn_activate_request
    fn_signature_data
    fn_anonymous
    fn_legacy_user_pwd
    //fn_user_pwd
    fn_username
    fn_password
    fn_user_cert
    fn_close_request
    fn_read_current_time
    fn_endpoints
}
