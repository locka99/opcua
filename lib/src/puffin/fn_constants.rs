// All result types must implement Extractable<OpcuaProtocolTypes>, and hence CodecP.

use puffin::algebra::error::FnError;

use crate::puffin::messages::ChunkType;
use crate::puffin::signature::fn_impl::{CipherSuite, SecretKey, Certificate};
use crate::puffin::static_certs::{
    ALICE_PRIVATE_KEY, ALICE_CERTIFICATE, BOB_PRIVATE_KEY, BOB_CERTIFICATE,
    MALLORY_PRIVATE_KEY, MALLORY_CERTIFICATE, OSCAR_PRIVATE_KEY, OSCAR_CERTIFICATE};
use crate::puffin::messages::MAX_WIRE_SIZE;
use crate::types::{ByteString, Identifier, MessageSecurityMode, NodeId, SecurityTokenRequestType, UAString};

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_tcp_1() -> Result<u8, FnError> {
    Ok(1)
}

pub fn fn_tcp_2() -> Result<u8, FnError> {
    Ok(2)
}

pub fn fn_seq_0() -> Result<u32, FnError> {
    Ok(0)
}
pub fn fn_seq_1() -> Result<u32, FnError> {
    Ok(1)
}
pub fn fn_seq_2() -> Result<u32, FnError> {
    Ok(2)
}
pub fn fn_seq_3() -> Result<u32, FnError> {
    Ok(3)
}
pub fn fn_seq_4() -> Result<u32, FnError> {
    Ok(4)
}
pub fn fn_seq_5() -> Result<u32, FnError> {
    Ok(5)
}
pub fn fn_seq_6() -> Result<u32, FnError> {
    Ok(6)
}
pub fn fn_seq_7() -> Result<u32, FnError> {
    Ok(7)
}
pub fn fn_seq_8() -> Result<u32, FnError> {
    Ok(8)
}
pub fn fn_seq_9() -> Result<u32, FnError> {
    Ok(9)
}
pub fn fn_seq_10() -> Result<u32, FnError> {
    Ok(10)
}
pub fn fn_succ(val: &u32) -> Result<u32, FnError> {
    Ok(*val +1)
}

pub fn fn_default_size() -> Result<u32, FnError> {
    Ok(MAX_WIRE_SIZE as u32)
}
pub fn fn_size_8192() -> Result<u32, FnError> {
    Ok(8192) // Part 6 § 7.1.2.3 Table 66: Buffer size shall be at least 8192 bytes.
}

pub fn fn_bob_endpoint() -> Result<UAString, FnError> {
    Ok(UAString::from("opc.tcp://localhost:4840/opcuapuffin.bob"))
}
pub fn fn_oscar_uri() -> Result<UAString, FnError> {
    Ok(UAString::from("opc.tcp://127.0.0.1:4840"))
}
pub fn fn_oscar_endpoint() -> Result<UAString, FnError> {
    Ok(UAString::from("opc.tcp://localhost:4840/opcuapuffin.oscar"))
}

/// Various constants:
// /!\ The SA Token is a NodeId!
pub fn fn_sa_token_zero() -> Result<NodeId, FnError> {
    Ok(NodeId {
        namespace: 0,
        identifier: Identifier::from(0)
    })
}

// Open or reopen:
pub fn fn_issue() -> Result<SecurityTokenRequestType, FnError> {
    Ok(SecurityTokenRequestType::Issue)
}
pub fn fn_renew() -> Result<SecurityTokenRequestType, FnError> {
    Ok(SecurityTokenRequestType::Renew)
}
pub fn fn_mode_none() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::None)
}
pub fn fn_mode_sign() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::Sign)
}

// Certificates:
pub fn fn_alice_cert() -> Result<Certificate, FnError> {
    Ok(Certificate(ByteString{value: Some(ALICE_CERTIFICATE.1.to_vec())}))
}
pub fn fn_bob_cert() -> Result<Certificate, FnError>  {
    Ok(Certificate(ByteString{value: Some(BOB_CERTIFICATE.1.to_vec())}))
}
pub fn fn_mallory_cert() -> Result<Certificate, FnError> {
    Ok(Certificate(ByteString{value: Some(MALLORY_CERTIFICATE.1.to_vec())}))
}
pub fn fn_oscar_cert() -> Result<Certificate, FnError> {
    Ok(Certificate(ByteString{value: Some(OSCAR_CERTIFICATE.1.to_vec())}))
}
pub fn fn_null_cert() -> Result<Certificate, FnError> {
    Ok(Certificate(ByteString::null()))
}

// Private keys:
pub fn fn_alice_sk() -> Result<SecretKey, FnError> {
    Ok(SecretKey(ALICE_PRIVATE_KEY.1.to_vec()))
}
pub fn fn_bob_sk() -> Result<SecretKey, FnError> {
    Ok(SecretKey(BOB_PRIVATE_KEY.1.to_vec()))
}
pub fn fn_mallory_sk() -> Result<SecretKey, FnError> {
    Ok(SecretKey(MALLORY_PRIVATE_KEY.1.to_vec()))
}
pub fn fn_oscar_sk() -> Result<SecretKey, FnError> {
    Ok(SecretKey(OSCAR_PRIVATE_KEY.1.to_vec()))
}

// Security Policies:
pub fn fn_security_policy_none() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::None)
}
pub fn fn_aes128sha256_rsa_oaep() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::Aes128Sha256RsaOaep)
}
pub fn fn_basic256sha256() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::Basic256Sha256)
}
pub fn fn_aes256sha256_rsa_pss() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::Aes256Sha256RsaPss)
}
pub fn fn_basic128_rsa_15() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::Basic128Rsa15)
}
pub fn fn_basic256() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::Basic256)
}

// Message Header:
pub fn fn_open() -> Result<ChunkType, FnError> {
    Ok(ChunkType::Open)
}
pub fn fn_close() -> Result<ChunkType, FnError> {
    Ok(ChunkType::Close)
}
pub fn fn_intermediate() -> Result<ChunkType, FnError> {
    Ok(ChunkType::Intermediate)
}
pub fn fn_final() -> Result<ChunkType, FnError> {
    Ok(ChunkType::Final)
}
pub fn fn_abort() -> Result<ChunkType, FnError> {
    Ok(ChunkType::FinalError)
}

// Nonces:
pub fn fn_channel_nonce_1() -> Result<ByteString, FnError> {
    Ok(ByteString{value: Some(vec![
        96, 136, 65, 244, 244, 100, 47, 233,
        225, 193, 23, 66, 151, 245, 47, 115,
        34, 200, 125, 96, 220, 252, 162, 206,
        62, 160, 115, 203, 96, 15, 105, 6])})
}
pub fn fn_channel_nonce_2() -> Result<ByteString, FnError> {
    Ok(ByteString{value: Some(vec![
        244, 108, 167, 184, 13, 100, 45, 5,
        10, 250, 197, 126, 173, 140, 236, 226,
        172, 79, 112, 133, 181, 253, 123, 7,
        106, 246, 206, 113, 129, 158, 26, 10])})
}
pub fn fn_session_nonce_1() -> Result<ByteString, FnError> {
    Ok(ByteString{value: Some(vec![
        131, 96, 12, 13, 188, 118, 177, 20,
        172, 8, 201, 194, 228, 150, 70, 61,
        118, 220, 37, 153, 61, 85, 163, 69,
        221, 252, 209, 206, 208, 30, 244, 139])})
}
pub fn fn_no_nonce() -> Result<ByteString, FnError> {
    Ok(ByteString::null())
}

pub fn fn_no_bytes() -> Result<Vec<u8>, FnError> {
    Ok(vec![])
}

pub fn fn_username() -> Result<UAString, FnError> {
    Ok(UAString::from("peter"))
}
pub fn fn_password() -> Result<UAString, FnError> {
    Ok(UAString::from("peter123"))
}
