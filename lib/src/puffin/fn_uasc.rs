// symbolic functions for the UA Secure Channel sub-protocol

use openssl::pkey::{Private};

use puffin::algebra::error::FnError;
use puffin::codec::{CodecP, Reader};
use puffin::error::Error;

use crate::crypto::{KeySize, PKey, PrivateKey, RsaPadding, SecurityPolicy, X509};
use crate::prelude::{AsymmetricSecurityHeader, MessageChunkHeader, SequenceHeader, SymmetricSecurityHeader};
use crate::puffin::messages::{ChunkType, DecryptedBody, EncryptedBody, Message, MessageBody, ServiceMessage, UaMessage};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{ByteString, ChannelSecurityToken, DateTime, DiagnosticBits, DiagnosticInfo, ExtensionObject,
    MessageSecurityMode, NodeId, RequestHeader, ResponseHeader, SecurityTokenRequestType,
    StatusCode, UAString, UtcTime};
use crate::types::service_types::{OpenSecureChannelRequest, OpenSecureChannelResponse, CloseSecureChannelRequest,
    CloseSecureChannelResponse};

use extractable_macro::Extractable;

pub fn fn_header (
    message_type: &ChunkType,
    secure_channel_id: &u32
) -> Result<MessageChunkHeader, FnError> {
    Ok(MessageChunkHeader{
        message_type: message_type.to_message_chunk_type(),
        is_final: message_type.to_is_final(),
        message_size: 0,
        secure_channel_id: *secure_channel_id
    })
}

// Making crate::crypto::SecurityPolicy extractable and encodable through CodecP
// creates a lot of troubles for compiling the existing code of opcua-mapper.
// (conflicts between puffin::codec:CodecP and BinaryEncoder and huge borrow
// checker errors).
// Hence I prefer to duplicate this enum here:

/// A private (asymmetric) signing/decryption key. Its own DY type so the fuzzer treats keys as a
/// distinct kind -- NOT interchangeable with the many generic `Vec<u8>` byte-buffers in a trace
/// (fn_mac / fn_service / fn_sign / ... outputs). Without this, ReplaceReuse would overwrite a key
/// slot with an arbitrary buffer (type-valid, semantically garbage) and ReplaceMatch/selection
/// would drown the 2 key leaves among dozens of Vec<u8> buffer nodes. Keys only swap with keys now.
#[derive(Clone, Debug, Deserialize, Eq, Extractable, Hash, PartialEq, Serialize)]
#[extractable(OpcuaProtocolTypes)]
pub struct SecretKey(pub Vec<u8>);

impl Default for SecretKey {
    fn default() -> Self { SecretKey(Vec::new()) }
}

impl CodecP for SecretKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }
    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        self.0.read(rd)?;
        Ok(())
    }
}

/// An X509 certificate. Its own DY type (wrapping ByteString) so the fuzzer treats certs as a
/// distinct kind -- NOT interchangeable with nonces / query ByteStrings / other byte blobs. Without
/// this, ReplaceMatch/ReplaceReuse would swap a cert with a nonce or an arbitrary ByteString
/// (type-valid, semantically garbage). Certs only swap with certs now. Derefs to ByteString so the
/// existing crypto bodies (.as_ref(), .is_null_or_empty(), .byte_len()) keep working.
#[derive(Clone, Debug, Deserialize, Eq, Extractable, Hash, PartialEq, Serialize)]
#[extractable(OpcuaProtocolTypes)]
pub struct Certificate(pub ByteString);

impl Default for Certificate {
    fn default() -> Self { Certificate(ByteString::null()) }
}

impl std::ops::Deref for Certificate {
    type Target = ByteString;
    fn deref(&self) -> &ByteString { &self.0 }
}

impl CodecP for Certificate {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.0.as_ref());
    }
    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        let mut v: Vec<u8> = Vec::new();
        v.read(rd)?;
        self.0 = ByteString { value: Some(v) };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Extractable, Hash, PartialEq, Serialize)]
#[extractable(OpcuaProtocolTypes)]
pub enum CipherSuite {
    None = 0,
    Aes128Sha256RsaOaep = 1,
    Basic256Sha256 = 2,
    Aes256Sha256RsaPss = 3,
    Basic128Rsa15 = 4,
    Basic256 = 5
}

impl CipherSuite {
    pub fn security_policy(self) -> SecurityPolicy {
        match self {
            CipherSuite::None => SecurityPolicy::None,
            CipherSuite::Aes128Sha256RsaOaep => SecurityPolicy::Aes128Sha256RsaOaep,
            CipherSuite::Basic256Sha256 => SecurityPolicy::Basic256Sha256,
            CipherSuite::Aes256Sha256RsaPss => SecurityPolicy::Aes256Sha256RsaPss,
            CipherSuite::Basic128Rsa15 => SecurityPolicy::Basic128Rsa15,
            CipherSuite::Basic256 => SecurityPolicy::Basic256
        }
    }

    fn needs_asym_encryption(self) -> bool {
        match self {
            CipherSuite::None => false,
            CipherSuite::Aes128Sha256RsaOaep => true,
            CipherSuite::Basic256Sha256 => true,
            CipherSuite::Aes256Sha256RsaPss => true,
            CipherSuite::Basic128Rsa15 => true,
            CipherSuite::Basic256 => true
        }
    }
}

impl From<SecurityPolicy> for CipherSuite {
    fn from(v: SecurityPolicy) -> CipherSuite {
        match v {
            SecurityPolicy::Unknown => CipherSuite::None,
            SecurityPolicy::None => CipherSuite::None,
            SecurityPolicy::Aes128Sha256RsaOaep => CipherSuite::Aes128Sha256RsaOaep,
            SecurityPolicy::Basic256Sha256 => CipherSuite::Basic256Sha256,
            SecurityPolicy::Aes256Sha256RsaPss => CipherSuite::Aes256Sha256RsaPss,
            SecurityPolicy::Basic128Rsa15 => CipherSuite::Basic128Rsa15,
            SecurityPolicy::Basic256 => CipherSuite::Basic256
        }
    }
}

impl CodecP for CipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self as u8);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        let mut value = 0u8;
        if let Ok(()) = CodecP::read(&mut value, rd){
            if value > 5 {
                return Err(Error::Codec("Cannot read a CipherSuite".to_string()))
            }
            *self = match value {
                0 => CipherSuite::None,
                1 => CipherSuite::Aes128Sha256RsaOaep,
                2 => CipherSuite::Basic256Sha256,
                3 => CipherSuite::Aes256Sha256RsaPss,
                4 => CipherSuite::Basic128Rsa15,
                5 => CipherSuite::Basic256,
                _ => { return Err(Error::Codec("Cannot read a CipherSuite".to_string())); }
            };
            Ok(())
        } else {
            Err(Error::Codec("Cannot read a CipherSuite".to_string()))
        }
    }
}

pub fn fn_sequence_header(
    sequence_number: &u32,
    request_id: &u32,
) -> Result<SequenceHeader, FnError> {
    Ok(SequenceHeader {
        sequence_number: *sequence_number,
        request_id: *request_id
    })
}

pub fn fn_service(
    sequence: &SequenceHeader,
    request: &ServiceMessage
 ) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(sequence, &mut buffer);
    CodecP::encode(request, &mut buffer);
    Ok(buffer)
 }

 pub fn fn_service_size(
    request: &ServiceMessage
 ) -> Result<u32, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(request, &mut buffer);
    Ok(8 + buffer.len() as u32)
 }


pub fn fn_body(
    token_id: &SymmetricSecurityHeader,
    sequence: &SequenceHeader,
    service: &ServiceMessage,
    mac: &Vec<u8>
 ) -> Result<MessageBody, FnError> {
    Ok(MessageBody{
        security_header: token_id.clone(),
        sequence_header: sequence.clone(),
        request: service.clone(),
        mac: mac.clone()
    })
 }

// helper function copied from crate::comms::secure_channel
//cf. fn plain_text_block_size(&self, padding: RsaPadding) -> usize
fn calculate_plain_text_block_size (
    security_policy: SecurityPolicy,
    encryption_key_size: usize
) -> Result<usize, FnError> {
    let padding: RsaPadding = security_policy.asymmetric_encryption_padding();
    let padding_size: usize = match padding {
        RsaPadding::Pkcs1 => 11,
        RsaPadding::OaepSha1 => 42,
        RsaPadding::OaepSha256 => 66,
        _ => return Err(FnError::Crypto("Unsupported padding".to_string())),
    };
    Ok(encryption_key_size - padding_size)
}

// The following functions are a complete revrite of SecureChannel::asymmetric_sign_and_encrypt()
// in crate::core::comms::secure_channel::SecureChannel.

pub fn fn_open_header(
    chunk_header: &MessageChunkHeader,
    cipher_suite: &CipherSuite,
    sender_certificate: &Certificate,
    receiver_certificate: &Certificate,
    data: &Vec<u8>
) -> Result<MessageChunkHeader, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let signature_size: usize = {
        if !sender_certificate.is_null_or_empty() {
            let x509 = X509::from_der(sender_certificate.as_ref())
               .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            x509.public_key().unwrap().size() }
        else { 0 }
    };
    let (receiver_certificate_thumbprint, encryption_key_size) =
        if needs_asym_encryption {
            let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            (receiver_x509.thumbprint().as_byte_string(), receiver_x509.public_key().unwrap().size())
        } else {
            (ByteString::null(), 0)
        };
    let cipher_text_size=
        if needs_asym_encryption {
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let cipher_text_bloc_size = encryption_key_size;
            let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
            let plain_text_size = data.len() + min_footer_size + signature_size;
            let padding_size = if (plain_text_size % plain_text_block_size) != 0
                {plain_text_block_size - (plain_text_size % plain_text_block_size)}
                else {0};
            let block_count = if padding_size == 0 {
                plain_text_size / plain_text_block_size
            } else {
                (plain_text_size / plain_text_block_size) + 1
            };
            let cipher_text_size = block_count * cipher_text_bloc_size;
            cipher_text_size
        } else {
            let plain_text_size = data.len();
            plain_text_size
        };

    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: sender_certificate.0.clone(),
        receiver_certificate_thumbprint
    };
    let mut header = chunk_header.clone();
    header.message_size = (header.byte_len() + security_header.byte_len() + cipher_text_size) as u32;
    Ok(header)
}


pub fn fn_data_to_sign (
    header: &MessageChunkHeader,
    cipher_suite: &CipherSuite,
    sender_certificate: &Certificate,
    receiver_certificate: &Certificate,
    data: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let signature_size: usize = {
        if !sender_certificate.is_null_or_empty() {
            let x509 = X509::from_der(sender_certificate.as_ref())
               .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            x509.public_key().unwrap().size() }
        else { 0 }
    };
    let (receiver_certificate_thumbprint, encryption_key_size) =
        if security_policy != SecurityPolicy::None {
            let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            (receiver_x509.thumbprint().as_byte_string(), receiver_x509.public_key().unwrap().size())
        } else {
            (ByteString::null(), 0)
        };
    let (padding_size, min_footer_size) =
        if needs_asym_encryption {
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
            let plain_text_size = data.len() + min_footer_size + signature_size;
            let padding_size = if (plain_text_size % plain_text_block_size) != 0
                {plain_text_block_size - (plain_text_size % plain_text_block_size)}
                else {0};
            (padding_size, min_footer_size)
        } else { (0, 0) };
    // collect data to sign in a buffer:
    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: sender_certificate.0.clone(),
        receiver_certificate_thumbprint
    };
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(header, &mut buffer);
    CodecP::encode(&security_header, &mut buffer);
    buffer.extend_from_slice(data);
    // Add padding in the Message Footer
    if needs_asym_encryption {
        let padding_byte= (padding_size & 0xff) as u8;
        for _ in 0..padding_size+1 {
            buffer.push(padding_byte);
        }
        if min_footer_size == 2 {
            buffer.push((padding_size >> 8) as u8);
        }
    };
    Ok(buffer)
}


pub fn fn_sign(
    data: &Vec<u8>,
    cipher_suite: &CipherSuite,
    sender_certificate: &Certificate,
    private_key: &SecretKey
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    if security_policy == SecurityPolicy::None {
        return Err(FnError::Crypto("Cannot sign with SecurityPolicy::None".to_string()))
    }
    let signature_size: usize = {
        let x509 = X509::from_der(sender_certificate.as_ref())
           .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
        x509.public_key().unwrap().size()
    };
    let signing_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(&private_key.0)
        .map(|value|{PrivateKey {value}})
        .map_err( |_| {FnError::Crypto("fn_sign: error reading private key (PKCS #8 with DER)".to_string())})?;
    let mut signature = vec![0u8; signature_size];
    security_policy.asymmetric_sign(&signing_key, data, &mut signature)
        .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
    Ok(signature)
}


pub fn fn_data_to_encrypt (
    cipher_suite: &CipherSuite,
    receiver_certificate: &Certificate,
    request: &Vec<u8>,
    signature: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();

    let (padding_size, min_footer_size) =
        if needs_asym_encryption {
            let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            let encryption_key_size: usize = receiver_x509.public_key().unwrap().size();
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
            let plain_text_size = request.len() + min_footer_size + signature.len();
            let padding_size = if (plain_text_size % plain_text_block_size) != 0
                {plain_text_block_size - (plain_text_size % plain_text_block_size)}
                else {0};
            (padding_size, min_footer_size)
        } else { (0, 0) };

    let mut buffer= Vec::<u8>::new();
    buffer.extend_from_slice(&request);

    if needs_asym_encryption {
        // Add padding in the Message Footer:
        let padding_byte= (padding_size & 0xff) as u8;
        for _ in 0..padding_size+1 {
            buffer.push(padding_byte);
        }
        if min_footer_size == 2 {
            buffer.push((padding_size >> 8) as u8);
        }
    };
    buffer.extend_from_slice(&signature);
    Ok(buffer)
}


pub fn fn_asym_header (
    cipher_suite: &CipherSuite,
    sender_certificate: &Certificate,
    receiver_certificate: &Certificate,
) -> Result<AsymmetricSecurityHeader, FnError> {

    let security_policy = cipher_suite.security_policy();
    let receiver_certificate_thumbprint =
        if sender_certificate.0 == ByteString::null() {
            ByteString::null()
        } else {
            match X509::from_der(receiver_certificate.as_ref()) {
                Ok(receiver_x509) => receiver_x509.thumbprint().as_byte_string(),
                Err(_) => ByteString::null()
        }};
    Ok(AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: sender_certificate.0.clone(),
        receiver_certificate_thumbprint
    })
}


pub fn fn_asym_encrypt (
    cipher_suite: &CipherSuite,
    receiver_certificate: &Certificate,
    data: &Vec<u8>,
) -> Result<EncryptedBody, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let mut buffer= Vec::<u8>::new();
    if data.len() == 0 {
        return Err(FnError::Crypto("No data to encrypt".to_string()))
    };

    if needs_asym_encryption {
        let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
        .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
        let encryption_key= receiver_x509.public_key().unwrap();
        let encryption_key_size: usize = encryption_key.size();
        let cipher_text_size= {
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let cipher_text_bloc_size = encryption_key_size;
            let plain_text_size = data.len();
            let block_count =
                if (plain_text_size % plain_text_block_size) == 0 {
                    plain_text_size / plain_text_block_size
                } else {
                    plain_text_size / plain_text_block_size + 1
                };
            block_count * cipher_text_bloc_size
        };
        let mut cipher_text= vec![0u8; cipher_text_size];
        // Encrypt data into buffer:
        let encrypted_size = security_policy.asymmetric_encrypt(
            &encryption_key, &data, &mut cipher_text)
            .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
        // Validate encrypted size is right:
        if encrypted_size != cipher_text_size {
            return Err(FnError::Crypto(
                format!("Encrypted block size {} is not the same as calculated cipher text size {}",
                encrypted_size, cipher_text_size)
            ))
        }
        buffer.extend_from_slice(&cipher_text);
    }
    else { // No asymmetric encryption.
        buffer.extend_from_slice(&data);
     };
    Ok(EncryptedBody{cipher_text: buffer})
}


pub fn fn_asym_decrypt(
    cipher_suite: &CipherSuite,
    body: &EncryptedBody,
    private_key: &SecretKey
) -> Result<Vec<u8>, FnError> {

    // Read asymmetric security header:
    let mut rd = Reader::init(&body.cipher_text);
    let security_policy = cipher_suite.security_policy();

    match security_policy {
        SecurityPolicy::None => Ok(rd.rest().to_vec()),
        SecurityPolicy::Unknown => Err(FnError::Crypto("Cannot decrypt with no or an unknown security policy".to_string())),
        _ => {
            // decrypt payload:
            let encrypted_size=  body.cipher_text.len();
            let decryption_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(&private_key.0)
                .map(|value|{PrivateKey {value}})
                .map_err( |_| {FnError::Crypto("fn_asym_decrypt: error reading private key (PKCS #8 with DER)".to_string())})?;
            let cipher_text_block_size = decryption_key.cipher_text_block_size();
            if encrypted_size % cipher_text_block_size != 0 {
                return Err(FnError::Crypto("Cannot decrypt due to an inappropriate cipher text size".to_string()))
            };
            let mut decrypted_tmp = vec![0u8; encrypted_size];
            let decrypted_size = security_policy.asymmetric_decrypt(&decryption_key,
                &&body.cipher_text,
                &mut decrypted_tmp)
                .map_err( |_| {FnError::Crypto("Error during asymmetric decryption".to_string())})?;

           Ok(decrypted_tmp[0..decrypted_size].to_vec())
        }
    }
}


pub fn fn_decrypted_body(
    body: &Vec<u8>,
    private_key: &SecretKey
) -> Result<DecryptedBody, FnError> {

    let mut rd = Reader::init(body);
    let mut decrypted_body = DecryptedBody::default();
    decrypted_body.sequence_header.read(&mut rd)
        .map_err(|e| FnError::Codec(format!("fn_decrypted_body cannot read sequence header: {e}")))?;
    decrypted_body.request.read(& mut rd)
        .map_err(|e| FnError::Codec(format!("fn_decrypted_body cannot read message: {e}")))?;

    // suppressed padding:
    if private_key.0.len() > 0 {
        // get decryption key:
        let decryption_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(&private_key.0)
        .map(|value|{PrivateKey {value}})
        .map_err( |_| -> FnError {FnError::Crypto("fn_decrypted_body: error reading private key (PKCS #8 with DER)".to_string())})?;
        let mut padding_byte: u8 = 0;
        padding_byte.read(&mut rd)
            .map_err(|e| FnError::Crypto(format!("fn_decrypted_body cannot read padding: {e}")))?;
        let mut byte = padding_byte;

        if decryption_key.size() <= 2048 {
            for _ in 0..padding_byte {
                byte.read(&mut rd).map_err(|e| FnError::Codec(format!("fn_decrypted_body, error in padding: {e}")))?;
                if byte != padding_byte {
                    return Err(FnError::Crypto(format!("fn_decrypted_body, error in padding, found {}, expected {}",
                            byte, padding_byte)))};
            }
        } else {
            let mut padding_size: u32 = 0;
            byte.read(&mut rd).map_err(|e| FnError::Codec(format!("fn_decrypted_body, error in padding: {e}")))?;
            while byte == padding_byte {
                padding_size += 1;
                byte.read(&mut rd).map_err(|e| FnError::Codec(format!("fn_decrypted_body, error in padding: {e}")))?;
            }
            if padding_size != ((byte as u32) << 8) + (padding_byte as u32) {
                return Err(FnError::Crypto("fn_decrypted_body, error in padding".to_string()))
            }
        };
        decrypted_body.signature.read(&mut rd)
            .map_err(|e| FnError::Codec(format!("fn_decrypted_body cannot read signature: {e}")))?;
    };
    Ok(decrypted_body)
}

pub fn fn_get_channel_token(
    open_response: &DecryptedBody
) -> Result<SymmetricSecurityHeader, FnError> {
    if let ServiceMessage::OpenSecureChannelResponse(response) = &open_response.request {
        Ok(SymmetricSecurityHeader {token_id: response.security_token.token_id})
    } else {
        Err(FnError::Unknown("Cannot get channel token id".to_string()))
    }
}

pub fn fn_channel_token(
    token_id: &u32
) -> Result<SymmetricSecurityHeader, FnError> {
    Ok(SymmetricSecurityHeader {token_id: *token_id})
}

pub fn fn_get_server_nonce(
    open_response: &DecryptedBody
) -> Result<ByteString, FnError> {
    if let ServiceMessage::OpenSecureChannelResponse(response) = &open_response.request {
        Ok(response.server_nonce.clone())
    } else {
        Err(FnError::Unknown("Cannot get channel nonce".to_string()))
    }
}

pub fn fn_client_mac_key(
    cipher_suite: &CipherSuite,
    client_nonce: &ByteString,
    server_nonce: &ByteString
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    if security_policy == SecurityPolicy::None {
        return Err(FnError::Crypto("Cannot compute MAC for SecurityPolicy::None".to_string()))
    };
    let nonce_length = security_policy.secure_channel_nonce_length();
    if (client_nonce.as_ref().len() != nonce_length) || (server_nonce.as_ref().len() != nonce_length) {
        return Err(FnError::Crypto("Cannot compute symmetric keys: nonce size is incorrect".to_string()))
    }
    // cf. SecureChannel: Our end's set of keys: Symmetric Signing Key, Decrypt [Encrypt!] Key, IV
    let client_keys = security_policy.make_secure_channel_keys(
        server_nonce.as_ref(), client_nonce.as_ref());
    Ok(client_keys.0)
}

pub fn fn_msg_header (
    _cipher_suite: &CipherSuite,
    message_header: &MessageChunkHeader,
) -> Result<MessageChunkHeader, FnError> {
    // The chunk `message_size` is no longer supplied as an explicit `fn_service_size(<payload>)`
    // term (which forced duplicating the whole service just to size the header). It is now computed
    // downstream from the payload we already carry -- in `fn_message` (outer, sent header) and in
    // `fn_data_to_mac` (inner header the MAC signs). Both derive the identical value, so the sent
    // bytes are unchanged. Deliberately-wrong header sizes are a bit-level concern (`--with-bit`).
    let mut header = message_header.clone();
    header.message_size = 0; // placeholder, overwritten once the payload/MAC length are known
    Ok(header)
}

pub fn fn_data_to_mac(
    cipher_suite: &CipherSuite,
    chunk_header: &MessageChunkHeader,
    security_header: &SymmetricSecurityHeader,
    request: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    // Patch the chunk header's message_size to match the payload before signing: the MAC must cover
    // the exact header bytes that will be sent. `request` = fn_service(seq, service), whose length
    // already equals fn_service_size(service) (the 8-byte sequence header matches the `8 +` there),
    // so this is identical to the size fn_message computes for the outer header.
    let security_policy = cipher_suite.security_policy();
    let mac_length: usize = security_policy.symmetric_signature_size();
    let mut header = chunk_header.clone();
    header.message_size = (header.byte_len() + 4 + request.len() + mac_length) as u32;
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(&header, &mut buffer);
    CodecP::encode(security_header, &mut buffer);
    buffer.extend_from_slice(request);
    Ok(buffer)
}

pub fn fn_mac (
    data: &Vec<u8>,
    cipher_suite: &CipherSuite,
    mac_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    if security_policy == SecurityPolicy::None {
        return Err(FnError::Crypto("Cannot compute MAC for SecurityPolicy::None".to_string()))
    };
    if mac_key.len() != security_policy.derived_signature_key_size() {
        return Err(FnError::Crypto("Cannot compute MAC: mac key size is incorrect".to_string()))
    };
    let mac_length: usize = security_policy.symmetric_signature_size();
    let mut mac = vec![0u8; mac_length];
    security_policy.symmetric_sign(mac_key, &data, &mut mac)
       .map_err( |_| {FnError::Crypto("Error during MAC computation".to_string())})?;
    Ok(mac)
}

pub fn fn_open_message (
    connexion: &u8,
    header: &MessageChunkHeader,
    security: &AsymmetricSecurityHeader,
    body: &EncryptedBody,
) -> Result<Message, FnError> {
    Ok(Message{
        connexion_id: *connexion,
        message: UaMessage::Open (header.clone(), security.clone(), body.clone())
    })
}

pub fn fn_message (
    connexion: &u8,
    header: &MessageChunkHeader,
    body: &MessageBody,
) -> Result<Message, FnError> {
    // Compute the chunk message_size from the body we already carry (service + MAC), rather than
    // taking a precomputed fn_service_size(<payload>) term in the header. service_len mirrors
    // fn_service_size (8-byte prefix + encoded service); mac length comes from the computed MAC.
    let mut buf = Vec::<u8>::new();
    CodecP::encode(&body.request, &mut buf);
    let service_len = 8 + buf.len();
    let mut header = header.clone();
    header.message_size = (header.byte_len() + 4 + service_len + body.mac.len()) as u32;
    Ok(Message{
        connexion_id: *connexion,
        message: UaMessage::Chunk (header, body.clone())
      })
}

pub fn fn_request_header (
    sa_token: &NodeId,
    request_id: &u32,
) -> Result<RequestHeader, FnError> {
    Ok(RequestHeader{
        authentication_token: sa_token.clone(),
        timestamp: UtcTime::from((2025, 11, 24, 9, 28, 05)),
        request_handle: *request_id,
        return_diagnostics: DiagnosticBits::empty(),
        audit_entry_id: UAString::null(),
        timeout_hint: 0, // No timeout
        additional_header: ExtensionObject::default()
    })
}
pub fn fn_response_header (
    request_id: &u32,
) -> Result<ResponseHeader, FnError> {
    Ok(ResponseHeader{
        timestamp: UtcTime::default(), // UtcTime::now(),
        request_handle: *request_id,
        additional_header: ExtensionObject::default(),
        service_result: StatusCode::Good,
        service_diagnostics: DiagnosticInfo::default(),
        string_table: Some(vec![UAString::null()]),
    })
}

const TYPICAL_CHANNEL_TOKEN_LIFETIME: u32 = 300000;

pub fn fn_client_open (
    request_header: &RequestHeader,
    kind: &SecurityTokenRequestType,
    security_mode: &MessageSecurityMode,
    client_nonce: &ByteString
) -> Result<ServiceMessage, FnError> {
    let request = OpenSecureChannelRequest {
        request_header: request_header.clone(),
        client_protocol_version: 0,
        request_type: *kind,
        security_mode: *security_mode,
        client_nonce: client_nonce.clone(),
        requested_lifetime: TYPICAL_CHANNEL_TOKEN_LIFETIME,
    };
    Ok(ServiceMessage::OpenSecureChannelRequest(request))
}

pub fn fn_server_open (
    response_header: &ResponseHeader,
    channel_id: &u32,
    token_id: &u32,
    server_nonce: &ByteString
) -> Result<ServiceMessage, FnError> {
    let response = OpenSecureChannelResponse {
        response_header: response_header.clone(),
        server_protocol_version: 0,
        security_token: ChannelSecurityToken{
            channel_id: *channel_id,
            token_id: *token_id,
            created_at: DateTime::now(),
            revised_lifetime: TYPICAL_CHANNEL_TOKEN_LIFETIME,
        },
        server_nonce: server_nonce.clone(),
    };
    Ok(ServiceMessage::OpenSecureChannelResponse(response))
}

pub fn fn_client_close (
    request_header: &RequestHeader,
) -> Result<ServiceMessage, FnError> {
    let request = CloseSecureChannelRequest {
        request_header: request_header.clone(),
    };
    Ok(ServiceMessage::CloseSecureChannelRequest(request))
}

pub fn fn_server_close (
    response_header: &ResponseHeader,
) -> Result<ServiceMessage, FnError> {
    let response = CloseSecureChannelResponse {
        response_header: response_header.clone(),
    };
    Ok(ServiceMessage::CloseSecureChannelResponse(response))
}

// Non-recursing dummy Comparable (opts OPC UA out of differential knowledge comparison)
crate::dummy_comparable!(CipherSuite);
