//! Crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.

pub mod types;
pub mod certificate_store;
pub mod hash;
pub mod security_policy;

pub use self::types::*;
pub use self::certificate_store::*;
pub use self::hash::*;
pub use self::security_policy::*;

use opcua_types::*;

fn concat_data_and_nonce(data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + nonce.len());
    buffer.extend_from_slice(data);
    buffer.extend_from_slice(nonce);
    buffer
}

/// Verifies that cert matches the signed data
pub fn verify_signature(verifying_cert: &X509, signature_data: &SignatureData, data: &ByteString, nonce: &ByteString) -> StatusCode {
    if data.is_null() || nonce.is_null() {
        error!("Data or nonce are null");
        BAD_UNEXPECTED_ERROR
    } else if signature_data.algorithm.is_null() {
        error!("Signature data has no algorithm");
        BAD_UNEXPECTED_ERROR
    } else {
        // Get the public key
        if let Ok(public_key) = verifying_cert.public_key() {
            let data = concat_data_and_nonce(data.as_ref(), nonce.as_ref());
            let signature = signature_data.signature.as_ref();

            let security_policy_uri = signature_data.algorithm.as_ref();
            let security_policy = SecurityPolicy::from_uri(security_policy_uri);

            let verified = match security_policy {
                SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                    public_key.verify_sha1(&data, signature)
                }
                SecurityPolicy::Basic256Sha256 => {
                    public_key.verify_sha256(&data, signature)
                }
                SecurityPolicy::None => {
                    error!("Cannot verify a signature with no security policy of None");
                    false
                }
                _ => {
                    error!("An unknown security policy uri {} was passed to signing function and rejected", security_policy_uri);
                    false
                }
            };
            if verified { GOOD } else { BAD_APPLICATION_SIGNATURE_INVALID }
        } else {
            error!("Public key cannot be obtained from cert");
            BAD_UNEXPECTED_ERROR
        }
    }
}

/// Creates a SignatureData object by signing the supplied certificate and nonce with a pkey
pub fn create_signature_data(pkey: &PKey, security_policy_uri: &str, data: &ByteString, nonce: &ByteString) -> SignatureData {
    let (algorithm, signature) = if data.is_null() || nonce.is_null() {
        (UAString::null(), ByteString::null())
    } else {
        let data = concat_data_and_nonce(data.as_ref(), nonce.as_ref());

        // Sign the bytes and return the algorithm, signature
        let security_policy = SecurityPolicy::from_uri(security_policy_uri);
        match security_policy {
            SecurityPolicy::Basic128Rsa15 => (
                UAString::from_str(security_policy.asymmetric_signature_algorithm()),
                ByteString::from_bytes(&pkey.sign_sha1(&data))
            ),
            SecurityPolicy::Basic256 => (
                UAString::from_str(security_policy.asymmetric_signature_algorithm()),
                ByteString::from_bytes(&pkey.sign_sha1(&data))
            ),
            SecurityPolicy::Basic256Sha256 => (
                UAString::from_str(security_policy.asymmetric_signature_algorithm()),
                ByteString::from_bytes(&pkey.sign_sha256(&data))
            ),
            SecurityPolicy::None => (
                UAString::null(), ByteString::null()
            ),
            _ => {
                error!("An unknown security policy uri {} was passed to signing function and rejected", security_policy_uri);
                (UAString::null(), ByteString::null())
            }
        }
    };
    SignatureData { algorithm, signature }
}