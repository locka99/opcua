// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.

use std::fmt;

use crate::types::{service_types::SignatureData, status_code::StatusCode, ByteString, UAString};
pub use {
    aeskey::*, certificate_store::*, hash::*, pkey::*, security_policy::*, thumbprint::*,
    user_identity::*, x509::*,
};

#[cfg(test)]
mod tests;

pub mod aeskey;
pub mod certificate_store;
pub mod hash;
pub mod pkey;
pub mod random;
pub mod security_policy;
pub mod thumbprint;
pub mod user_identity;
pub mod x509;

// Size of a SHA1 hash value in bytes
pub const SHA1_SIZE: usize = 20;
// Size of a SHA256 hash value bytes
pub const SHA256_SIZE: usize = 32;

/// These are algorithms that are used by various policies or external to this file
pub(crate) mod algorithms {
    // Symmetric encryption algorithm AES128-CBC
    //pub const ENC_AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

    // Symmetric encryption algorithm AES256-CBC
    //pub const ENC_AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

    /// Asymmetric encryption algorithm RSA15
    pub const ENC_RSA_15: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

    /// Asymmetric encryption algorithm RSA-OAEP
    pub const ENC_RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";

    /// Asymmetrric encrypttion
    pub const ENC_RSA_OAEP_SHA256: &str = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256";

    // Asymmetric encryption algorithm RSA-OAEP-MGF1P
    //pub const ENC_RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    /// SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
    pub const DSIG_HMAC_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

    /// SymmetricSignatureAlgorithm – HmacSha256 – (http://www.w3.org/2000/09/xmldsig#hmac-sha256).
    pub const DSIG_HMAC_SHA256: &str = "http://www.w3.org/2000/09/xmldsig#hmac-sha256";

    /// Asymmetric digital signature algorithm using RSA-SHA1
    pub const DSIG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// Asymmetric digital signature algorithm using RSA-SHA256
    pub const DSIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// Asymmetric digital signature algorithm using RSA-PSS_SHA2-256
    pub const DSIG_RSA_PSS_SHA2_256: &str = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256";

    // Key derivation algorithm P_SHA1
    //pub const KEY_P_SHA1: &str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1";

    // Key derivation algorithm P_SHA256
    //pub const KEY_P_SHA256: &str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256";
}

fn concat_data_and_nonce(data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + nonce.len());
    buffer.extend_from_slice(data);
    buffer.extend_from_slice(nonce);
    buffer
}

/// Creates a `SignatureData` object by signing the supplied certificate and nonce with a pkey
pub fn create_signature_data(
    signing_key: &PrivateKey,
    security_policy: SecurityPolicy,
    contained_cert: &ByteString,
    nonce: &ByteString,
) -> Result<SignatureData, StatusCode> {
    // TODO this function should be refactored to return an error if the contained cert or nonce is incorrect, not a blank signature. That
    //  very much depends on reading the spec to see what should happen if its not possible to create a signature, e.g. because
    //  policy is None.

    let (algorithm, signature) = if contained_cert.is_null() || nonce.is_null() {
        (UAString::null(), ByteString::null())
    } else {
        let data = concat_data_and_nonce(contained_cert.as_ref(), nonce.as_ref());
        // Sign the bytes and return the algorithm, signature
        match security_policy {
            SecurityPolicy::None => (UAString::null(), ByteString::null()),
            SecurityPolicy::Unknown => {
                error!(
                    "An unknown security policy was passed to create_signature_data and rejected"
                );
                (UAString::null(), ByteString::null())
            }
            security_policy => {
                let signing_key_size = signing_key.size();
                let mut signature = vec![0u8; signing_key_size];
                let _ = security_policy.asymmetric_sign(signing_key, &data, &mut signature)?;
                (
                    UAString::from(security_policy.asymmetric_signature_algorithm()),
                    ByteString::from(&signature),
                )
            }
        }
    };
    let signature_data = SignatureData {
        algorithm,
        signature,
    };
    trace!("Creating signature contained_cert = {:?}", signature_data);
    Ok(signature_data)
}

/// Verifies that the supplied signature data was produced by the signing cert. The contained cert and nonce are supplied so
/// the signature can be verified against the expected data.
pub fn verify_signature_data(
    signature: &SignatureData,
    security_policy: SecurityPolicy,
    signing_cert: &X509,
    contained_cert: &X509,
    contained_nonce: &[u8],
) -> StatusCode {
    if let Ok(verification_key) = signing_cert.public_key() {
        // This is the data that the should have been signed
        let contained_cert = contained_cert.as_byte_string();
        let data = concat_data_and_nonce(contained_cert.as_ref(), contained_nonce);

        // Verify the signature
        let result = security_policy.asymmetric_verify_signature(
            &verification_key,
            &data,
            signature.signature.as_ref(),
            None,
        );
        match result {
            Ok(_) => StatusCode::Good,
            Err(result) => {
                error!(
                    "Client signature verification failed, status code = {}",
                    result
                );
                result
            }
        }
    } else {
        error!(
            "Signature verification failed, signing certificate has no public key to verify with"
        );
        StatusCode::BadUnexpectedError
    }
}

#[derive(Debug)]
pub struct HostnameError;

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostnameError")
    }
}

impl std::error::Error for HostnameError {}

/// Returns this computer's hostname
pub fn hostname() -> Result<String, HostnameError> {
    use gethostname::gethostname;
    gethostname().into_string().map_err(|_| HostnameError {})
}
