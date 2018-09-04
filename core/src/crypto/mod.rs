//! Crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.

pub mod x509;
pub mod aeskey;
pub mod pkey;
pub mod thumbprint;
pub mod certificate_store;
pub mod hash;
pub mod security_policy;

pub use self::x509::*;
pub use self::aeskey::*;
pub use self::pkey::*;
pub use self::thumbprint::*;
pub use self::certificate_store::*;
pub use self::hash::*;
pub use self::security_policy::*;

use opcua_types::{UAString, ByteString};
use opcua_types::service_types::SignatureData;
use opcua_types::status_code::StatusCode;

// Size of a SHA1 hash value in bytes
pub const SHA1_SIZE: usize = 20;
// Size of a SHA256 hash value bytes
pub const SHA256_SIZE: usize = 32;

/// These are algorithms that are used by various policies or external to this file
pub mod algorithms {
    /// Symmetric encryption algorithm AES128-CBC
    pub const ENC_AES128_CBC: &'static str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

    /// Symmetric encryption algorithm AES256-CBC
    pub const ENC_AES256_CBC: &'static str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

    /// Asymmetric encryption algorithm RSA15
    pub const ENC_RSA_15: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

    /// Asymmetric encryption algorithm RSA-OAEP
    pub const ENC_RSA_OAEP: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";

    /// Asymmetric encryption algorithm RSA-OAEP-MGF1P
    pub const ENC_RSA_OAEP_MGF1P: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    /// SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
    pub const DSIG_HMAC_SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

    /// SymmetricSignatureAlgorithm – HmacSha256 – (http://www.w3.org/2000/09/xmldsig#hmac-sha256).
    pub const DSIG_HMAC_SHA256: &'static str = "http://www.w3.org/2000/09/xmldsig#hmac-sha256";

    /// Asymmetric digital signature algorithm using RSA-SHA1
    pub const DSIG_RSA_SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// Asymmetric digital signature algorithm using RSA-SHA256
    pub const DSIG_RSA_SHA256: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// Key derivation algorithm P_SHA1
    pub const KEY_P_SHA1: &'static str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1";

    /// Key derivation algorithm P_SHA256
    pub const KEY_P_SHA256: &'static str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256";
}

pub fn concat_data_and_nonce(data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + nonce.len());
    buffer.extend_from_slice(data);
    buffer.extend_from_slice(nonce);
    buffer
}

/// Creates a `SignatureData` object by signing the supplied certificate and nonce with a pkey
pub fn create_signature_data(signing_key: &PrivateKey, security_policy: SecurityPolicy, contained_cert: &ByteString, nonce: &ByteString) -> Result<SignatureData, StatusCode> {
    let (algorithm, signature) = if contained_cert.is_null() || nonce.is_null() {
        (UAString::null(), ByteString::null())
    } else {
        let data = concat_data_and_nonce(contained_cert.as_ref(), nonce.as_ref());
        // Sign the bytes and return the algorithm, signature
        match security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                let signing_key_size = signing_key.size();
                let mut signature = vec![0u8; signing_key_size];
                let _ = security_policy.asymmetric_sign(signing_key, &data, &mut signature)?;
                (
                    UAString::from(security_policy.asymmetric_signature_algorithm()),
                    ByteString::from(&signature)
                )
            }
            SecurityPolicy::None => (
                UAString::null(), ByteString::null()
            ),
            _ => {
                error!("An unknown security policy was passed to create_signature_data and rejected");
                (UAString::null(), ByteString::null())
            }
        }
    };
    let signature_data = SignatureData { algorithm, signature };
    trace!("Creating signature contained_cert = {:?}", signature_data);
    Ok(signature_data)
}

/// Verifies that the supplied signature data was produced by the signing cert. The contained cert and nonce are supplied so
/// the signature can be verified against the expected data.
pub fn verify_signature_data(signature: &SignatureData, security_policy: SecurityPolicy, signing_cert: &X509, contained_cert: &X509, contained_nonce: &ByteString) -> StatusCode {
    if let Ok(verification_key) = signing_cert.public_key() {
        // This is the data that the should have been signed
        let contained_cert = contained_cert.as_byte_string();
        let data = concat_data_and_nonce(contained_cert.as_ref(), contained_nonce.as_ref());

        // Verify the signature
        let result = security_policy.asymmetric_verify_signature(&verification_key, &data, signature.signature.as_ref(), None);
        if result.is_ok() {
            StatusCode::Good
        } else {
            let result = result.unwrap_err();
            error!("Client signature verification failed, status code = {:?}", result);
            result
        }
    } else {
        error!("Signature verification failed, signing certificate has no public key to verify with");
        StatusCode::BadUnexpectedError
    }
}