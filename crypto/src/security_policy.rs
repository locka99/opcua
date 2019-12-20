//! Security policy is the symmetric, asymmetric encryption / decryption + signing / verification
//! algorithms to use and enforce for the current session.
use std::fmt;
use std::str::FromStr;

use openssl::hash as openssl_hash;

use opcua_types::{
    ByteString,
    constants,
    status_code::StatusCode,
};

use crate::{
    SHA1_SIZE, SHA256_SIZE,
    aeskey::AesKey,
    pkey::{PrivateKey, PublicKey, RsaPadding, KeySize},
    hash,
    random,
};

// These are constants that govern the different encryption / signing modes for OPC UA. In some
// cases these algorithm string constants will be passed over the wire and code needs to test the
// string to see if the algorithm is supported.

/// 128Rsa15
///
/// A suite of algorithms that uses RSA15 as Key-Wrap-algorithm and 128-Bit for encryption algorithms.
pub mod basic128rsa15 {
    use crate::algorithms::*;

    /// SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA1;

    /// SymmetricEncryptionAlgorithm – Aes128 – (http://www.w3.org/2001/04/xmlenc#aes128-cbc).
    pub const SYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_AES128_CBC;

    /// AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA1;

    /// AsymmetricKeyWrapAlgorithm – KwRsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
    pub const ASYMMETRIC_KEY_WRAP_ALGORITHM: &str = ENC_RSA_15;

    /// AsymmetricEncryptionAlgorithm – Rsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_15;

    /// KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
    pub const KEY_DERIVATION_ALGORITHM: &str = KEY_P_SHA1;

    /// DerivedSignatureKeyLength – 128 / 16 bytes.
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 128;

    /// DerivedEncryptionKeyLength – 128 / 16 bytes.
    pub const DERIVED_ENCRYPTION_KEY_LENGTH: usize = 128;

    /// MinAsymmetricKeyLength – 512
    pub const MIN_ASYMMETRIC_KEY_LENGTH: usize = 512;

    /// MaxAsymmetricKeyLength – 2048
    pub const MAX_ASYMMETRIC_KEY_LENGTH: usize = 2048;

    /// Symmetric key length - 128 / 16 bytes
    pub const SYMMETRIC_KEY_LENGTH: usize = 128;

    /// CertificateSignatureAlgorithm – Sha1
    ///
    /// If a certificate or any certificate in the chain is not signed with a hash that is Sha1 or stronger then the certificate shall be rejected.
    pub const CERTIFICATE_SIGNATURE_ALGORITHM: &str = "Sha1";
}

/// Security Basic 256
///
/// A suite of algorithms that are for 256-Bit encryption, algorithms include:
pub mod basic256 {
    use crate::algorithms::*;

    /// SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA1;

    /// SymmetricEncryptionAlgorithm – Aes256 – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
    pub const SYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_AES256_CBC;

    /// AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA1;

    /// AsymmetricKeyWrapAlgorithm – KwRsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p).
    pub const ASYMMETRIC_KEY_WRAP_ALGORITHM: &str = ENC_RSA_OAEP_MGF1P;

    /// AsymmetricEncryptionAlgorithm – RsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_OAEP;

    /// KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
    pub const KEY_DERIVATION_ALGORITHM: &str = KEY_P_SHA1;

    /// DerivedSignatureKeyLength – 192.
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 192;

    /// DerivedEncryptionKeyLength – 192 / 24 bytes.
    pub const DERIVED_ENCRYPTION_KEY_LENGTH: usize = 192;

    /// MinAsymmetricKeyLength – 512
    pub const MIN_ASYMMETRIC_KEY_LENGTH: usize = 512;

    /// MaxAsymmetricKeyLength – 2048
    pub const MAX_ASYMMETRIC_KEY_LENGTH: usize = 2048;

    /// Symmetric key length - 256 / 32 bytes
    pub const SYMMETRIC_KEY_LENGTH: usize = 256;

    /// CertificateSignatureAlgorithm –
    ///
    /// Sha1 [deprecated] or Sha256 [recommended]
    ///
    /// If a certificate or any certificate in the chain is not signed with a hash that is Sha1 or stronger then the certificate shall be rejected.
    /// Release 1.03 17 OPC Unified Architecture, Part 7
    /// Both Sha1 and Sha256 shall be supported. However, it is recommended to use Sha256 since Sha1 is considered not secure anymore.
    pub const CERTIFICATE_SIGNATURE_ALGORITHM: &str = "Sha256";
}

/// Security Basic 256 Sha256
///
/// A suite of algorithms that are for 256-Bit encryption, algorithms include.
pub mod basic256sha256 {
    use crate::algorithms::*;

    /// SymmetricSignatureAlgorithm – Hmac_Sha256 – (http://www.w3.org/2000/09/xmldsig#hmac-sha256).
    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA256;

    /// SymmetricEncryptionAlgorithm – Aes256_CBC – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
    pub const SYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_AES256_CBC;

    /// AsymmetricSignatureAlgorithm – Rsa_Sha256 – (http://www.w3.org/2001/04/xmldsig#rsa-sha256).
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA256;

    /// AsymmetricKeyWrapAlgorithm – KwRsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p).
    pub const ASYMMETRIC_KEY_WRAP_ALGORITHM: &str = ENC_RSA_OAEP_MGF1P;

    /// -> AsymmetricEncryptionAlgorithm – Rsa_Oaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_OAEP;

    /// KeyDerivationAlgorithm – PSHA256 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256).
    pub const KEY_DERIVATION_ALGORITHM: &str = KEY_P_SHA256;

    /// DerivedSignatureKeyLength – 256 / 32 bytes.
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;

    /// DerivedEncryptionKeyLength – 256 / 32 bytes.
    pub const DERIVED_ENCRYPTION_KEY_LENGTH: usize = 256;

    /// MinAsymmetricKeyLength – 1024
    pub const MIN_ASYMMETRIC_KEY_LENGTH: usize = 1024;

    /// MaxAsymmetricKeyLength – 2048
    pub const MAX_ASYMMETRIC_KEY_LENGTH: usize = 2048;

    /// Symmetric key length - 256 / 32 bytes
    pub const SYMMETRIC_KEY_LENGTH: usize = 256;

    /// CertificateSignatureAlgorithm – Sha256
    ///
    /// If a certificate or any certificate in the chain is not signed with a hash that is Sha256 or stronger
    /// then the certificate shall be rejected. Support for this security profile may require support for
    /// a second application instance certificate, with a larger keysize. Applications shall support
    /// multiple Application Instance Certificates if required by supported Security Polices and use
    /// the certificate that is required for a given security endpoint.
    pub const CERTIFICATE_SIGNATURE_ALGORITHM: &str = "Sha256";
}

/// SecurityPolicy implies what encryption and signing algorithms and their relevant key strengths
/// are used during an encrypted session.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum SecurityPolicy {
    Unknown,
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
}

impl fmt::Display for SecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl FromStr for SecurityPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            constants::SECURITY_POLICY_NONE | constants::SECURITY_POLICY_NONE_URI => SecurityPolicy::None,
            constants::SECURITY_POLICY_BASIC_128_RSA_15 | constants::SECURITY_POLICY_BASIC_128_RSA_15_URI => SecurityPolicy::Basic128Rsa15,
            constants::SECURITY_POLICY_BASIC_256 | constants::SECURITY_POLICY_BASIC_256_URI => SecurityPolicy::Basic256,
            constants::SECURITY_POLICY_BASIC_256_SHA_256 | constants::SECURITY_POLICY_BASIC_256_SHA_256_URI => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy \"{}\" is not recognized", s);
                SecurityPolicy::Unknown
            }
        })
    }
}

impl From<SecurityPolicy> for String {
    fn from(v: SecurityPolicy) -> String {
        v.to_str().to_string()
    }
}

impl SecurityPolicy {
    pub fn to_uri(&self) -> &'static str {
        match self {
            SecurityPolicy::None => constants::SECURITY_POLICY_NONE_URI,
            SecurityPolicy::Basic128Rsa15 => constants::SECURITY_POLICY_BASIC_128_RSA_15_URI,
            SecurityPolicy::Basic256 => constants::SECURITY_POLICY_BASIC_256_URI,
            SecurityPolicy::Basic256Sha256 => constants::SECURITY_POLICY_BASIC_256_SHA_256_URI,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            SecurityPolicy::None => constants::SECURITY_POLICY_NONE,
            SecurityPolicy::Basic128Rsa15 => constants::SECURITY_POLICY_BASIC_128_RSA_15,
            SecurityPolicy::Basic256 => constants::SECURITY_POLICY_BASIC_256,
            SecurityPolicy::Basic256Sha256 => constants::SECURITY_POLICY_BASIC_256_SHA_256,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a string");
            }
        }
    }

    pub fn asymmetric_encryption_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Basic256 => basic256::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => basic256sha256::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256 => basic256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => basic256sha256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn symmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256 => basic256::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => basic256sha256::SYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Symmetric key size in bytes
    pub fn symmetric_key_size(&self) -> usize {
        let length = match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::SYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256 => basic256::SYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => basic256sha256::SYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        };
        length / 8
    }

    // Plaintext block size in bytes
    pub fn plain_block_size(&self) -> usize {
        match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => 16,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Signature size in bytes
    pub fn symmetric_signature_size(&self) -> usize {
        match self {
            SecurityPolicy::None => 0,
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => SHA1_SIZE,
            SecurityPolicy::Basic256Sha256 => SHA256_SIZE,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the derived signature key (not the signature) size in bytes
    pub fn derived_signature_key_size(&self) -> usize {
        let length = match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Basic256 => basic256::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => basic256sha256::DERIVED_SIGNATURE_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        };
        length / 8
    }

    /// Returns the max key length in bits
    pub fn min_asymmetric_key_length(&self) -> usize {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::MIN_ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256 => basic256::MIN_ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => basic256sha256::MIN_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the max key length in bits
    pub fn max_asymmetric_key_length(&self) -> usize {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic128rsa15::MAX_ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256 => basic256::MAX_ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => basic256sha256::MAX_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Creates a random nonce in a bytestring with a length appropriate for the policy
    pub fn random_nonce(&self) -> ByteString {
        match self {
            SecurityPolicy::None => ByteString::null(),
            SecurityPolicy::Basic128Rsa15 |
            SecurityPolicy::Basic256 |
            SecurityPolicy::Basic256Sha256 => random::byte_string(self.symmetric_key_size()),
            _ => {
                panic!("Cannot make a nonce because key size is unknown");
            }
        }
    }

    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            constants::SECURITY_POLICY_NONE_URI => SecurityPolicy::None,
            constants::SECURITY_POLICY_BASIC_128_RSA_15_URI => SecurityPolicy::Basic128Rsa15,
            constants::SECURITY_POLICY_BASIC_256_URI => SecurityPolicy::Basic256,
            constants::SECURITY_POLICY_BASIC_256_SHA_256_URI => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy uri \"{}\" is not recognized", uri);
                SecurityPolicy::Unknown
            }
        }
    }

    /// Pseudo random function is used as a key derivation algorithm. It creates pseudo random bytes
    /// from a secret and seed specified by the parameters.
    fn prf(&self, secret: &[u8], seed: &[u8], length: usize, offset: usize) -> Vec<u8> {
        // P_SHA1 or P_SHA256
        let message_digest = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => openssl_hash::MessageDigest::sha1(),
            SecurityPolicy::Basic256Sha256 => openssl_hash::MessageDigest::sha256(),
            _ => {
                panic!("Invalid policy");
            }
        };
        let result = hash::p_sha(message_digest, secret, seed, offset + length);
        result[offset..(offset + length)].to_vec()
    }

    /// Part 6
    /// 6.7.5
    /// Deriving keys Once the SecureChannel is established the Messages are signed and encrypted with
    /// keys derived from the Nonces exchanged in the OpenSecureChannel call. These keys are derived by passing the Nonces to a pseudo-random function which produces a sequence of bytes from a set of inputs. A pseudo-random function is represented by the following function declaration:
    ///
    /// ```c++
    /// Byte[] PRF( Byte[] secret,  Byte[] seed,  i32 length,  i32 offset)
    /// ```
    ///
    /// Where length is the number of bytes to return and offset is a number of bytes from the beginning of the sequence.
    ///
    /// The lengths of the keys that need to be generated depend on the SecurityPolicy used for the channel.
    /// The following information is specified by the SecurityPolicy:
    ///
    /// a) SigningKeyLength (from the DerivedSignatureKeyLength);
    /// b) EncryptingKeyLength (implied by the SymmetricEncryptionAlgorithm);
    /// c) EncryptingBlockSize (implied by the SymmetricEncryptionAlgorithm).
    ///
    /// The parameters passed to the pseudo random function are specified in Table 33.
    ///
    /// Table 33 – Cryptography key generation parameters
    ///
    /// Key | Secret | Seed | Length | Offset
    /// ClientSigningKey | ServerNonce | ClientNonce | SigningKeyLength | 0
    /// ClientEncryptingKey | ServerNonce | ClientNonce | EncryptingKeyLength | SigningKeyLength
    /// ClientInitializationVector | ServerNonce | ClientNonce | EncryptingBlockSize | SigningKeyLength + EncryptingKeyLength
    /// ServerSigningKey | ClientNonce | ServerNonce | SigningKeyLength | 0
    /// ServerEncryptingKey | ClientNonce | ServerNonce | EncryptingKeyLength | SigningKeyLength
    /// ServerInitializationVector | ClientNonce | ServerNonce | EncryptingBlockSize | SigningKeyLength + EncryptingKeyLength
    ///
    /// The Client keys are used to secure Messages sent by the Client. The Server keys
    /// are used to secure Messages sent by the Server.
    ///
    pub fn make_secure_channel_keys(&self, secret: &[u8], seed: &[u8]) -> (Vec<u8>, AesKey, Vec<u8>) {
        // Work out the length of stuff
        let signing_key_length = self.derived_signature_key_size();
        let (encrypting_key_length, encrypting_block_size) = match self {
            SecurityPolicy::Basic128Rsa15 => (16, 16),
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => (32, 16),
            _ => {
                panic!("Invalid policy");
            }
        };

        let signing_key = self.prf(secret, seed, signing_key_length, 0);
        let encrypting_key = self.prf(secret, seed, encrypting_key_length, signing_key_length);
        let encrypting_key = AesKey::new(*self, &encrypting_key);
        let iv = self.prf(secret, seed, encrypting_block_size, signing_key_length + encrypting_key_length);

        (signing_key, encrypting_key, iv)
    }

    /// Produce a signature of the data using an asymmetric key. Stores the signature in the supplied
    /// `signature` buffer. Returns the size of the signature within that buffer.
    pub fn asymmetric_sign(&self, signing_key: &PrivateKey, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                signing_key.sign_hmac_sha1(data, signature)?
            }
            SecurityPolicy::Basic256Sha256 => {
                signing_key.sign_hmac_sha256(data, signature)?
            }
            _ => {
                panic!("Invalid policy");
            }
        };
        Ok(result)
    }

    /// Verifies a signature of the data using an asymmetric key. In a debugging scenario, the
    /// signing key can also be supplied so that the supplied signature can be compared to a freshly
    /// generated signature.
    pub fn asymmetric_verify_signature(&self, verification_key: &PublicKey, data: &[u8], signature: &[u8], their_private_key: Option<PrivateKey>) -> Result<(), StatusCode> {
        // Asymmetric verify signature against supplied certificate
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                verification_key.verify_hmac_sha1(data, signature)?
            }
            SecurityPolicy::Basic256Sha256 => {
                verification_key.verify_hmac_sha256(data, signature)?
            }
            _ => {
                panic!("Invalid policy");
            }
        };
        if result {
            Ok(())
        } else {
            error!("Signature mismatch");

            // For debugging / unit testing purposes we might have a their_key to see the source of the error
            if let Some(their_key) = their_private_key {
                // Calculate the signature using their key, see what we were expecting versus theirs
                let mut their_signature = vec![0u8; their_key.size()];
                self.asymmetric_sign(&their_key, data, their_signature.as_mut_slice())?;
                trace!("Using their_key, signature should be {:?}", &their_signature);
            }
            Err(StatusCode::BadSecurityChecksFailed)
        }
    }

    /// Returns the padding algorithm used for this security policy.
    pub fn padding(&self) -> RsaPadding {
        match self {
            SecurityPolicy::Basic128Rsa15 => RsaPadding::PKCS1,
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => RsaPadding::OAEP,
            _ => {
                panic!("Security policy is not supported, shouldn't have gotten here");
            }
        }
    }
    /// Encrypts a message using the supplied encryption key, returns the encrypted size. Destination
    /// buffer must be large enough to hold encrypted bytes including any padding.
    pub fn asymmetric_encrypt(&self, encryption_key: &PublicKey, src: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        let padding = self.padding();
        encryption_key.public_encrypt(src, dst, padding)
            .map_err(|_| StatusCode::BadUnexpectedError)
    }

    /// Decrypts a message whose thumbprint matches the x509 cert and private key pair.
    ///
    /// Returns the number of decrypted bytes
    pub fn asymmetric_decrypt(&self, decryption_key: &PrivateKey, src: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        let padding = self.padding();
        decryption_key.private_decrypt(src, dst, padding)
            .map_err(|_| {
                error!("Asymmetric decryption failed");
                StatusCode::BadSecurityChecksFailed
            })
    }

    /// Produce a signature of some data using the supplied symmetric key. Signing algorithm is determined
    /// by the security policy. Signature is stored in the supplied `signature` argument.
    pub fn symmetric_sign(&self, key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
        trace!("Producing signature for {} bytes of data into signature of {} bytes", data.len(), signature.len());
        match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                // HMAC SHA-1
                hash::hmac_sha1(key, data, signature)
            }
            SecurityPolicy::Basic256Sha256 => {
                // HMAC SHA-256
                hash::hmac_sha256(key, data, signature)
            }
            _ => {
                panic!("Unsupported policy")
            }
        }
    }

    /// Verify the signature of a data block using the supplied symmetric key.
    pub fn symmetric_verify_signature(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        // Verify the signature using SHA-1 / SHA-256 HMAC
        let verified = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                // HMAC SHA-1
                hash::verify_hmac_sha1(key, data, signature)
            }
            SecurityPolicy::Basic256Sha256 => {
                // HMAC SHA-256
                hash::verify_hmac_sha256(key, data, signature)
            }
            _ => {
                panic!("Unsupported policy")
            }
        };
        if verified {
            Ok(verified)
        } else {
            error!("Signature invalid {:?}", signature);
            Err(StatusCode::BadSecurityChecksFailed)
        }
    }

    /// Encrypt the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_encrypt(&self, key: &AesKey, iv: &[u8], src: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        key.encrypt(src, iv, dst)
    }

    /// Decrypts the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_decrypt(&self, key: &AesKey, iv: &[u8], src: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        key.decrypt(src, iv, dst)
    }
}
