use std::fmt;

use openssl::hash as openssl_hash;
use openssl::rsa::*;

use opcua_types::StatusCode;
use opcua_types::StatusCode::*;

use crypto::types::{AesKey, PKey};
use crypto::hash;

/// URI supplied for the None security policy
pub const SECURITY_POLICY_NONE_URI: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#None";
/// URI supplied for the Basic128Rsa15 security policy
pub const SECURITY_POLICY_BASIC_128_RSA_15_URI: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
/// URI supplied for the Basic256 security policy
pub const SECURITY_POLICY_BASIC_256_URI: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
/// URI supplied for the Basic256Sha256 security policy
pub const SECURITY_POLICY_BASIC_256_SHA_256_URI: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

/// String used as shorthand in config files, debug etc.for None security policy
pub const SECURITY_POLICY_NONE: &'static str = "None";
/// String used as shorthand in config files, debug etc.for Basic128Rsa15 security policy
pub const SECURITY_POLICY_BASIC_128_RSA_15: &'static str = "Basic128Rsa15";
/// String used as shorthand in config files, debug etc.for Basic256 security policy
pub const SECURITY_POLICY_BASIC_256: &'static str = "Basic256";
/// String used as shorthand in config files, debug etc.for Basic256Sha256 security policy
pub const SECURITY_POLICY_BASIC_256_SHA_256: &'static str = "Basic256Sha256";

// These are constants that govern the different encryption / signing modes for OPC UA. In some
// cases these algorithm string constants will be passed over the wire and code needs to test the
// string to see if the algorithm is supported.

/// 128Rsa15
///
/// A suite of algorithms that uses RSA15 as Key-Wrap-algorithm and 128-Bit for encryption algorithms.
pub mod basic128rsa15
{
    /// SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &'static str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

    /// SymmetricEncryptionAlgorithm – Aes128 – (http://www.w3.org/2001/04/xmlenc#aes128-cbc).
    pub const SYMMETRIC_ENCRYPTION_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

    /// AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// AsymmetricKeyWrapAlgorithm – KwRsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
    pub const ASYMMETRIC_KEY_WRAP_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

    /// AsymmetricEncryptionAlgorithm – Rsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

    /// KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
    pub const KEY_DERIVATION_ALGORITHM: &'static str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1";

    /// DerivedSignatureKeyLength – 128.
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 128;

    /// MinAsymmetricKeyLength – 1024
    pub const MIN_ASYMMETRIC_KEY_LENGTH: usize = 1024;

    /// MaxAsymmetricKeyLength – 2048
    pub const MAX_ASYMMETRIC_KEY_LENGTH: usize = 2048;

    /// CertificateSignatureAlgorithm – Sha1
    ///
    /// If a certificate or any certificate in the chain is not signed with a hash that is Sha1 or stronger then the certificate shall be rejected.
    pub const CERTIFICATE_SIGNATURE_ALGORITHM: &'static str = "Sha1";
}

/// Security Basic 256
///
/// A suite of algorithms that are for 256-Bit encryption, algorithms include:
pub mod basic256 {
    /// SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &'static str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

    ///SymmetricEncryptionAlgorithm – Aes256 – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
    pub const SYMMETRIC_ENCRYPTION_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

    /// AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // AsymmetricKeyWrapAlgorithm – KwRsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p).
    pub const ASYMMETRIC_KEY_WRAP_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    /// AsymmetricEncryptionAlgorithm – RsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";

    /// KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
    pub const KEY_DERIVATION_ALGORITHM: &'static str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1";

    /// DerivedSignatureKeyLength – 192.
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 192;

    /// MinAsymmetricKeyLength – 1024
    pub const MIN_ASYMMETRIC_KEY_LENGTH: usize = 1024;

    /// MaxAsymmetricKeyLength – 2048
    pub const MAX_ASYMMETRIC_KEY_LENGTH: usize = 2048;

    /// CertificateSignatureAlgorithm –
    ///
    /// Sha1 [deprecated] or Sha256 [recommended]
    ///
    /// If a certificate or any certificate in the chain is not signed with a hash that is Sha1 or stronger then the certificate shall be rejected.
    /// Release 1.03 17 OPC Unified Architecture, Part 7
    /// Both Sha1 and Sha256 shall be supported. However, it is recommended to use Sha256 since Sha1 is considered not secure anymore.
    pub const CERTIFICATE_SIGNATURE_ALGORITHM: &'static str = "Sha256";
}

/// Security Basic 256 Sha256
///
/// A suite of algorithms that are for 256-Bit encryption, algorithms include.
pub mod basic256sha256 {
    /// SymmetricSignatureAlgorithm – Hmac_Sha256 – (http://www.w3.org/2000/09/xmldsig#hmac-sha256).
    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &'static str = "http://www.w3.org/2000/09/xmldsig#hmac-sha256";

    /// SymmetricEncryptionAlgorithm – Aes256_CBC – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
    pub const SYMMETRIC_ENCRYPTION_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

    /// AsymmetricSignatureAlgorithm – Rsa_Sha256 – (http://www.w3.org/2001/04/xmldsig#rsa-sha256).
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmldsig#rsa-sha256";

    // AsymmetricKeyWrapAlgorithm – KwRsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p).
    pub const ASYMMETRIC_KEY_WRAP_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    // -> AsymmetricEncryptionAlgorithm – Rsa_Oaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &'static str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";

    // KeyDerivationAlgorithm – PSHA256 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256).
    pub const KEY_DERIVATION_ALGORITHM: &'static str = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256";

    /// DerivedSignatureKeyLength – 256
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;

    /// MinAsymmetricKeyLength – 2048
    pub const MIN_ASYMMETRIC_KEY_LENGTH: usize = 2048;

    /// MaxAsymmetricKeyLength – 4096
    pub const MAX_ASYMMETRIC_KEY_LENGTH: usize = 4096;

    /// CertificateSignatureAlgorithm – Sha256
    ///
    /// If a certificate or any certificate in the chain is not signed with a hash that is Sha256 or stronger
    /// then the certificate shall be rejected. Support for this security profile may require support for
    /// a second application instance certificate, with a larger keysize. Applications shall support
    /// multiple Application Instance Certificates if required by supported Security Polices and use
    /// the certificate that is required for a given security endpoint.
    pub const CERTIFICATE_SIGNATURE_ALGORITHM: &'static str = "Sha256";
}

/// SecurityPolicy implies what encryption and signing algorithms and their relevant key strengths
/// are used during an encrypted session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityPolicy {
    Unknown,
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
}

impl fmt::Display for SecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            &SecurityPolicy::None => SECURITY_POLICY_NONE,
            &SecurityPolicy::Basic128Rsa15 => SECURITY_POLICY_BASIC_128_RSA_15,
            &SecurityPolicy::Basic256 => SECURITY_POLICY_BASIC_256,
            &SecurityPolicy::Basic256Sha256 => SECURITY_POLICY_BASIC_256_SHA_256,
            _ => ""
        };
        write!(f, "{}", name)
    }
}

impl SecurityPolicy {
    pub fn to_uri(&self) -> &'static str {
        match self {
            &SecurityPolicy::None => SECURITY_POLICY_NONE_URI,
            &SecurityPolicy::Basic128Rsa15 => SECURITY_POLICY_BASIC_128_RSA_15_URI,
            &SecurityPolicy::Basic256 => SECURITY_POLICY_BASIC_256_URI,
            &SecurityPolicy::Basic256Sha256 => SECURITY_POLICY_BASIC_256_SHA_256_URI,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            &SecurityPolicy::Basic128Rsa15 => basic128rsa15::ASYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256 => basic256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256Sha256 => basic256sha256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn symmetric_signature_algorithm(&self) -> &'static str {
        match self {
            &SecurityPolicy::Basic128Rsa15 => basic128rsa15::SYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256 => basic256::SYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256Sha256 => basic256sha256::SYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn symmetric_key_size(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => 16,
            &SecurityPolicy::Basic256 => 32,
            &SecurityPolicy::Basic256Sha256 => 32,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Plaintext block size in bytes
    pub fn plain_block_size(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => 16,
            &SecurityPolicy::Basic256 => 16,
            &SecurityPolicy::Basic256Sha256 => 16,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Cipher block size in bytes
    pub fn cipher_block_size(&self) -> usize {
        // AES uses a 128-bit block size regardless of key length
        match self {
            &SecurityPolicy::Basic128Rsa15 => 16,
            &SecurityPolicy::Basic256 => 16,
            &SecurityPolicy::Basic256Sha256 => 16,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn symmetric_signature_size(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 | &SecurityPolicy::Basic256 => 20,
            &SecurityPolicy::Basic256Sha256 => 32,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the derived signature key (not the signature) size in bytes
    pub fn derived_signature_key_size(&self) -> usize {
        let result = match self {
            &SecurityPolicy::Basic128Rsa15 => basic128rsa15::DERIVED_SIGNATURE_KEY_LENGTH,
            &SecurityPolicy::Basic256 => basic256::DERIVED_SIGNATURE_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => basic256sha256::DERIVED_SIGNATURE_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        };
        result / 8
    }

    /// Returns the max key length in bits
    pub fn min_asymmetric_key_length(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => basic128rsa15::MIN_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256 => basic256::MIN_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => basic256sha256::MIN_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the max key length in bits
    pub fn max_asymmetric_key_length(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => basic128rsa15::MAX_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256 => basic256::MAX_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => basic256sha256::MAX_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            SECURITY_POLICY_NONE_URI => SecurityPolicy::None,
            SECURITY_POLICY_BASIC_128_RSA_15_URI => SecurityPolicy::Basic128Rsa15,
            SECURITY_POLICY_BASIC_256_URI => SecurityPolicy::Basic256,
            SECURITY_POLICY_BASIC_256_SHA_256_URI => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", uri);
                SecurityPolicy::Unknown
            }
        }
    }

    pub fn from_str(str: &str) -> SecurityPolicy {
        match str {
            SECURITY_POLICY_NONE => SecurityPolicy::None,
            SECURITY_POLICY_BASIC_128_RSA_15 => SecurityPolicy::Basic128Rsa15,
            SECURITY_POLICY_BASIC_256 => SecurityPolicy::Basic256,
            SECURITY_POLICY_BASIC_256_SHA_256 => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", str);
                SecurityPolicy::Unknown
            }
        }
    }

    /// Pseudo random function is used as a key derivation algorithm. It creates pseudo random bytes
    /// from a secret and seed specified by the parameters.
    fn prf(&self, secret: &[u8], seed: &[u8], length: usize, offset: usize) -> Vec<u8> {
        // P_SHA1 or P_SHA256
        let message_digest = match self {
            &SecurityPolicy::Basic128Rsa15 | &SecurityPolicy::Basic256 => openssl_hash::MessageDigest::sha1(),
            &SecurityPolicy::Basic256Sha256 => openssl_hash::MessageDigest::sha256(),
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
    /// Byte[] PRF( Byte[] secret,  Byte[] seed,  Int32 length,  Int32 offset)
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
    pub fn make_secure_channel_keys(&self, nonce1: &[u8], nonce2: &[u8]) -> (Vec<u8>, AesKey, Vec<u8>) {
        // Work out the length of stuff
        let signing_key_length = self.derived_signature_key_size();
        let (encrypting_key_length, encrypting_block_size) = match self {
            &SecurityPolicy::Basic128Rsa15 => (16, 16),
            &SecurityPolicy::Basic256 => (32, 16),
            &SecurityPolicy::Basic256Sha256 => (32, 16),
            _ => {
                panic!("Invalid policy");
            }
        };

        let signing_key = self.prf(nonce1, nonce2, signing_key_length, 0);

        let encrypting_key = self.prf(nonce1, nonce2, encrypting_key_length, signing_key_length);
        let encrypting_key = AesKey::new(*self, &encrypting_key);

        let iv = self.prf(nonce1, nonce2, encrypting_block_size, signing_key_length + encrypting_key_length);

        (signing_key, encrypting_key, iv)
    }

    pub fn asymmetric_verify_signature(&self, verification_key: &PKey, data: &[u8], signature: &[u8]) -> Result<(), StatusCode> {
        // Asymmetric verify signature against supplied certificate
        let result = match self {
            &SecurityPolicy::Basic128Rsa15 | &SecurityPolicy::Basic256 => {
                verification_key.verify_sha1(data, signature)?
            }
            &SecurityPolicy::Basic256Sha256 => {
                verification_key.verify_sha256(data, signature)?
            }
            _ => {
                panic!("Invalid policy");
            }
        };
        debug!("Comparing signatures");
        if result {
            debug!("Signature matches");
            Ok(())
        } else {
            error!("Signature mismatch");
            Err(BAD_APPLICATION_SIGNATURE_INVALID)
        }
    }

    pub fn asymmetric_sign(&self, signing_key: &PKey, data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
        let result = match self {
            &SecurityPolicy::Basic128Rsa15 | &SecurityPolicy::Basic256 => {
                signing_key.sign_sha1(data)?
            }
            &SecurityPolicy::Basic256Sha256 => {
                signing_key.sign_sha256(data)?
            }
            _ => {
                panic!("Invalid policy");
            }
        };
        signature.copy_from_slice(&result[..]);
        Ok(())
    }

    /// Decrypts a message whose thumbprint matches the x509 cert and private key pair.
    ///
    /// Returns the number of decrypted bytes
    pub fn asymmetric_decrypt(&self, private_key: &PKey, src: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        // decrypt data using our private key
        let rsa = private_key.value.rsa().unwrap();
        let key_size = private_key.bit_length() / 8;

        let padding = match self {
            &SecurityPolicy::Basic128Rsa15 => PKCS1_PADDING,
            &SecurityPolicy::Basic256 | &SecurityPolicy::Basic256Sha256 => PKCS1_OAEP_PADDING,
            _ => {
                panic!("Security policy is not supported, shouldn't have gotten here");
            }
        };

        // Decrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;
        while src_idx < src.len() {
            let src = &src[src_idx..(src_idx + key_size)];
            let dst = &mut dst[dst_idx..(dst_idx + key_size)];
            let decrypted_bytes = rsa.private_decrypt(src, dst, padding);
            if decrypted_bytes.is_err() {
                return Err(BAD_DECODING_ERROR);
            }
            src_idx += key_size;
            dst_idx += decrypted_bytes.unwrap();
        }

        Ok(dst_idx)
    }

    /// Encrypts a message using the supplied encryption key, returns the encrypted size. Destination
    /// buffer must be large enough to hold encrypted bytes including padding.
    pub fn asymmetric_encrypt(&self, encryption_key: &PKey, src: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        let rsa = encryption_key.value.rsa().unwrap();
        let key_size = encryption_key.bit_length() / 8;

        let padding = match self {
            &SecurityPolicy::Basic128Rsa15 => PKCS1_PADDING,
            &SecurityPolicy::Basic256 | &SecurityPolicy::Basic256Sha256 => PKCS1_OAEP_PADDING,
            _ => {
                panic!("Security policy is not supported, shouldn't have gotten here");
            }
        };

        // Encrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;
        while src_idx < src.len() {
            let src = &src[src_idx..(src_idx + key_size)];
            let dst = &mut dst[dst_idx..(dst_idx + key_size)];
            let encrypted_bytes = rsa.public_encrypt(src, dst, padding);
            if encrypted_bytes.is_err() {
                return Err(BAD_ENCODING_ERROR);
            }
            src_idx += key_size;
            dst_idx += encrypted_bytes.unwrap();
        }

        Ok(dst_idx)
    }

    /// Sign the following block
    pub fn symmetric_sign(&self, key: &[u8], src: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
        debug!("Producing signature for {} bytes of data into signature of {} bytes", src.len(), signature.len());
        match self {
            &SecurityPolicy::Basic128Rsa15 => {
                // HMAC SHA-1
                hash::hmac_sha1(key, src, signature)
            }
            &SecurityPolicy::Basic256 | &SecurityPolicy::Basic256Sha256 => {
                // HMAC SHA-256                
                hash::hmac_sha256(key, src, signature)
            }
            _ => {
                panic!("Unsupported policy")
            }
        }
    }

    /// Verify their signature
    pub fn symmetric_verify_signature(&self, key: &[u8], src: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        // Verify the signature using SHA-1 / SHA-256 HMAC
        let verified = match self {
            &SecurityPolicy::Basic128Rsa15 => {
                // HMAC SHA-1
                hash::verify_hmac_sha1(key, src, signature)
            }
            &SecurityPolicy::Basic256 | &SecurityPolicy::Basic256Sha256 => {
                // HMAC SHA-256                
                hash::verify_hmac_sha256(key, src, signature)
            }
            _ => {
                panic!("Unsupported policy")
            }
        };
        if verified {
            Ok(verified)
        } else {
            error!("Signature invalid {:?}", signature);
            Err(BAD_APPLICATION_SIGNATURE_INVALID)
        }
    }

    /// Encrypt the data
    pub fn symmetric_encrypt(&self, key: &AesKey, iv: &[u8], src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        let result = key.encrypt(src, iv, dst);
        if result.is_ok() {
            Ok(())
        } else {
            error!("Cannot encrypt data, {}", result.unwrap_err());
            Err(BAD_ENCODING_ERROR)
        }
    }

    /// Decrypt the data
    pub fn symmetric_decrypt(&self, key: &AesKey, iv: &[u8], src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        let result = key.decrypt(src, iv, dst);
        if result.is_ok() {
            Ok(())
        } else {
            error!("Cannot decrypt data, {}", result.unwrap_err());
            Err(BAD_DECODING_ERROR)
        }
    }
}
