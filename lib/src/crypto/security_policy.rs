// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Security policy is the symmetric, asymmetric encryption / decryption + signing / verification
//! algorithms to use and enforce for the current session.
use std::fmt;
use std::str::FromStr;

use openssl::hash as openssl_hash;

use crate::types::{constants, status_code::StatusCode, ByteString};

use super::{
    aeskey::AesKey,
    hash,
    pkey::{KeySize, PrivateKey, PublicKey, RsaPadding},
    random, SHA1_SIZE, SHA256_SIZE,
};

// These are constants that govern the different encryption / signing modes for OPC UA. In some
// cases these algorithm string constants will be passed over the wire and code needs to test the
// string to see if the algorithm is supported.

/// Aes128-Sha256-RsaOaep security policy
///
///   AsymmetricEncryptionAlgorithm_RSA-PKCS15-SHA2-256
///   AsymmetricSignatureAlgorithm_RSA-OAEP-SHA1
///   CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
///   KeyDerivationAlgorithm_P-SHA2-256
///   SymmetricEncryptionAlgorithm_AES128-CBC
///   SymmetricSignatureAlgorithm_HMAC-SHA2-256
///
/// # Limits
///
///   DerivedSignatureKeyLength – 256 bits
///   AsymmetricKeyLength - 2048-4096 bits
///   SecureChannelNonceLength - 32 bytes
mod aes_128_sha_256_rsa_oaep {
    use crate::crypto::algorithms::*;

    pub const SECURITY_POLICY: &str = "Aes128-Sha256-RsaOaep";
    pub const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";

    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA256;
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA256;
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_15;
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;
    pub const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);
}

/// Aes256-Sha256-RsaPss security policy
///
///   AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA2-256
///   AsymmetricSignatureAlgorithm_RSA-PSS -SHA2-256
///   CertificateSignatureAlgorithm_ RSA-PKCS15-SHA2-256
///   KeyDerivationAlgorithm_P-SHA2-256
///   SymmetricEncryptionAlgorithm_AES256-CBC
///   SymmetricSignatureAlgorithm_HMAC-SHA2-256
///
/// # Limits
///
///   DerivedSignatureKeyLength – 256 bits
///   AsymmetricKeyLength - 2048-4096 bits
///   SecureChannelNonceLength - 32 bytes
mod aes_256_sha_256_rsa_pss {
    use crate::crypto::algorithms::*;

    pub const SECURITY_POLICY: &str = "Aes256-Sha256-RsaPss";
    pub const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA256;
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_PSS_SHA2_256;
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_OAEP;
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;
    pub const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);
}

/// Basic256Sha256 security policy
///
///   AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA1
///   AsymmetricSignatureAlgorithm_RSA-PKCS15-SHA2-256
///   CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
///   KeyDerivationAlgorithm_P-SHA2-256
///   SymmetricEncryptionAlgorithm_AES256-CBC
///   SymmetricSignatureAlgorithm_HMAC-SHA2-256
///
/// # Limits
///
///   DerivedSignatureKeyLength – 256 bits
///   AsymmetricKeyLength - 2048-4096 bits
///   SecureChannelNonceLength - 32 bytes
mod basic_256_sha_256 {
    use crate::crypto::algorithms::*;

    pub const SECURITY_POLICY: &str = "Basic256Sha256";
    pub const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA256;
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA256;
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_OAEP;
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;
    pub const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);
}

/// Basic128Rsa15 security policy (deprecated in OPC UA 1.04)
///
///   AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
///   AsymmetricEncryptionAlgorithm – Rsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
///   SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
///   SymmetricEncryptionAlgorithm – Aes128 – (http://www.w3.org/2001/04/xmlenc#aes128-cbc).
///   KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
///
/// # Limits
///
///   DerivedSignatureKeyLength – 128 bits
///   AsymmetricKeyLength - 1024-2048 bits
///   SecureChannelNonceLength - 16 bytes
mod basic_128_rsa_15 {
    use crate::crypto::algorithms::*;

    pub const SECURITY_POLICY: &str = "Basic128Rsa15";
    pub const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";

    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA1;
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA1;
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_15;
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 128;
    pub const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (1024, 2048);
}

/// Basic256 security policy (deprecated in OPC UA 1.04)
///
///   AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
///   AsymmetricEncryptionAlgorithm – RsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
///   SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
///   SymmetricEncryptionAlgorithm – Aes256 – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
///   KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
///
/// # Limits
///
///   DerivedSignatureKeyLength – 192 bits
///   AsymmetricKeyLength - 1024-2048 bits
///   SecureChannelNonceLength - 32 bytes
mod basic_256 {
    use crate::crypto::algorithms::*;

    pub const SECURITY_POLICY: &str = "Basic256";
    pub const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";

    pub const SYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_HMAC_SHA1;
    pub const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = DSIG_RSA_SHA1;
    pub const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = ENC_RSA_OAEP;
    pub const DERIVED_SIGNATURE_KEY_LENGTH: usize = 192;
    pub const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (1024, 2048);
}

/// SecurityPolicy implies what encryption and signing algorithms and their relevant key strengths
/// are used during an encrypted session.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum SecurityPolicy {
    Unknown,
    None,
    Aes128Sha256RsaOaep,
    Basic256Sha256,
    Aes256Sha256RsaPss,
    Basic128Rsa15,
    Basic256,
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
            constants::SECURITY_POLICY_NONE | constants::SECURITY_POLICY_NONE_URI => {
                SecurityPolicy::None
            }
            basic_128_rsa_15::SECURITY_POLICY | basic_128_rsa_15::SECURITY_POLICY_URI => {
                SecurityPolicy::Basic128Rsa15
            }
            basic_256::SECURITY_POLICY | basic_256::SECURITY_POLICY_URI => SecurityPolicy::Basic256,
            basic_256_sha_256::SECURITY_POLICY | basic_256_sha_256::SECURITY_POLICY_URI => {
                SecurityPolicy::Basic256Sha256
            }
            aes_128_sha_256_rsa_oaep::SECURITY_POLICY
            | aes_128_sha_256_rsa_oaep::SECURITY_POLICY_URI => SecurityPolicy::Aes128Sha256RsaOaep,
            aes_256_sha_256_rsa_pss::SECURITY_POLICY
            | aes_256_sha_256_rsa_pss::SECURITY_POLICY_URI => SecurityPolicy::Aes256Sha256RsaPss,
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
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::SECURITY_POLICY_URI,
            SecurityPolicy::Basic256 => basic_256::SECURITY_POLICY_URI,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::SECURITY_POLICY_URI,
            SecurityPolicy::Aes128Sha256RsaOaep => aes_128_sha_256_rsa_oaep::SECURITY_POLICY_URI,
            SecurityPolicy::Aes256Sha256RsaPss => aes_256_sha_256_rsa_pss::SECURITY_POLICY_URI,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    /// Returns true if the security policy is supported. It might be recognized but be unsupported by the implementation
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            SecurityPolicy::None
                | SecurityPolicy::Basic128Rsa15
                | SecurityPolicy::Basic256
                | SecurityPolicy::Basic256Sha256
                | SecurityPolicy::Aes128Sha256RsaOaep
                | SecurityPolicy::Aes256Sha256RsaPss
        )
    }

    /// Returns true if the security policy has been deprecated by the OPC UA specification
    pub fn is_deprecated(&self) -> bool {
        // Since 1.04 because SHA-1 is no longer considered safe
        matches!(
            self,
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256
        )
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            SecurityPolicy::None => constants::SECURITY_POLICY_NONE,
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::SECURITY_POLICY,
            SecurityPolicy::Basic256 => basic_256::SECURITY_POLICY,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::SECURITY_POLICY,
            SecurityPolicy::Aes128Sha256RsaOaep => aes_128_sha_256_rsa_oaep::SECURITY_POLICY,
            SecurityPolicy::Aes256Sha256RsaPss => aes_256_sha_256_rsa_pss::SECURITY_POLICY,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a string");
            }
        }
    }

    pub fn asymmetric_encryption_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Basic256 => basic_256::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                aes_128_sha_256_rsa_oaep::ASYMMETRIC_ENCRYPTION_ALGORITHM
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                aes_256_sha_256_rsa_pss::ASYMMETRIC_ENCRYPTION_ALGORITHM
            }
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256 => basic_256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                aes_128_sha_256_rsa_oaep::ASYMMETRIC_SIGNATURE_ALGORITHM
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                aes_256_sha_256_rsa_pss::ASYMMETRIC_SIGNATURE_ALGORITHM
            }
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn symmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256 => basic_256::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                aes_128_sha_256_rsa_oaep::SYMMETRIC_SIGNATURE_ALGORITHM
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                aes_256_sha_256_rsa_pss::SYMMETRIC_SIGNATURE_ALGORITHM
            }
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Plaintext block size in bytes
    pub fn plain_block_size(&self) -> usize {
        match self {
            SecurityPolicy::Basic128Rsa15
            | SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => 16,
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
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => SHA256_SIZE,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the derived signature key (not the signature) size in bytes
    pub fn derived_signature_key_size(&self) -> usize {
        let length = match self {
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Basic256 => basic_256::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                aes_128_sha_256_rsa_oaep::DERIVED_SIGNATURE_KEY_LENGTH
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                aes_256_sha_256_rsa_pss::DERIVED_SIGNATURE_KEY_LENGTH
            }
            _ => {
                panic!("Invalid policy");
            }
        };
        length / 8
    }

    /// Returns the min and max (inclusive) key length in bits
    pub fn min_max_asymmetric_keylength(&self) -> (usize, usize) {
        match self {
            SecurityPolicy::Basic128Rsa15 => basic_128_rsa_15::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256 => basic_256::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => basic_256_sha_256::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Aes128Sha256RsaOaep => aes_128_sha_256_rsa_oaep::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Aes256Sha256RsaPss => aes_256_sha_256_rsa_pss::ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Tests if the supplied key length is valid for this policy
    pub fn is_valid_keylength(&self, keylength: usize) -> bool {
        let min_max = self.min_max_asymmetric_keylength();
        keylength >= min_max.0 && keylength <= min_max.1
    }

    /// Creates a random nonce in a bytestring with a length appropriate for the policy
    pub fn random_nonce(&self) -> ByteString {
        match self {
            SecurityPolicy::None => ByteString::null(),
            _ => random::byte_string(self.secure_channel_nonce_length()),
        }
    }

    pub fn secure_channel_nonce_length(&self) -> usize {
        match self {
            SecurityPolicy::Basic128Rsa15 => 16,
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => 32,
            // The nonce can be used for password or X509 authentication
            // even when the security policy is None.
            // see https://github.com/advisories/GHSA-pq4w-qm9g-qx68
            SecurityPolicy::None | SecurityPolicy::Unknown => 32,
        }
    }

    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            constants::SECURITY_POLICY_NONE_URI => SecurityPolicy::None,
            basic_128_rsa_15::SECURITY_POLICY_URI => SecurityPolicy::Basic128Rsa15,
            basic_256::SECURITY_POLICY_URI => SecurityPolicy::Basic256,
            basic_256_sha_256::SECURITY_POLICY_URI => SecurityPolicy::Basic256Sha256,
            aes_128_sha_256_rsa_oaep::SECURITY_POLICY_URI => SecurityPolicy::Aes128Sha256RsaOaep,
            aes_256_sha_256_rsa_pss::SECURITY_POLICY_URI => SecurityPolicy::Aes256Sha256RsaPss,
            _ => {
                error!(
                    "Specified security policy uri \"{}\" is not recognized",
                    uri
                );
                SecurityPolicy::Unknown
            }
        }
    }

    /// Pseudo random function is used as a key derivation algorithm. It creates pseudo random bytes
    /// from a secret and seed specified by the parameters.
    fn prf(&self, secret: &[u8], seed: &[u8], length: usize, offset: usize) -> Vec<u8> {
        // P_SHA1 or P_SHA256
        let message_digest = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                openssl_hash::MessageDigest::sha1()
            }
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => openssl_hash::MessageDigest::sha256(),
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
    /// keys derived from the Nonces exchanged in the OpenSecureChannel call. These keys are derived
    /// by passing the Nonces to a pseudo-random function which produces a sequence of bytes from a
    /// set of inputs. A pseudo-random function is represented by the following function declaration:
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
    pub fn make_secure_channel_keys(
        &self,
        secret: &[u8],
        seed: &[u8],
    ) -> (Vec<u8>, AesKey, Vec<u8>) {
        // Work out the length of stuff
        let signing_key_length = self.derived_signature_key_size();
        let (encrypting_key_length, encrypting_block_size) = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Aes128Sha256RsaOaep => (16, 16),
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => (32, 16),
            _ => {
                panic!("Invalid policy");
            }
        };

        let signing_key = self.prf(secret, seed, signing_key_length, 0);
        let encrypting_key = self.prf(secret, seed, encrypting_key_length, signing_key_length);
        let encrypting_key = AesKey::new(*self, &encrypting_key);
        let iv = self.prf(
            secret,
            seed,
            encrypting_block_size,
            signing_key_length + encrypting_key_length,
        );

        (signing_key, encrypting_key, iv)
    }

    /// Produce a signature of the data using an asymmetric key. Stores the signature in the supplied
    /// `signature` buffer. Returns the size of the signature within that buffer.
    pub fn asymmetric_sign(
        &self,
        signing_key: &PrivateKey,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                signing_key.sign_sha1(data, signature)?
            }
            SecurityPolicy::Basic256Sha256 | SecurityPolicy::Aes128Sha256RsaOaep => {
                signing_key.sign_sha256(data, signature)?
            }
            SecurityPolicy::Aes256Sha256RsaPss => signing_key.sign_sha256_pss(data, signature)?,
            _ => {
                panic!("Invalid policy");
            }
        };
        Ok(result)
    }

    /// Verifies a signature of the data using an asymmetric key. In a debugging scenario, the
    /// signing key can also be supplied so that the supplied signature can be compared to a freshly
    /// generated signature.
    pub fn asymmetric_verify_signature(
        &self,
        verification_key: &PublicKey,
        data: &[u8],
        signature: &[u8],
        their_private_key: Option<PrivateKey>,
    ) -> Result<(), StatusCode> {
        // Asymmetric verify signature against supplied certificate
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                verification_key.verify_sha1(data, signature)?
            }
            SecurityPolicy::Basic256Sha256 | SecurityPolicy::Aes128Sha256RsaOaep => {
                verification_key.verify_sha256(data, signature)?
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                verification_key.verify_sha256_pss(data, signature)?
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
                trace!(
                    "Using their_key, signature should be {:?}",
                    &their_signature
                );
            }
            Err(StatusCode::BadSecurityChecksFailed)
        }
    }

    /// Returns the padding algorithm used for this security policy for asymettric encryption
    /// and decryption.
    pub fn asymmetric_encryption_padding(&self) -> RsaPadding {
        match self {
            SecurityPolicy::Basic128Rsa15 => RsaPadding::Pkcs1,
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep => RsaPadding::OaepSha1,
            // PSS uses OAEP-SHA256 for encryption, but PSS for signing
            SecurityPolicy::Aes256Sha256RsaPss => RsaPadding::OaepSha256,
            _ => {
                panic!("Security policy is not supported, shouldn't have gotten here");
            }
        }
    }

    /// Encrypts a message using the supplied encryption key, returns the encrypted size. Destination
    /// buffer must be large enough to hold encrypted bytes including any padding.
    pub fn asymmetric_encrypt(
        &self,
        encryption_key: &PublicKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let padding = self.asymmetric_encryption_padding();
        encryption_key
            .public_encrypt(src, dst, padding)
            .map_err(|_| StatusCode::BadUnexpectedError)
    }

    /// Decrypts a message whose thumbprint matches the x509 cert and private key pair.
    ///
    /// Returns the number of decrypted bytes
    pub fn asymmetric_decrypt(
        &self,
        decryption_key: &PrivateKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let padding = self.asymmetric_encryption_padding();
        decryption_key
            .private_decrypt(src, dst, padding)
            .map_err(|_| {
                error!("Asymmetric decryption failed");
                StatusCode::BadSecurityChecksFailed
            })
    }

    /// Produce a signature of some data using the supplied symmetric key. Signing algorithm is determined
    /// by the security policy. Signature is stored in the supplied `signature` argument.
    pub fn symmetric_sign(
        &self,
        key: &[u8],
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), StatusCode> {
        trace!(
            "Producing signature for {} bytes of data into signature of {} bytes",
            data.len(),
            signature.len()
        );
        match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                hash::hmac_sha1(key, data, signature)
            }
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => hash::hmac_sha256(key, data, signature),
            _ => {
                panic!("Unsupported policy")
            }
        }
    }

    /// Verify the signature of a data block using the supplied symmetric key.
    pub fn symmetric_verify_signature(
        &self,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, StatusCode> {
        // Verify the signature using SHA-1 / SHA-256 HMAC
        let verified = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                hash::verify_hmac_sha1(key, data, signature)
            }
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => hash::verify_hmac_sha256(key, data, signature),
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
    pub fn symmetric_encrypt(
        &self,
        key: &AesKey,
        iv: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        key.encrypt(src, iv, dst)
    }

    /// Decrypts the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_decrypt(
        &self,
        key: &AesKey,
        iv: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        key.decrypt(src, iv, dst)
    }
}
