use opcua_types::*;
use opcua_types::profiles;
use opcua_types::constants;

use crypto;
use crypto::types::AesKey;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityPolicy {
    Unknown,
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
}

impl SecurityPolicy {
    pub fn to_string(&self) -> UAString {
        UAString::from_str(self.to_uri())
    }

    pub fn to_uri(&self) -> &'static str {
        match self {
            &SecurityPolicy::None => profiles::SECURITY_POLICY_NONE,
            &SecurityPolicy::Basic128Rsa15 => profiles::SECURITY_POLICY_BASIC_128_RSA_15,
            &SecurityPolicy::Basic256 => profiles::SECURITY_POLICY_BASIC_256,
            &SecurityPolicy::Basic256Sha256 => profiles::SECURITY_POLICY_BASIC_256_SHA_256,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::ASYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn symmetric_signature_algorithm(&self) -> &'static str {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::SYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::SYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::SYMMETRIC_SIGNATURE_ALGORITHM,
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

    /// Returns the signature size in bytes
    pub fn derived_signature_size(&self) -> usize {
        let result = match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::DERIVED_SIGNATURE_KEY_LENGTH,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::DERIVED_SIGNATURE_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::DERIVED_SIGNATURE_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        };
        result / 8
    }

    /// Returns the max key length in bits
    pub fn min_asymmetric_key_length(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::MIN_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::MIN_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::MIN_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the max key length in bits
    pub fn max_asymmetric_key_length(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::MAX_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::MAX_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::MAX_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            profiles::SECURITY_POLICY_NONE => SecurityPolicy::None,
            profiles::SECURITY_POLICY_BASIC_128_RSA_15 => SecurityPolicy::Basic128Rsa15,
            profiles::SECURITY_POLICY_BASIC_256 => SecurityPolicy::Basic256,
            profiles::SECURITY_POLICY_BASIC_256_SHA_256 => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", uri);
                SecurityPolicy::Unknown
            }
        }
    }

    pub fn from_str(str: &str) -> SecurityPolicy {
        match str {
            constants::SECURITY_POLICY_NONE => SecurityPolicy::None,
            constants::SECURITY_POLICY_BASIC_128_RSA_15 => SecurityPolicy::Basic128Rsa15,
            constants::SECURITY_POLICY_BASIC_256 => SecurityPolicy::Basic256,
            constants::SECURITY_POLICY_BASIC_256_SHA_256 => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", str);
                SecurityPolicy::Unknown
            }
        }
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
    pub fn make_secure_channel_keys(&self, nonce1: &[u8], nonce2: &[u8]) -> (AesKey, AesKey, Vec<u8>) {
        // Work out the length of stuff
        let signing_key_length = self.derived_signature_size();
        let (encrypting_key_length, encrypting_block_size) = match self {
            &SecurityPolicy::Basic128Rsa15 => (16, 16),
            &SecurityPolicy::Basic256 => (24, 16),
            &SecurityPolicy::Basic256Sha256 => (32, 16),
            _ => {
                panic!("Invalid policy");
            }
        };

        let mut buffer = Vec::with_capacity(nonce1.len() + nonce2.len());
        buffer.extend_from_slice(nonce1);
        buffer.extend_from_slice(nonce2);
        // Pseudo random function just returns a slice of data
        fn prf(data: &[u8], length: usize, offset: usize) -> &[u8] {
            &data[offset..(offset + length)]
        }

        let signing_key = prf(&buffer, signing_key_length, 0);
        let signing_key = AesKey::new(*self, signing_key);

        let encrypting_key = prf(&buffer, encrypting_key_length, signing_key_length);
        let encrypting_key = AesKey::new(*self, encrypting_key);

        let iv = prf(&buffer, encrypting_block_size, signing_key_length + encrypting_key_length).to_vec();

        (signing_key, encrypting_key, iv)
    }
}
