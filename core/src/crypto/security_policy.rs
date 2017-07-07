use opcua_types::*;
use opcua_types::profiles;
use opcua_types::constants;

use crypto;

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
    pub fn signature_size(&self) -> usize {
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
}
