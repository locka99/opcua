use types::*;
use profiles::*;

#[cfg(not(feature = "crypto"))]
type Cert = u32;

#[derive(Debug, Clone)]
pub struct SecureChannelInfo {
    pub security_policy: SecurityPolicy,
    pub secure_channel_id: UInt32,
    pub token_id: UInt32,
    pub nonce: [u8; 32],
    pub their_nonce: [u8; 32],

    pub their_cert: Cert,
}

impl SecureChannelInfo {
    pub fn new() -> SecureChannelInfo {
        SecureChannelInfo {
            security_policy: SecurityPolicy::None,
            secure_channel_id: 0,
            token_id: 0,
            nonce: [0; 32],
            their_nonce: [0; 32],
            their_cert: 0
        }
    }

    pub fn create_random_nonce(&mut self) {
        use rand::{self, Rng};
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut self.nonce);
    }

    pub fn nonce_as_byte_string(&self) -> ByteString {
        ByteString::from_bytes(&self.nonce)
    }

    pub fn set_their_nonce(&mut self, their_nonce: &ByteString) -> Result<(), ()> {
        if their_nonce.value.is_some() && their_nonce.value.as_ref().unwrap().len() == self.their_nonce.len() {
            self.their_nonce[..].clone_from_slice(their_nonce.value.as_ref().unwrap());
            Ok(())
        }
        else {
            Err(())
        }
    }
}



#[derive(Debug, Clone, PartialEq)]
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
            &SecurityPolicy::None => SECURITY_POLICY_NONE,
            &SecurityPolicy::Basic128Rsa15 => SECURITY_POLICY_BASIC128RSA15,
            &SecurityPolicy::Basic256 => SECURITY_POLICY_BASIC256,
            &SecurityPolicy::Basic256Sha256 => SECURITY_POLICY_BASIC256SHA256,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    pub fn from_str(str: &str) -> SecurityPolicy {
        match str {
            "None" => SecurityPolicy::None,
            "Basic128Rsa15" => SecurityPolicy::Basic128Rsa15,
            "Basic256" => SecurityPolicy::Basic256,
            "Basic256Sha256" => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", str);
                SecurityPolicy::Unknown
            }
        }
    }

    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            SECURITY_POLICY_NONE => SecurityPolicy::None,
            SECURITY_POLICY_BASIC128RSA15 => SecurityPolicy::Basic128Rsa15,
            SECURITY_POLICY_BASIC256 => SecurityPolicy::Basic256,
            SECURITY_POLICY_BASIC256SHA256 => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", uri);
                SecurityPolicy::Unknown
            }
        }
    }
}
