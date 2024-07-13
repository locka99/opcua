use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use crate::{crypto::SecurityPolicy, types::MessageSecurityMode};

use super::server::{ServerUserToken, ANONYMOUS_USER_TOKEN_ID};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ServerEndpoint {
    /// Endpoint path
    pub path: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// Security level, higher being more secure
    pub security_level: u8,
    /// Password security policy when a client supplies a user name identity token
    pub password_security_policy: Option<String>,
    /// User tokens
    pub user_token_ids: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Hash, Eq)]
pub struct EndpointIdentifier {
    /// Endpoint path
    pub path: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
}

impl From<&ServerEndpoint> for EndpointIdentifier {
    fn from(value: &ServerEndpoint) -> Self {
        Self {
            path: value.path.clone(),
            security_policy: value.security_policy.clone(),
            security_mode: value.security_mode.clone(),
        }
    }
}

/// Convenience method to make an endpoint from a tuple
impl<'a> From<(&'a str, SecurityPolicy, MessageSecurityMode, &'a [&'a str])> for ServerEndpoint {
    fn from(v: (&'a str, SecurityPolicy, MessageSecurityMode, &'a [&'a str])) -> ServerEndpoint {
        ServerEndpoint {
            path: v.0.into(),
            security_policy: v.1.to_string(),
            security_mode: v.2.to_string(),
            security_level: Self::security_level(v.1, v.2),
            password_security_policy: None,
            user_token_ids: v.3.iter().map(|id| id.to_string()).collect(),
        }
    }
}

impl ServerEndpoint {
    pub fn new<T>(
        path: T,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_token_ids: &[String],
    ) -> Self
    where
        T: Into<String>,
    {
        ServerEndpoint {
            path: path.into(),
            security_policy: security_policy.to_string(),
            security_mode: security_mode.to_string(),
            security_level: Self::security_level(security_policy, security_mode),
            password_security_policy: None,
            user_token_ids: user_token_ids.iter().cloned().collect(),
        }
    }

    /// Recommends a security level for the supplied security policy
    fn security_level(security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> u8 {
        let security_level = match security_policy {
            SecurityPolicy::Basic128Rsa15 => 1,
            SecurityPolicy::Aes128Sha256RsaOaep => 2,
            SecurityPolicy::Basic256 => 3,
            SecurityPolicy::Basic256Sha256 => 4,
            SecurityPolicy::Aes256Sha256RsaPss => 5,
            _ => 0,
        };
        if security_mode == MessageSecurityMode::SignAndEncrypt {
            security_level + 10
        } else {
            security_level
        }
    }

    pub fn new_none<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::None,
            MessageSecurityMode::None,
            user_token_ids,
        )
    }

    pub fn new_basic128rsa15_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_basic128rsa15_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_basic256_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_basic256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_basic256sha256_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_basic256sha256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_aes128_sha256_rsaoaep_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_aes128_sha256_rsaoaep_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn new_aes256_sha256_rsapss_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    pub fn new_aes256_sha256_rsapss_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    pub fn is_valid(&self, id: &str, user_tokens: &BTreeMap<String, ServerUserToken>) -> bool {
        let mut valid = true;

        // Validate that the user token ids exist
        for id in &self.user_token_ids {
            // Skip anonymous
            if id == ANONYMOUS_USER_TOKEN_ID {
                continue;
            }
            if !user_tokens.contains_key(id) {
                error!("Cannot find user token with id {}", id);
                valid = false;
            }
        }

        if let Some(ref password_security_policy) = self.password_security_policy {
            let password_security_policy =
                SecurityPolicy::from_str(password_security_policy).unwrap();
            if password_security_policy == SecurityPolicy::Unknown {
                error!("Endpoint {} is invalid. Password security policy \"{}\" is invalid. Valid values are None, Basic128Rsa15, Basic256, Basic256Sha256", id, password_security_policy);
                valid = false;
            }
        }

        // Validate the security policy and mode
        let security_policy = SecurityPolicy::from_str(&self.security_policy).unwrap();
        let security_mode = MessageSecurityMode::from(self.security_mode.as_ref());
        if security_policy == SecurityPolicy::Unknown {
            error!("Endpoint {} is invalid. Security policy \"{}\" is invalid. Valid values are None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss,", id, self.security_policy);
            valid = false;
        } else if security_mode == MessageSecurityMode::Invalid {
            error!("Endpoint {} is invalid. Security mode \"{}\" is invalid. Valid values are None, Sign, SignAndEncrypt", id, self.security_mode);
            valid = false;
        } else if (security_policy == SecurityPolicy::None
            && security_mode != MessageSecurityMode::None)
            || (security_policy != SecurityPolicy::None
                && security_mode == MessageSecurityMode::None)
        {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (1).", id);
            valid = false;
        } else if security_policy != SecurityPolicy::None
            && security_mode == MessageSecurityMode::None
        {
            error!("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should (2).", id);
            valid = false;
        }
        valid
    }

    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_str(&self.security_policy).unwrap()
    }

    pub fn message_security_mode(&self) -> MessageSecurityMode {
        MessageSecurityMode::from(self.security_mode.as_ref())
    }

    pub fn endpoint_url(&self, base_endpoint: &str) -> String {
        format!("{}{}", base_endpoint, self.path)
    }

    /// Returns the effective password security policy for the endpoint. This is the explicitly set password
    /// security policy, or just the regular security policy.
    pub fn password_security_policy(&self) -> SecurityPolicy {
        let mut password_security_policy = self.security_policy();
        if let Some(ref security_policy) = self.password_security_policy {
            match SecurityPolicy::from_str(security_policy).unwrap() {
                SecurityPolicy::Unknown => {
                    panic!(
                        "Password security policy {} is unrecognized",
                        security_policy
                    );
                }
                security_policy => {
                    password_security_policy = security_policy;
                }
            }
        }
        password_security_policy
    }

    /// Test if the endpoint supports anonymous users
    pub fn supports_anonymous(&self) -> bool {
        self.supports_user_token_id(ANONYMOUS_USER_TOKEN_ID)
    }

    /// Tests if this endpoint supports user pass tokens. It does this by looking to see
    /// if any of the users allowed to access this endpoint are user pass users.
    pub fn supports_user_pass(&self, server_tokens: &BTreeMap<String, ServerUserToken>) -> bool {
        for user_token_id in &self.user_token_ids {
            if user_token_id != ANONYMOUS_USER_TOKEN_ID {
                if let Some(user_token) = server_tokens.get(user_token_id) {
                    if user_token.is_user_pass() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Tests if this endpoint supports x509 tokens.  It does this by looking to see
    /// if any of the users allowed to access this endpoint are x509 users.
    pub fn supports_x509(&self, server_tokens: &BTreeMap<String, ServerUserToken>) -> bool {
        for user_token_id in &self.user_token_ids {
            if user_token_id != ANONYMOUS_USER_TOKEN_ID {
                if let Some(user_token) = server_tokens.get(user_token_id) {
                    if user_token.is_x509() {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn supports_user_token_id(&self, id: &str) -> bool {
        self.user_token_ids.contains(id)
    }
}
