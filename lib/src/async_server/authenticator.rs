use async_trait::async_trait;

use crate::server::prelude::{
    AttributeId, MessageSecurityMode, NodeId, StatusCode, Thumbprint, UserAccessLevel,
};

use super::{config::ANONYMOUS_USER_TOKEN_ID, ServerEndpoint, ServerUserToken};
use std::{collections::BTreeMap, fmt::Debug};

pub struct Password(String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserToken(pub String);

/// Key used to identify a user.
/// Goes beyond just the identity token, since some services require
/// information about the application URI and security mode as well.
#[derive(Debug, Clone)]
pub struct UserSecurityKey {
    pub token: UserToken,
    pub security_mode: MessageSecurityMode,
    pub application_uri: String,
}

impl Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"****").finish()
    }
}

impl UserToken {
    pub fn is_anonymous(&self) -> bool {
        self.0 == ANONYMOUS_USER_TOKEN_ID
    }
}

impl Password {
    pub fn new(password: String) -> Self {
        Self(password)
    }

    pub fn get(&self) -> &str {
        &self.0
    }
}

#[allow(unused)]
#[async_trait]
pub trait AuthManager: Send + Sync + 'static {
    async fn authenticate_anonymous_token(
        &self,
        endpoint: &ServerEndpoint,
    ) -> Result<UserToken, StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        username: &str,
        password: &Password,
    ) -> Result<UserToken, StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    async fn authenticate_x509_identity_token(
        &self,
        signing_thumbprint: &Thumbprint,
        endpoint: &ServerEndpoint,
    ) -> Result<UserToken, StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    fn effective_user_access_level(
        &self,
        token: &UserToken,
        user_access_level: UserAccessLevel,
        node_id: &NodeId,
        attribute_id: AttributeId,
    ) -> UserAccessLevel {
        user_access_level
    }

    fn is_user_executable(&self, token: &UserToken, method_id: &NodeId) -> bool {
        true
    }
}

pub struct DefaultAuthenticator {
    users: BTreeMap<String, ServerUserToken>,
}

impl DefaultAuthenticator {
    pub fn new(users: BTreeMap<String, ServerUserToken>) -> Self {
        Self { users }
    }
}

#[async_trait]
impl AuthManager for DefaultAuthenticator {
    async fn authenticate_anonymous_token(
        &self,
        endpoint: &ServerEndpoint,
    ) -> Result<UserToken, StatusCode> {
        if !endpoint.supports_anonymous() {
            error!(
                "Endpoint \"{}\" does not support anonymous authentication",
                endpoint.path
            );
            return Err(StatusCode::BadIdentityTokenRejected);
        }
        Ok(UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()))
    }

    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        username: &str,
        password: &Password,
    ) -> Result<UserToken, StatusCode> {
        let token_password = password.get();
        for user_token_id in &endpoint.user_token_ids {
            if let Some(server_user_token) = self.users.get(user_token_id) {
                if server_user_token.is_user_pass() && server_user_token.user == username.as_ref() {
                    // test for empty password
                    let valid = if server_user_token.pass.is_none() {
                        // Empty password for user
                        token_password.is_empty()
                    } else {
                        // Password compared as UTF-8 bytes
                        let server_password = server_user_token.pass.as_ref().unwrap().as_bytes();
                        server_password == token_password.as_bytes()
                    };
                    if !valid {
                        error!(
                            "Cannot authenticate \"{}\", password is invalid",
                            server_user_token.user
                        );
                        return Err(StatusCode::BadUserAccessDenied);
                    } else {
                        return Ok(UserToken(user_token_id.clone()));
                    }
                }
            }
        }
        error!(
            "Cannot authenticate \"{}\", user not found for endpoint",
            username
        );
        Err(StatusCode::BadUserAccessDenied)
    }

    async fn authenticate_x509_identity_token(
        &self,
        signing_thumbprint: &Thumbprint,
        endpoint: &ServerEndpoint,
    ) -> Result<UserToken, StatusCode> {
        // Check the endpoint to see if this token is supported
        for user_token_id in &endpoint.user_token_ids {
            if let Some(server_user_token) = self.users.get(user_token_id) {
                if let Some(ref user_thumbprint) = server_user_token.thumbprint {
                    // The signing cert matches a user's identity, so it is valid
                    if user_thumbprint == signing_thumbprint {
                        return Ok(UserToken(user_token_id.clone()));
                    }
                }
            }
        }
        Err(StatusCode::BadIdentityTokenInvalid)
    }
}
