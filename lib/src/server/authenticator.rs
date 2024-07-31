use async_trait::async_trait;

use crate::{
    crypto::Thumbprint,
    types::{MessageSecurityMode, NodeId, StatusCode},
};

use super::{
    address_space::UserAccessLevel, config::ANONYMOUS_USER_TOKEN_ID, ServerEndpoint,
    ServerUserToken,
};
use std::{collections::BTreeMap, fmt::Debug};

/// Debug-safe wrapper around a password.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"****").finish()
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

/// A unique identifier for a _user_. Distinct from a client/session, a user can
/// have multiple sessions at the same time, and is typically the value we use to
/// control access.
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

impl UserToken {
    pub fn is_anonymous(&self) -> bool {
        self.0 == ANONYMOUS_USER_TOKEN_ID
    }
}

#[allow(unused)]
#[async_trait]
/// The AuthManager trait is used to let servers control access to the server.
/// It serves two main purposes:
///
/// - It validates user credentials and returns a user token. Two clients with the
///   same user token are considered the _same_ user, and have some ability to interfere
///   with each other.
/// - It uses user tokens to check access levels.
///
/// Note that the only async methods are the ones validating access tokens. This means
/// that these methods should load and store any information you need to check user
/// access level down the line.
///
/// This is currently the only way to restrict access to core resources. For resources in
/// your own custom node managers you are free to use whatever access regime you want.
pub trait AuthManager: Send + Sync + 'static {
    /// Validate whether an anonymous user is allowed to access the given endpoint.
    /// This does not return a user token, all anonymous users share the same special token.
    async fn authenticate_anonymous_token(
        &self,
        endpoint: &ServerEndpoint,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    /// Validate the given username and password for `endpoint`.
    /// This should return a user token associated with the user, for example the username itself.
    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        username: &str,
        password: &Password,
    ) -> Result<UserToken, StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    /// Validate the signing thumbprint for `endpoint`.
    /// This should return a user token associated with the user.
    async fn authenticate_x509_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        signing_thumbprint: &Thumbprint,
    ) -> Result<UserToken, StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    /// Return the effective user access level for the given node ID
    fn effective_user_access_level(
        &self,
        token: &UserToken,
        user_access_level: UserAccessLevel,
        node_id: &NodeId,
    ) -> UserAccessLevel {
        user_access_level
    }

    fn is_user_executable(&self, token: &UserToken, method_id: &NodeId) -> bool {
        true
    }
}

/// A simple authenticator that keeps a map of valid users in memory.
/// In production applications you will almost always want to create your own
/// custom authenticator.
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
    ) -> Result<(), StatusCode> {
        if !endpoint.supports_anonymous() {
            error!(
                "Endpoint \"{}\" does not support anonymous authentication",
                endpoint.path
            );
            return Err(StatusCode::BadIdentityTokenRejected);
        }
        Ok(())
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
        endpoint: &ServerEndpoint,
        signing_thumbprint: &Thumbprint,
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
