use std::sync::Arc;

use crate::{
    async_server::{
        authenticator::{AuthManager, UserToken},
        session::instance::Session,
    },
    sync::RwLock,
};

pub struct RequestContext {
    pub session: Arc<RwLock<Session>>,
    pub authenticator: Arc<dyn AuthManager>,
    pub token: UserToken,
}
