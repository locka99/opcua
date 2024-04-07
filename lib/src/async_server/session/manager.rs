use std::{
    collections::HashMap,
    sync::atomic::{AtomicI32, Ordering},
};

use crate::server::prelude::NodeId;

use super::instance::Session;

lazy_static! {
    static ref NEXT_SESSION_ID: AtomicI32 = AtomicI32::new(1);
}

fn next_session_id() -> NodeId {
    // Session id will be a string identifier
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let session_id = format!("Session-{}", session_id);
    NodeId::new(1, session_id)
}

/// Manages sessions for a single connection.
#[derive(Default)]
pub struct SessionManager {
    sessions: HashMap<NodeId, Session>,
}

impl SessionManager {
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_mut(&mut self, session_id: &NodeId) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    pub fn find_by_token_mut(&mut self, authentication_token: &NodeId) -> Option<&mut Session> {
        self.sessions
            .iter_mut()
            .find(|(_, s)| &s.authentication_token == authentication_token)
            .map(|p| p.1)
    }
}
