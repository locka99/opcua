// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::collections::{HashMap, HashSet};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use opcua_core::supported_message::SupportedMessage;

pub(crate) struct MessageQueue {
    /// The requests that are in-flight, defined by their request handle and an async flag. Basically,
    /// the sent requests reside here until the response returns at which point the entry is removed.
    /// If a response is received for which there is no entry, the response will be discarded.
    inflight_requests: HashSet<(u32, bool)>,
    /// A map of incoming responses waiting to be processed
    responses: HashMap<u32, (SupportedMessage, bool)>,
    /// This is the queue that messages will be sent onto the transport for sending
    sender: Option<UnboundedSender<Message>>,
}

pub enum Message {
    Quit,
    SupportedMessage(SupportedMessage),
}

impl MessageQueue {
    pub fn new() -> MessageQueue {
        MessageQueue {
            inflight_requests: HashSet::new(),
            responses: HashMap::new(),
            sender: None,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.inflight_requests.clear();
        self.responses.clear();
    }

    // Creates the transmission queue that outgoing requests will be sent over
    pub(crate) fn make_request_channel(
        &mut self,
    ) -> (UnboundedSender<Message>, UnboundedReceiver<Message>) {
        let (tx, rx) = mpsc::unbounded_channel();
        self.sender = Some(tx.clone());
        (tx, rx)
    }

    pub(crate) fn request_was_processed(&mut self, request_handle: u32) {
        debug!("Request {} was processed by the server", request_handle);
    }

    fn send_message(&mut self, message: Message) {
        if let Err(err) = self.sender.as_ref().unwrap().send(message) {
            debug!("Cannot send message to message receiver, error {}", err);
        }
    }

    /// Called by the session to add a request to be sent
    pub(crate) fn add_request(&mut self, request: SupportedMessage, is_async: bool) {
        let request_handle = request.request_handle();
        trace!("Sending request {:?} to be sent", request);
        self.inflight_requests.insert((request_handle, is_async));
        self.send_message(Message::SupportedMessage(request));
    }

    pub(crate) fn quit(&mut self) {
        debug!("Sending a quit to the message receiver");
        self.send_message(Message::Quit);
    }

    /// Called when a session's request times out. This call allows the session state to remove
    /// the request as pending and ignore any response that arrives for it.
    pub(crate) fn request_has_timed_out(&mut self, request_handle: u32) {
        info!(
            "Request {} has timed out and any response will be ignored",
            request_handle
        );
        let _ = self.inflight_requests.remove(&(request_handle, false));
        let _ = self.inflight_requests.remove(&(request_handle, true));
    }

    /// Called by the connection to store a response for the consumption of the session.
    pub(crate) fn store_response(&mut self, response: SupportedMessage) {
        // Remove corresponding request handle from inflight queue, add to responses
        let request_handle = response.request_handle();
        trace!("Received response {:?}", response);
        debug!("Response to Request {} has been stored", request_handle);
        // Remove the inflight request
        // This true / false is slightly clunky.
        if let Some(request) = self.inflight_requests.take(&(request_handle, true)) {
            self.responses.insert(request_handle, (response, request.1));
        } else if let Some(request) = self.inflight_requests.take(&(request_handle, false)) {
            self.responses.insert(request_handle, (response, request.1));
        } else {
            error!("A response with request handle {} doesn't belong to any request and will be ignored, inflight requests = {:?}, request = {:?}", request_handle, self.inflight_requests, response);
            if let SupportedMessage::ServiceFault(response) = response {
                error!(
                    "Unhandled response is a service fault, service result = {}",
                    response.response_header.service_result
                )
            }
        }
    }

    /// Takes all pending asynchronous responses into a vector sorted oldest to latest and
    /// returns them to the caller.
    pub(crate) fn async_responses(&mut self) -> Vec<SupportedMessage> {
        // Gather up all request handles
        let mut async_handles = self
            .responses
            .iter()
            .filter(|(_, v)| v.1)
            .map(|(k, _)| *k)
            .collect::<Vec<_>>();

        // Order them from oldest to latest (except if handles wrap)
        async_handles.sort();

        // Remove each item from the map and return to caller
        async_handles
            .iter()
            .map(|k| self.responses.remove(k).unwrap().0)
            .collect()
    }

    /// Called by the session to take the identified response if one exists, otherwise None
    pub(crate) fn take_response(&mut self, request_handle: u32) -> Option<SupportedMessage> {
        self.responses.remove(&request_handle).map(|v| v.0)
    }
}
