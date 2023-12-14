// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::collections::HashMap;

use tokio::sync::{
    mpsc::{self, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::core::supported_message::SupportedMessage;

pub async fn message_queue_loop(mut rx: mpsc::Receiver<Request>) {
    let mut queue = MessageQueue::new();
    log::debug!("Spawn message queue");

    while let Some(msg) = rx.recv().await {
        match msg {
            Request::Quit => {
                queue.quit();
                break;
            }
            Request::Clear => {
                queue.clear();
            }
            Request::AddRequest(msg, sender) => {
                queue.add_request(msg, Some(sender));
            }
            Request::Publish(msg) => {
                queue.add_request(msg, None);
            }
            Request::SetSender(tx) => {
                queue.sender = Some(tx);
            }
            Request::StoreResponse(msg) => {
                queue.store_response(msg);
            }
            Request::GetResponses(tx) => {
                if let Err(_) = tx.send(queue.async_responses()) {
                    log::error!("Unable to send responses");
                    break;
                };
            }
        }
    }
    log::info!("Exit message queue loop");
}

pub enum Request {
    Quit,
    Clear,
    SetSender(UnboundedSender<Message>),
    AddRequest(SupportedMessage, oneshot::Sender<SupportedMessage>),
    Publish(SupportedMessage),
    StoreResponse(SupportedMessage),
    GetResponses(oneshot::Sender<Vec<SupportedMessage>>),
}

struct MessageQueue {
    /// The requests that are in-flight, defined by their request handle and optionally a sender that will be notified with the response.
    /// Basically, the sent requests reside here until the response returns at which point the entry is removed.
    /// If a response is received for which there is no entry, the response will be discarded.
    inflight_requests: HashMap<u32, Option<oneshot::Sender<SupportedMessage>>>,
    /// A map of incoming responses waiting to be processed
    responses: HashMap<u32, SupportedMessage>,
    /// This is the queue that messages will be sent onto the transport for sending
    sender: Option<UnboundedSender<Message>>,
}

#[derive(Debug)]
pub enum Message {
    Quit,
    SupportedMessage(SupportedMessage),
}

impl MessageQueue {
    fn new() -> MessageQueue {
        MessageQueue {
            inflight_requests: HashMap::new(),
            responses: HashMap::new(),
            sender: None,
        }
    }

    fn clear(&mut self) {
        self.inflight_requests.clear();
        self.responses.clear();
    }

    fn send_message(&self, message: Message) -> bool {
        let sender = self.sender.as_ref().expect(
            "MessageQueue::send_message should never be called before make_request_channel",
        );
        if sender.is_closed() {
            log::error!("Send message will fail because sender has been closed");
            false
        } else if let Err(err) = sender.send(message) {
            log::debug!("Cannot send message to message receiver, error {}", err);
            false
        } else {
            true
        }
    }

    /// Called by the session to add a request to be sent. The sender parameter
    /// is supplied by synchronous callers to be notified the moment the response is received.
    /// Async callers, e.g. publish requests can supply None.
    fn add_request(
        &mut self,
        request: SupportedMessage,
        sender: Option<oneshot::Sender<SupportedMessage>>,
    ) {
        let request_handle = request.request_handle();
        //log::trace!("Sending request {:?} to be sent", request);
        log::trace!("Sending request");
        self.inflight_requests.insert(request_handle, sender);
        let _ = self.send_message(Message::SupportedMessage(request));
    }

    fn quit(&self) {
        log::debug!("Sending a quit to the message receiver");
        let _ = self.send_message(Message::Quit);
    }

    /// Called when a session's request times out. This call allows the session state to remove
    /// the request as pending and ignore any response that arrives for it.
    fn request_has_timed_out(&mut self, request_handle: u32) {
        log::info!("Request {request_handle} has timed out and any response will be ignored");
        let _ = self.inflight_requests.remove(&request_handle);
    }

    /// Called by the connection to store a response for the consumption of the session.
    fn store_response(&mut self, response: SupportedMessage) {
        // Remove corresponding request handle from inflight queue, add to responses
        let request_handle = response.request_handle();
        log::trace!("Received response {response:?}");
        log::debug!("Response to Request {request_handle} has been stored");
        // Remove the inflight request
        // This true / false is slightly clunky.
        if let Some(sender) = self.inflight_requests.remove(&request_handle) {
            if let Some(sender) = sender {
                // Synchronous request
                if let Err(_) = sender.send(response) {
                    log::error!(
                        "Cannot send a response to a synchronous request {} because send failed",
                        request_handle,
                    );
                }
            } else {
                self.responses.insert(request_handle, response);
            }
        } else {
            log::error!("A response with request handle {request_handle} doesn't belong to any request and will be ignored, inflight requests = {:?}, request = {:?}", self.inflight_requests, response);
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
    fn async_responses(&mut self) -> Vec<SupportedMessage> {
        // Gather up all request handles
        let mut async_handles = self.responses.keys().copied().collect::<Vec<_>>();

        // Order them from oldest to latest (except if handles wrap)
        async_handles.sort();

        // Remove each item from the map and return to caller
        async_handles
            .iter()
            .map(|k| self.responses.remove(k).unwrap())
            .collect()
    }
}
