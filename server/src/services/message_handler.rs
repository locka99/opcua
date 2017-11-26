use std::sync::{Arc, Mutex};

use opcua_types::*;

use address_space::address_space::AddressSpace;
use server_state::ServerState;
use session::Session;

use services::attribute::AttributeService;
use services::discovery::DiscoveryService;
use services::monitored_item::MonitoredItemService;
use services::session::SessionService;
use services::subscription::SubscriptionService;
use services::view::ViewService;

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Server state
    server_state: Arc<Mutex<ServerState>>,
    /// Address space
    address_space: Arc<Mutex<AddressSpace>>,
    /// Session state
    session: Arc<Mutex<Session>>,
    /// Attribute service
    attribute_service: AttributeService,
    /// Discovery service
    discovery_service: DiscoveryService,
    /// MonitoredItem service
    monitored_item_service: MonitoredItemService,
    /// Session service
    session_service: SessionService,
    /// Subscription service
    subscription_service: SubscriptionService,
    /// View service
    view_service: ViewService,
}

impl MessageHandler {
    pub fn new(server_state: Arc<Mutex<ServerState>>, session: Arc<Mutex<Session>>, address_space: Arc<Mutex<AddressSpace>>) -> MessageHandler {
        MessageHandler {
            server_state,
            session,
            address_space,
            attribute_service: AttributeService::new(),
            discovery_service: DiscoveryService::new(),
            monitored_item_service: MonitoredItemService::new(),
            session_service: SessionService::new(),
            view_service: ViewService::new(),
            subscription_service: SubscriptionService::new(),
        }
    }

    /// Validates the request header information to ensure it is valid for the session.
    ///
    /// The request header should contain the session authentication token issued during a
    /// CreateSession or the request is invalid. An invalid token can cause the session to close.
    fn validate_request(&self, session: &mut Session, request_header: &RequestHeader) -> Result<(), SupportedMessage> {
        // TODO if session's token is null, it might be possible to retrieve session state from a
        // previously closed session and reassociate it if the authentication token is recognized
        if session.authentication_token != request_header.authentication_token {
            // Session should terminate
            session.terminate_session = true;
            Err(ServiceFault::new_supported_message(request_header, BAD_IDENTITY_TOKEN_REJECTED))
        } else {
            Ok(())
        }
    }

    pub fn handle_message(&mut self, request_id: UInt32, message: SupportedMessage) -> Result<Option<SupportedMessage>, StatusCode> {
        // Note address space has to be locked before server_state because of deadlock in address_space.rs
        // or other vars tied to state that will happen the other way around.
        let mut address_space = trace_lock_unwrap!(self.address_space);
        let mut server_state = trace_lock_unwrap!(self.server_state);
        let mut session = trace_lock_unwrap!(self.session);

        let response = match message {
            SupportedMessage::GetEndpointsRequest(request) => {
                Some(self.discovery_service.get_endpoints(&mut server_state, request)?)
            }
            SupportedMessage::CreateSessionRequest(request) => {
                Some(self.session_service.create_session(&mut server_state, &mut session, request)?)
            }
            SupportedMessage::CloseSessionRequest(request) => {
                Some(self.session_service.close_session(&mut server_state, &mut session, request)?)
            }
            // ALL THE REQUESTS BELOW MUST BE VALIDATED AGAINST THE SESSION
            SupportedMessage::ActivateSessionRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.session_service.activate_session(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::CreateSubscriptionRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.create_subscription(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.modify_subscription(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.delete_subscriptions(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.set_publishing_mode(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::PublishRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    self.subscription_service.publish(&mut server_state, &mut session, request_id, &mut address_space, request)?
                }
            }
            SupportedMessage::RepublishRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.republish(&mut server_state, &mut session, &mut address_space, request)?)
                }
            }
            SupportedMessage::BrowseRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.view_service.browse(&mut server_state, &mut session, &mut address_space, request)?)
                }
            }
            SupportedMessage::BrowseNextRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.view_service.browse_next(&mut server_state, &mut session, &mut address_space, request)?)
                }
            }
            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.view_service.translate_browse_paths_to_node_ids(&mut address_space, request)?)
                }
            }
            SupportedMessage::ReadRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.attribute_service.read(&mut session, &mut address_space, request)?)
                }
            }
            SupportedMessage::WriteRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.attribute_service.write(&mut session, &mut address_space, request)?)
                }
            }
            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.monitored_item_service.create_monitored_items(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.monitored_item_service.modify_monitored_items(&mut server_state, &mut session, request)?)
                }
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.monitored_item_service.delete_monitored_items(&mut server_state, &mut session, request)?)
                }
            }
            _ => {
                debug!("Message handler does not handle this kind of message {:?}", message);
                return Err(BAD_SERVICE_UNSUPPORTED);
            }
        };
        Ok(response)
    }
}
