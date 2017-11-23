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
        let mut server_state = self.server_state.lock().unwrap();
        let server_state = &mut server_state;
        let mut session = self.session.lock().unwrap();
        let address_space = self.address_space.lock().unwrap();
        let address_space = &address_space;
        let session = &mut session;

        let response = match message {
            SupportedMessage::GetEndpointsRequest(request) => {
                Some(self.discovery_service.get_endpoints(server_state, session, address_space, request)?)
            }
            SupportedMessage::CreateSessionRequest(request) => {
                Some(self.session_service.create_session(server_state, session, address_space, request)?)
            }
            SupportedMessage::CloseSessionRequest(request) => {
                Some(self.session_service.close_session(server_state, session, address_space, request)?)
            }
            // ALL THE REQUESTS BELOW MUST BE VALIDATED AGAINST THE SESSION
            SupportedMessage::ActivateSessionRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.session_service.activate_session(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::CreateSubscriptionRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.create_subscription(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.modify_subscription(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.delete_subscriptions(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.set_publishing_mode(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::PublishRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    self.subscription_service.publish(server_state, session, request_id, address_space, request)?
                }
            }
            SupportedMessage::RepublishRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.subscription_service.republish(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::BrowseRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.view_service.browse(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::BrowseNextRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.view_service.browse_next(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.view_service.translate_browse_paths_to_node_ids(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::ReadRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.attribute_service.read(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::WriteRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.attribute_service.write(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.monitored_item_service.create_monitored_items(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.monitored_item_service.modify_monitored_items(server_state, session, address_space, request)?)
                }
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                if let Err(response) = self.validate_request(session, &request.request_header) {
                    Some(response)
                } else {
                    Some(self.monitored_item_service.delete_monitored_items(server_state, session, address_space, request)?)
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
