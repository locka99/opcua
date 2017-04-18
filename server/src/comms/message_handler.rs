use std::sync::{Arc, Mutex};

use opcua_core::types::*;
use opcua_core::comms::*;

use server::ServerState;
use session::SessionState;

use services::attribute::*;
use services::discovery::*;
use services::monitored_item::*;
use services::session::*;
use services::subscription::*;
use services::view::*;

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Server state
    server_state: Arc<Mutex<ServerState>>,
    /// Session state
    session_state: Arc<Mutex<SessionState>>,
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
    pub fn new(server_state: &Arc<Mutex<ServerState>>, session_state: &Arc<Mutex<SessionState>>) -> MessageHandler {
        MessageHandler {
            server_state: server_state.clone(),
            session_state: session_state.clone(),
            attribute_service: AttributeService::new(),
            discovery_service: DiscoveryService::new(),
            monitored_item_service: MonitoredItemService::new(),
            session_service: SessionService::new(),
            view_service: ViewService::new(),
            subscription_service: SubscriptionService::new(),
        }
    }

    pub fn handle_message(&mut self, request_id: UInt32, message: SupportedMessage) -> Result<SupportedMessage, StatusCode> {
        let mut server_state = self.server_state.lock().unwrap();
        let mut server_state = &mut server_state;
        let mut session_state = self.session_state.lock().unwrap();
        let mut session_state = &mut session_state;

        let response = match message {
            SupportedMessage::GetEndpointsRequest(request) => {
                self.discovery_service.get_endpoints(server_state, session_state, request)?
            }
            SupportedMessage::CreateSessionRequest(request) => {
                self.session_service.create_session(server_state, session_state, request)?
            }
            SupportedMessage::CloseSessionRequest(request) => {
                self.session_service.close_session(server_state, session_state, request)?
            }
            SupportedMessage::ActivateSessionRequest(request) => {
                self.session_service.activate_session(server_state, session_state, request)?
            }
            SupportedMessage::CreateSubscriptionRequest(request) => {
                self.subscription_service.create_subscription(server_state, session_state, request)?
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                self.subscription_service.modify_subscription(server_state, session_state, request)?
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                self.subscription_service.delete_subscriptions(server_state, session_state, request)?
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                self.subscription_service.set_publishing_mode(server_state, session_state, request)?
            }
            SupportedMessage::PublishRequest(request) => {
                self.subscription_service.publish(server_state, session_state, request_id, request)?
            }
            SupportedMessage::RepublishRequest(request) => {
                self.subscription_service.republish(server_state, session_state, request)?
            }
            SupportedMessage::BrowseRequest(request) => {
                self.view_service.browse(server_state, session_state, request)?
            }
            SupportedMessage::BrowseNextRequest(request) => {
                self.view_service.browse_next(server_state, session_state, request)?
            }
            SupportedMessage::ReadRequest(request) => {
                self.attribute_service.read(server_state, session_state, request)?
            }
            SupportedMessage::WriteRequest(request) => {
                self.attribute_service.write(server_state, session_state, request)?
            }
            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                self.monitored_item_service.create_monitored_items(server_state, session_state, request)?
            }
            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                self.monitored_item_service.modify_monitored_items(server_state, session_state, request)?
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                self.monitored_item_service.delete_monitored_items(server_state, session_state, request)?
            }
            _ => {
                debug!("Message handler does not handle this kind of message {:?}", message);
                return Err(BAD_SERVICE_UNSUPPORTED);
            }
        };
        Ok(response)
    }
}
