use std::sync::{Arc, RwLock};

use chrono::Utc;

use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_core::supported_message::SupportedMessage;

use crate::{
    address_space::AddressSpace,
    services::{
        attribute::AttributeService,
        discovery::DiscoveryService,
        method::MethodService,
        monitored_item::MonitoredItemService,
        session::SessionService,
        subscription::SubscriptionService,
        view::ViewService,
    },
    session::Session,
    state::ServerState,
};
use crate::services::node_management::NodeManagementService;

macro_rules! validate_security {
    ($validator: expr, $request: expr, $session: expr, $action: block) => {
        if let Err(response) = $validator.validate_request($session.clone(), &$request.request_header) {
            Some(response)
        } else {
            Some($action)
        }
    }
}

macro_rules! validate_security_and_active_session {
    ($validator: expr, $request: expr, $session: expr, $action: block) => {
        if let Err(response) = $validator.validate_request($session.clone(), &$request.request_header) {
            Some(response)
        } else if let Err(response) = $validator.session_activated($session.clone(), &$request.request_header) {
            Some(response)
        } else {
            Some($action)
        }
    }
}

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Certificate store for certs
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Server state
    server_state: Arc<RwLock<ServerState>>,
    /// Address space
    address_space: Arc<RwLock<AddressSpace>>,
    /// Session state
    session: Arc<RwLock<Session>>,
    /// Attribute service
    attribute_service: AttributeService,
    /// Discovery service
    discovery_service: DiscoveryService,
    /// Node Management service
    node_management_service: NodeManagementService,
    /// Method service
    method_service: MethodService,
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
    pub fn new(certificate_store: Arc<RwLock<CertificateStore>>, server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>) -> MessageHandler {
        MessageHandler {
            certificate_store,
            server_state,
            session,
            address_space,
            attribute_service: AttributeService::new(),
            discovery_service: DiscoveryService::new(),
            method_service: MethodService::new(),
            monitored_item_service: MonitoredItemService::new(),
            node_management_service: NodeManagementService::new(),
            session_service: SessionService::new(),
            view_service: ViewService::new(),
            subscription_service: SubscriptionService::new(),
        }
    }

    fn session_activated(&self, session: Arc<RwLock<Session>>, request_header: &RequestHeader) -> Result<(), SupportedMessage> {
        let session = trace_read_lock_unwrap!(session);
        if !session.activated {
            error!("Session is not activated so request fails");
            Err(ServiceFault::new(request_header, StatusCode::BadSessionNotActivated).into())
        } else {
            Ok(())
        }
    }

    /// Validates the request header information to ensure it is valid for the session.
    ///
    /// The request header should contain the session authentication token issued during a
    /// CreateSession or the request is invalid. An invalid token can cause the session to close.
    fn validate_request(&self, session: Arc<RwLock<Session>>, request_header: &RequestHeader) -> Result<(), SupportedMessage> {
        let mut session = trace_write_lock_unwrap!(session);
        // TODO if session's token is null, it might be possible to retrieve session state from a
        //  previously closed session and reassociate it if the authentication token is recognized
        let is_secure_connection = {
            let secure_channel = trace_read_lock_unwrap!(session.secure_channel);
            secure_channel.security_policy() != SecurityPolicy::None
        };

        if is_secure_connection && session.authentication_token != request_header.authentication_token {
            // Session should terminate
            session.terminate_session = true;
            error!("supplied authentication token {:?} does not match session's expected token {:?}", request_header.authentication_token, session.authentication_token);
            Err(ServiceFault::new(request_header, StatusCode::BadIdentityTokenRejected).into())
        } else {
            Ok(())
        }
    }

    pub fn handle_message(&mut self, request_id: u32, message: SupportedMessage) -> Result<Option<SupportedMessage>, StatusCode> {
        // Note the order of arguments for all these services is the order that they must be locked in,
        //
        // 1. ServerState
        // 2. Session
        // 3. AddressSpace

        let server_state = self.server_state.clone();
        let session = self.session.clone();
        let address_space = self.address_space.clone();

        let response = match &message {

            // Discovery Service Set, OPC UA Part 4, Section 5.4
            SupportedMessage::GetEndpointsRequest(request) => {
                Some(self.discovery_service.get_endpoints(server_state, request))
            }

            // Session Service Set, OPC UA Part 4, Section 5.6

            SupportedMessage::CreateSessionRequest(request) => {
                let certificate_store = trace_read_lock_unwrap!(self.certificate_store);
                Some(self.session_service.create_session(&certificate_store, server_state, session, address_space, request))
            }
            SupportedMessage::CloseSessionRequest(request) => {
                Some(self.session_service.close_session(session, request))
            }

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION

            SupportedMessage::ActivateSessionRequest(request) => {
                validate_security!(self, request, session, {
                    self.session_service.activate_session(server_state, session, request)
                })
            }

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION AND
            //        HAVE AN ACTIVE SESSION

            SupportedMessage::CancelRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.session_service.cancel(server_state, session, request)
                })
            }

            // NodeManagement Service Set, OPC UA Part 4, Section 5.7

            SupportedMessage::AddNodesRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.node_management_service.add_nodes(server_state, session, address_space, request)
                })
            }

            SupportedMessage::AddReferencesRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.node_management_service.add_references(server_state, session, address_space, request)
                })
            }

            SupportedMessage::DeleteNodesRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.node_management_service.delete_nodes(server_state, session, address_space, request)
                })
            }

            SupportedMessage::DeleteReferencesRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.node_management_service.delete_references(server_state, session, address_space, request)
                })
            }

            // View Service Set, OPC UA Part 4, Section 5.8

            SupportedMessage::BrowseRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.view_service.browse(session, address_space, request)
                })
            }
            SupportedMessage::BrowseNextRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.view_service.browse_next(session, address_space, request)
                })
            }
            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.view_service.translate_browse_paths_to_node_ids(server_state, address_space, request)
                })
            }
            SupportedMessage::RegisterNodesRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.view_service.register_nodes(server_state, session, request)
                })
            }
            SupportedMessage::UnregisterNodesRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.view_service.unregister_nodes(server_state, session, request)
                })
            }

            // Attribute Service Set, OPC UA Part 4, Section 5.10

            SupportedMessage::ReadRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.attribute_service.read(server_state, session, address_space, request)
                })
            }
            SupportedMessage::HistoryReadRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.attribute_service.history_read(server_state, session, address_space, request)
                })
            }
            SupportedMessage::WriteRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.attribute_service.write(server_state, session, address_space, request)
                })
            }
            SupportedMessage::HistoryUpdateRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.attribute_service.history_update(server_state, session,address_space, request)
                })
            }

            // Method Service Set, OPC UA Part 4, Section 5.11

            SupportedMessage::CallRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.method_service.call(server_state, session, address_space, request)
                })
            }

            // Monitored Item Service Set, OPC UA Part 4, Section 5.12

            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.monitored_item_service.create_monitored_items(server_state, session, address_space, request)
                })
            }
            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.monitored_item_service.modify_monitored_items(session, address_space, request)
                })
            }
            SupportedMessage::SetMonitoringModeRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.monitored_item_service.set_monitoring_mode(session, request)
                })
            }
            SupportedMessage::SetTriggeringRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.monitored_item_service.set_triggering(session, request)
                })
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.monitored_item_service.delete_monitored_items(session, request)
                })
            }

            // Subscription Service Set, OPC UA Part 4, Section 5.13

            SupportedMessage::CreateSubscriptionRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.subscription_service.create_subscription(server_state, session, request)
                })
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.subscription_service.modify_subscription(server_state, session, request)
                })
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.subscription_service.set_publishing_mode(session, request)
                })
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.subscription_service.delete_subscriptions(session, request)
                })
            }
            SupportedMessage::TransferSubscriptionsRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.subscription_service.transfer_subscriptions(session, request)
                })
            }
            SupportedMessage::PublishRequest(request) => {
                if let Err(response) = self.validate_request(session.clone(), &request.request_header) {
                    Some(response)
                } else {
                    // Unlike other calls which return immediately, this one is asynchronous - the
                    // request is queued and the response will come back out of sequence some time in
                    // the future.
                    self.subscription_service.async_publish(&Utc::now(), session, address_space, request_id, &request)
                }
            }
            SupportedMessage::RepublishRequest(request) => {
                validate_security_and_active_session!(self, request, session, {
                    self.subscription_service.republish(session, request)
                })
            }

            // Unhandle messages

            message => {
                debug!("Message handler does not handle this kind of message {:?}", message);
                return Err(StatusCode::BadServiceUnsupported);
            }
        };
        Ok(response)
    }
}
