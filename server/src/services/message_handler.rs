use std::sync::{Arc, RwLock};

use opcua_core::crypto::CertificateStore;
use opcua_types::*;
use opcua_types::service_types::*;
use opcua_types::status_code::StatusCode;

use crate::{
    address_space::AddressSpace,
    state::ServerState,
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
};

macro_rules!  validated_request{
    ($validator: expr, $request: expr, $session: expr, $action: block) => {
        if let Err(response) = $validator.validate_request($session, &$request.request_header) {
            Some(response)
        } else {
            Some($action?)
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
        //  previously closed session and reassociate it if the authentication token is recognized
        if session.authentication_token != request_header.authentication_token {
            // Session should terminate
            session.terminate_session = true;
            Err(ServiceFault::new_supported_message(request_header, StatusCode::BadIdentityTokenRejected))
        } else {
            Ok(())
        }
    }

    pub fn handle_message(&mut self, request_id: u32, message: SupportedMessage) -> Result<Option<SupportedMessage>, StatusCode> {
        // Note address space has to be locked before server_state because of deadlock in address_space.rs
        // or other vars tied to state that will happen the other way around.
        let mut server_state = trace_write_lock_unwrap!(self.server_state);
        let mut session = trace_write_lock_unwrap!(self.session);

        // This MUST be last of the lockable items because server impls may set timers on this but not
        // state / session.
        let mut address_space = trace_write_lock_unwrap!(self.address_space);

        let response = match message {

            // Discovery Service Set, OPC UA Part 4, Section 5.4
            SupportedMessage::GetEndpointsRequest(request) => {
                Some(self.discovery_service.get_endpoints(&server_state, &request)?)
            }

            // Session Service Set, OPC UA Part 4, Section 5.6

            SupportedMessage::CreateSessionRequest(request) => {
                let certificate_store = trace_read_lock_unwrap!(self.certificate_store);
                Some(self.session_service.create_session(&certificate_store, &mut server_state, &mut session, &request)?)
            }
            SupportedMessage::CloseSessionRequest(request) => {
                Some(self.session_service.close_session(&mut session, &request)?)
            }

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION

            SupportedMessage::ActivateSessionRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.session_service.activate_session(&mut server_state, &mut session, &request)
                })
            }
            SupportedMessage::CancelRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.session_service.cancel(&mut server_state, &mut session, &request)
                })
            }

            // NodeManagement Service Set, OPC UA Part 4, Section 5.7

            // View Service Set, OPC UA Part 4, Section 5.8

            SupportedMessage::BrowseRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.view_service.browse(&mut session, &address_space, &request)
                })
            }
            SupportedMessage::BrowseNextRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.view_service.browse_next(&mut session, &address_space, &request)
                })
            }
            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.view_service.translate_browse_paths_to_node_ids(&address_space, &request)
                })
            }

            // Attribute Service Set, OPC UA Part 4, Section 5.10

            SupportedMessage::ReadRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.attribute_service.read(&address_space, &request)
                })
            }
            SupportedMessage::WriteRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.attribute_service.write(&mut address_space, &request)
                })
            }

            // Method Service Set, OPC UA Part 4, Section 5.11

            SupportedMessage::CallRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.method_service.call(&address_space, &server_state, &mut session, &request)
                })
            }

            // Monitored Item Service Set, OPC UA Part 4, Section 5.12

            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.monitored_item_service.create_monitored_items(&mut session, &request)
                })
            }
            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.monitored_item_service.modify_monitored_items(&mut session, &request)
                })
            }
            SupportedMessage::SetMonitoringModeRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.monitored_item_service.set_monitoring_mode(&mut session, &request)
                })
            }
            SupportedMessage::SetTriggeringRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.monitored_item_service.set_triggering(&mut session, &request)
                })
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.monitored_item_service.delete_monitored_items(&mut session, &request)
                })
            }

            // Subscription Service Set, OPC UA Part 4, Section 5.13

            SupportedMessage::CreateSubscriptionRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.subscription_service.create_subscription(&mut server_state, &mut session, &request)
                })
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.subscription_service.modify_subscription(&mut server_state, &mut session, &request)
                })
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.subscription_service.set_publishing_mode(&mut session, &request)
                })
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.subscription_service.delete_subscriptions(&mut session, &request)
                })
            }
            SupportedMessage::TransferSubscriptionsRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.subscription_service.transfer_subscriptions(&mut session, &request)
                })
            }
            SupportedMessage::PublishRequest(request) => {
                if let Err(response) = self.validate_request(&mut session, &request.request_header) {
                    Some(response)
                } else {
                    // Unlike other calls which return immediately, this one is asynchronous - the
                    // request is queued and the response will come back out of sequence some time in
                    // the future.
                    self.subscription_service.async_publish(&mut session, request_id, &address_space, &request)?
                }
            }
            SupportedMessage::RepublishRequest(request) => {
                validated_request!(self, &request, &mut session, {
                    self.subscription_service.republish(&mut session, &request)
                })
            }

            _ => {
                debug!("Message handler does not handle this kind of message {:?}", message);
                return Err(StatusCode::BadServiceUnsupported);
            }
        };
        Ok(response)
    }
}
