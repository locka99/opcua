// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::sync::{Arc, RwLock};

use chrono::Utc;

use opcua_core::supported_message::SupportedMessage;
use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::{status_code::StatusCode, *};

use crate::{
    address_space::AddressSpace,
    comms::tcp_transport::MessageSender,
    services::{
        attribute::AttributeService, discovery::DiscoveryService, method::MethodService,
        monitored_item::MonitoredItemService, node_management::NodeManagementService,
        query::QueryService, session::SessionService, subscription::SubscriptionService,
        view::ViewService,
    },
    session::Session,
    session_diagnostics::*,
    state::ServerState,
};

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
    /// Query service
    query_service: QueryService,
    /// Session service
    session_service: SessionService,
    /// Subscription service
    subscription_service: SubscriptionService,
    /// View service
    view_service: ViewService,
}

impl MessageHandler {
    pub fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
    ) -> MessageHandler {
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
            query_service: QueryService::new(),
            session_service: SessionService::new(),
            view_service: ViewService::new(),
            subscription_service: SubscriptionService::new(),
        }
    }

    pub fn handle_message(
        &mut self,
        request_id: u32,
        message: &SupportedMessage,
        sender: &MessageSender,
    ) -> Result<(), StatusCode> {
        // Note the order of arguments for all these services is the order that they must be locked in,
        //
        // 1. ServerState
        // 2. Session
        // 3. AddressSpace

        let server_state = self.server_state.clone();
        let session = self.session.clone();
        let address_space = self.address_space.clone();

        let response = match message {
            // Discovery Service Set, OPC UA Part 4, Section 5.4
            SupportedMessage::GetEndpointsRequest(request) => {
                Some(self.discovery_service.get_endpoints(server_state, request))
            }

            SupportedMessage::RegisterServerRequest(request) => Some(
                self.discovery_service
                    .register_server(server_state, request),
            ),

            SupportedMessage::RegisterServer2Request(request) => Some(
                self.discovery_service
                    .register_server2(server_state, request),
            ),

            SupportedMessage::FindServersRequest(request) => {
                Some(self.discovery_service.find_servers(server_state, request))
            }

            // Session Service Set, OPC UA Part 4, Section 5.6
            SupportedMessage::CreateSessionRequest(request) => {
                let certificate_store = trace_read_lock_unwrap!(self.certificate_store);
                Some(self.session_service.create_session(
                    &certificate_store,
                    server_state,
                    session,
                    address_space,
                    request,
                ))
            }
            SupportedMessage::CloseSessionRequest(request) => Some(
                self.session_service
                    .close_session(server_state, session, address_space, request),
            ),

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION
            SupportedMessage::ActivateSessionRequest(request) => {
                Self::validate_service_request(message, session.clone(), "", move || {
                    self.session_service.activate_session(
                        server_state,
                        session,
                        address_space,
                        request,
                    )
                })
            }

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION AND
            //        HAVE AN ACTIVE SESSION
            SupportedMessage::CancelRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    "",
                    move || self.session_service.cancel(server_state, session, request),
                )
            }

            // NodeManagement Service Set, OPC UA Part 4, Section 5.7
            SupportedMessage::AddNodesRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    ADD_NODES_COUNT,
                    move || {
                        self.node_management_service.add_nodes(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }

            SupportedMessage::AddReferencesRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    ADD_REFERENCES_COUNT,
                    move || {
                        self.node_management_service.add_references(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }

            SupportedMessage::DeleteNodesRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    DELETE_NODES_COUNT,
                    move || {
                        self.node_management_service.delete_nodes(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }

            SupportedMessage::DeleteReferencesRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    DELETE_REFERENCES_COUNT,
                    move || {
                        self.node_management_service.delete_references(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }

            // View Service Set, OPC UA Part 4, Section 5.8
            SupportedMessage::BrowseRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    BROWSE_COUNT,
                    move || {
                        self.view_service
                            .browse(server_state, session, address_space, request)
                    },
                )
            }
            SupportedMessage::BrowseNextRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    BROWSE_NEXT_COUNT,
                    move || {
                        self.view_service
                            .browse_next(session, address_space, request)
                    },
                )
            }
            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_COUNT,
                    move || {
                        self.view_service.translate_browse_paths_to_node_ids(
                            server_state,
                            address_space,
                            request,
                        )
                    },
                )
            }
            SupportedMessage::RegisterNodesRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    REGISTER_NODES_COUNT,
                    move || {
                        self.view_service
                            .register_nodes(server_state, session, request)
                    },
                )
            }
            SupportedMessage::UnregisterNodesRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    UNREGISTER_NODES_COUNT,
                    move || {
                        self.view_service
                            .unregister_nodes(server_state, session, request)
                    },
                )
            }

            // Query Service Set, OPC UA Part 4, Section 5.9
            SupportedMessage::QueryFirstRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    READ_COUNT,
                    move || {
                        self.query_service.query_first(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }

            SupportedMessage::QueryNextRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    READ_COUNT,
                    move || {
                        self.query_service
                            .query_next(server_state, session, address_space, request)
                    },
                )
            }

            // Attribute Service Set, OPC UA Part 4, Section 5.10
            SupportedMessage::ReadRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    READ_COUNT,
                    move || {
                        self.attribute_service
                            .read(server_state, session, address_space, request)
                    },
                )
            }
            SupportedMessage::HistoryReadRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    HISTORY_READ_COUNT,
                    move || {
                        self.attribute_service.history_read(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }
            SupportedMessage::WriteRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    WRITE_COUNT,
                    move || {
                        self.attribute_service
                            .write(server_state, session, address_space, request)
                    },
                )
            }
            SupportedMessage::HistoryUpdateRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    HISTORY_UPDATE_COUNT,
                    move || {
                        self.attribute_service.history_update(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }

            // Method Service Set, OPC UA Part 4, Section 5.11
            SupportedMessage::CallRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    CALL_COUNT,
                    move || {
                        self.method_service
                            .call(server_state, session, address_space, request)
                    },
                )
            }

            // Monitored Item Service Set, OPC UA Part 4, Section 5.12
            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    CREATE_MONITORED_ITEMS_COUNT,
                    move || {
                        self.monitored_item_service.create_monitored_items(
                            server_state,
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }
            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    MODIFY_MONITORED_ITEMS_COUNT,
                    move || {
                        self.monitored_item_service.modify_monitored_items(
                            session,
                            address_space,
                            request,
                        )
                    },
                )
            }
            SupportedMessage::SetMonitoringModeRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    SET_MONITORING_MODE_COUNT,
                    move || {
                        self.monitored_item_service
                            .set_monitoring_mode(session, request)
                    },
                )
            }
            SupportedMessage::SetTriggeringRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    SET_TRIGGERING_COUNT,
                    move || self.monitored_item_service.set_triggering(session, request),
                )
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    DELETE_MONITORED_ITEMS_COUNT,
                    move || {
                        self.monitored_item_service
                            .delete_monitored_items(session, request)
                    },
                )
            }

            // Subscription Service Set, OPC UA Part 4, Section 5.13
            SupportedMessage::CreateSubscriptionRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    CREATE_SUBSCRIPTION_COUNT,
                    move || {
                        self.subscription_service.create_subscription(
                            server_state,
                            session,
                            request,
                        )
                    },
                )
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    MODIFY_SUBSCRIPTION_COUNT,
                    move || {
                        self.subscription_service.modify_subscription(
                            server_state,
                            session,
                            request,
                        )
                    },
                )
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    SET_PUBLISHING_MODE_COUNT,
                    move || {
                        self.subscription_service
                            .set_publishing_mode(session, request)
                    },
                )
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    DELETE_SUBSCRIPTIONS_COUNT,
                    move || {
                        self.subscription_service
                            .delete_subscriptions(session, request)
                    },
                )
            }
            SupportedMessage::TransferSubscriptionsRequest(request) => {
                Self::validate_active_session_service_request(
                    message,
                    session.clone(),
                    TRANSFER_SUBSCRIPTIONS_COUNT,
                    move || {
                        self.subscription_service
                            .transfer_subscriptions(session, request)
                    },
                )
            }
            SupportedMessage::PublishRequest(request) => {
                if let Err(response) =
                    Self::is_authentication_token_valid(session.clone(), &request.request_header)
                {
                    Some(response)
                } else {
                    // TODO publish request diagnostics have to be done asynchronously too

                    // Unlike other calls which return immediately, this one is asynchronous - the
                    // request is queued and the response will come back out of sequence some time in
                    // the future.
                    self.subscription_service.async_publish(
                        &Utc::now(),
                        session,
                        address_space,
                        request_id,
                        &request,
                    )
                }
            }
            SupportedMessage::RepublishRequest(request) => {
                Self::validate_active_session_service_request(
                    &message,
                    session.clone(),
                    REPUBLISH_COUNT,
                    move || self.subscription_service.republish(session, request),
                )
            }

            // Unhandle messages
            message => {
                debug!(
                    "Message handler does not handle this kind of message {:?}",
                    message
                );
                return Err(StatusCode::BadServiceUnsupported);
            }
        };

        if let Some(response) = response {
            let _ = sender.send_message(request_id, response);
        }

        Ok(())
    }

    /// Tests the request header information to ensure it is valid for the session.
    ///
    /// The request header should contain the session authentication token issued during a
    /// CreateSession or the request is invalid. An invalid token can cause the session to close.
    fn is_authentication_token_valid(
        session: Arc<RwLock<Session>>,
        request_header: &RequestHeader,
    ) -> Result<(), SupportedMessage> {
        let mut session = trace_write_lock_unwrap!(session);
        // TODO if session's token is null, it might be possible to retrieve session state from a
        //  previously closed session and reassociate it if the authentication token is recognized
        let is_secure_connection = {
            let secure_channel = session.secure_channel();
            let secure_channel = trace_read_lock_unwrap!(secure_channel);
            secure_channel.security_policy() != SecurityPolicy::None
        };
        if is_secure_connection
            && session.authentication_token() != &request_header.authentication_token
        {
            // Session should terminate
            session.terminate_session();
            error!(
                "supplied authentication token {:?} does not match session's expected token {:?}",
                request_header.authentication_token,
                session.authentication_token()
            );
            Err(ServiceFault::new(request_header, StatusCode::BadIdentityTokenRejected).into())
        } else {
            Ok(())
        }
    }

    /// Tests if this request should be rejected because of a session timeout
    fn is_session_timed_out(
        session: Arc<RwLock<Session>>,
        request_header: &RequestHeader,
        now: DateTimeUtc,
    ) -> Result<(), SupportedMessage> {
        let mut session = trace_write_lock_unwrap!(session);
        let last_service_request_timestamp = session.last_service_request_timestamp();
        let elapsed = now - last_service_request_timestamp;
        if elapsed.num_milliseconds() as f64 > session.session_timeout() {
            session.terminate_session();
            error!("Session has timed out because too much time has elapsed between service calls - elapsed time = {}ms", elapsed.num_milliseconds());
            Err(ServiceFault::new(request_header, StatusCode::BadSessionIdInvalid).into())
        } else {
            Ok(())
        }
    }

    /// Updates the last service request timestamp after handling the request
    fn update_last_service_request_timestamp(session: Arc<RwLock<Session>>, now: DateTimeUtc) {
        let mut session = trace_write_lock_unwrap!(session);
        session.set_last_service_request_timestamp(now);
    }

    /// Test if the session is activated
    fn is_session_activated(
        session: Arc<RwLock<Session>>,
        request_header: &RequestHeader,
    ) -> Result<(), SupportedMessage> {
        let session = trace_read_lock_unwrap!(session);
        if !session.is_activated() {
            error!("Session is not activated so request fails");
            Err(ServiceFault::new(request_header, StatusCode::BadSessionNotActivated).into())
        } else {
            Ok(())
        }
    }

    /// Validate the security of the call
    fn validate_service_request<F>(
        request: &SupportedMessage,
        session: Arc<RwLock<Session>>,
        diagnostic_key: &'static str,
        action: F,
    ) -> Option<SupportedMessage>
    where
        F: FnOnce() -> SupportedMessage,
    {
        let now = Utc::now();
        let request_header = request.request_header();
        let (response, authorized) = if let Err(response) =
            Self::is_authentication_token_valid(session.clone(), request_header)
        {
            (response, false)
        } else if let Err(response) =
            Self::is_session_timed_out(session.clone(), request_header, now)
        {
            (response, false)
        } else {
            let response = action();
            let mut session = trace_write_lock_unwrap!(session);
            session.set_last_service_request_timestamp(now);
            (response, true)
        };
        Self::diag_service_response(session, authorized, &response, diagnostic_key);
        Some(response)
    }

    /// Validate the security of the call and also for an active session
    fn validate_active_session_service_request<F>(
        request: &SupportedMessage,
        session: Arc<RwLock<Session>>,
        diagnostic_key: &'static str,
        action: F,
    ) -> Option<SupportedMessage>
    where
        F: FnOnce() -> SupportedMessage,
    {
        let now = Utc::now();
        let request_header = request.request_header();
        let (response, authorized) = if let Err(response) =
            Self::is_authentication_token_valid(session.clone(), request_header)
        {
            (response, false)
        } else if let Err(response) = Self::is_session_activated(session.clone(), request_header) {
            (response, false)
        } else if let Err(response) =
            Self::is_session_timed_out(session.clone(), request_header, now)
        {
            (response, false)
        } else {
            let response = action();
            let mut session = trace_write_lock_unwrap!(session);
            session.set_last_service_request_timestamp(now);
            (response, true)
        };
        Self::diag_service_response(session, authorized, &response, diagnostic_key);
        Some(response)
    }

    /// Increment count of request in session diagnostics
    fn diag_authorized_request(session_diagnostics: &mut SessionDiagnostics, authorized: bool) {
        if authorized {
            session_diagnostics.request();
        } else {
            session_diagnostics.unauthorized_request();
        }
    }

    /// Increment count of service call in session diagnostics
    fn diag_service_response(
        session: Arc<RwLock<Session>>,
        authorized: bool,
        response: &SupportedMessage,
        diagnostic_key: &'static str,
    ) {
        let session = trace_read_lock_unwrap!(session);
        let session_diagnostics = session.session_diagnostics();
        let mut session_diagnostics = trace_write_lock_unwrap!(session_diagnostics);
        Self::diag_authorized_request(&mut session_diagnostics, authorized);
        if diagnostic_key.len() > 0 {
            let service_success = if let SupportedMessage::ServiceFault(_response) = response {
                false
            } else {
                true
            };
            if service_success {
                session_diagnostics.service_success(diagnostic_key);
            } else {
                session_diagnostics.service_error(diagnostic_key);
            }
        }
    }
}
