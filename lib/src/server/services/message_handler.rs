// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use chrono::Utc;

use crate::core::comms::secure_channel::SecureChannel;
use crate::core::supported_message::SupportedMessage;
use crate::crypto::CertificateStore;
use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::{
    address_space::AddressSpace,
    comms::tcp_transport::MessageSender,
    services::{
        attribute::AttributeService, discovery::DiscoveryService, method::MethodService,
        monitored_item::MonitoredItemService, node_management::NodeManagementService,
        query::QueryService, session::SessionService, subscription::SubscriptionService,
        view::ViewService,
    },
    session::{Session, SessionManager},
    session_diagnostics::*,
    state::ServerState,
};

/// Processes and dispatches messages for handling
pub(crate) struct MessageHandler {
    /// Secure channel
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Certificate store for certs
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Server state
    server_state: Arc<RwLock<ServerState>>,
    /// Address space
    address_space: Arc<RwLock<AddressSpace>>,
    /// Session state
    session_manager: Arc<RwLock<SessionManager>>,
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
        secure_channel: Arc<RwLock<SecureChannel>>,
        certificate_store: Arc<RwLock<CertificateStore>>,
        server_state: Arc<RwLock<ServerState>>,
        session_manager: Arc<RwLock<SessionManager>>,
        address_space: Arc<RwLock<AddressSpace>>,
    ) -> MessageHandler {
        MessageHandler {
            secure_channel,
            certificate_store,
            server_state,
            session_manager,
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
                let mut session_manager = trace_write_lock!(self.session_manager);

                // TODO this is completely arbitrary - 5 sessions total in a single connection
                pub(crate) const MAX_SESSIONS_PER_TRANSPORT: usize = 5;

                let response = if session_manager.len() >= MAX_SESSIONS_PER_TRANSPORT {
                    ServiceFault::new(&request.request_header, StatusCode::BadTooManySessions)
                        .into()
                } else {
                    let (session, response) = self.session_service.create_session(
                        self.secure_channel.clone(),
                        self.certificate_store.clone(),
                        server_state,
                        address_space,
                        request,
                    );
                    if let Some(session) = session {
                        session_manager.register_session(Arc::new(RwLock::new(session)));
                    }
                    response
                };
                Some(response)
            }
            SupportedMessage::CloseSessionRequest(request) => {
                let secure_channel = self.secure_channel.clone();
                Some(self.session_service.close_session(
                    secure_channel,
                    self.session_manager.clone(),
                    server_state,
                    address_space,
                    request,
                ))
            }

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION
            SupportedMessage::ActivateSessionRequest(request) => self
                .validate_activate_service_request(message, "", |session| {
                    let secure_channel = self.secure_channel.clone();
                    self.session_service.activate_session(
                        secure_channel,
                        server_state,
                        session,
                        address_space,
                        request,
                    )
                }),

            // NOTE - ALL THE REQUESTS BEYOND THIS POINT MUST BE VALIDATED AGAINST THE SESSION AND
            //        HAVE AN ACTIVE SESSION
            SupportedMessage::CancelRequest(request) => {
                self.validate_service_request(message, "", |session, _| {
                    Some(self.session_service.cancel(server_state, session, request))
                })
            }

            // NodeManagement Service Set, OPC UA Part 4, Section 5.7
            SupportedMessage::AddNodesRequest(request) => {
                self.validate_service_request(message, ADD_NODES_COUNT, |session, _| {
                    Some(self.node_management_service.add_nodes(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            SupportedMessage::AddReferencesRequest(request) => {
                self.validate_service_request(message, ADD_REFERENCES_COUNT, |session, _| {
                    Some(self.node_management_service.add_references(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            SupportedMessage::DeleteNodesRequest(request) => {
                self.validate_service_request(message, DELETE_NODES_COUNT, |session, _| {
                    Some(self.node_management_service.delete_nodes(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            SupportedMessage::DeleteReferencesRequest(request) => {
                self.validate_service_request(message, DELETE_REFERENCES_COUNT, |session, _| {
                    Some(self.node_management_service.delete_references(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            // View Service Set, OPC UA Part 4, Section 5.8
            SupportedMessage::BrowseRequest(request) => {
                self.validate_service_request(message, BROWSE_COUNT, |session, _| {
                    Some(
                        self.view_service
                            .browse(server_state, session, address_space, request),
                    )
                })
            }
            SupportedMessage::BrowseNextRequest(request) => {
                self.validate_service_request(message, BROWSE_NEXT_COUNT, |session, _| {
                    Some(
                        self.view_service
                            .browse_next(session, address_space, request),
                    )
                })
            }
            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => self
                .validate_service_request(
                    message,
                    TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_COUNT,
                    |_, _| {
                        Some(self.view_service.translate_browse_paths_to_node_ids(
                            server_state,
                            address_space,
                            request,
                        ))
                    },
                ),
            SupportedMessage::RegisterNodesRequest(request) => {
                self.validate_service_request(message, REGISTER_NODES_COUNT, |session, _| {
                    Some(
                        self.view_service
                            .register_nodes(server_state, session, request),
                    )
                })
            }
            SupportedMessage::UnregisterNodesRequest(request) => {
                self.validate_service_request(message, UNREGISTER_NODES_COUNT, |session, _| {
                    Some(
                        self.view_service
                            .unregister_nodes(server_state, session, request),
                    )
                })
            }

            // Query Service Set, OPC UA Part 4, Section 5.9
            SupportedMessage::QueryFirstRequest(request) => {
                self.validate_service_request(message, READ_COUNT, |session, _| {
                    Some(self.query_service.query_first(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            SupportedMessage::QueryNextRequest(request) => {
                self.validate_service_request(message, READ_COUNT, |session, _| {
                    Some(self.query_service.query_next(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            // Attribute Service Set, OPC UA Part 4, Section 5.10
            SupportedMessage::ReadRequest(request) => {
                self.validate_service_request(message, READ_COUNT, |session, _| {
                    Some(
                        self.attribute_service
                            .read(server_state, session, address_space, request),
                    )
                })
            }
            SupportedMessage::HistoryReadRequest(request) => {
                self.validate_service_request(message, HISTORY_READ_COUNT, |session, _| {
                    Some(self.attribute_service.history_read(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }
            SupportedMessage::WriteRequest(request) => {
                self.validate_service_request(message, WRITE_COUNT, |session, _| {
                    Some(self.attribute_service.write(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }
            SupportedMessage::HistoryUpdateRequest(request) => {
                self.validate_service_request(message, HISTORY_UPDATE_COUNT, |session, _| {
                    Some(self.attribute_service.history_update(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                })
            }

            // Method Service Set, OPC UA Part 4, Section 5.11
            SupportedMessage::CallRequest(request) => {
                self.validate_service_request(message, CALL_COUNT, |session, session_manager| {
                    let session_id = {
                        let session = trace_read_lock!(session);
                        session.session_id().clone()
                    };
                    Some(self.method_service.call(
                        server_state,
                        &session_id,
                        session_manager,
                        address_space,
                        request,
                    ))
                })
            }

            // Monitored Item Service Set, OPC UA Part 4, Section 5.12
            SupportedMessage::CreateMonitoredItemsRequest(request) => self
                .validate_service_request(message, CREATE_MONITORED_ITEMS_COUNT, |session, _| {
                    Some(self.monitored_item_service.create_monitored_items(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                }),
            SupportedMessage::ModifyMonitoredItemsRequest(request) => self
                .validate_service_request(message, MODIFY_MONITORED_ITEMS_COUNT, |session, _| {
                    Some(self.monitored_item_service.modify_monitored_items(
                        server_state,
                        session,
                        address_space,
                        request,
                    ))
                }),
            SupportedMessage::SetMonitoringModeRequest(request) => {
                self.validate_service_request(message, SET_MONITORING_MODE_COUNT, |session, _| {
                    Some(
                        self.monitored_item_service
                            .set_monitoring_mode(session, request),
                    )
                })
            }
            SupportedMessage::SetTriggeringRequest(request) => {
                self.validate_service_request(message, SET_TRIGGERING_COUNT, |session, _| {
                    Some(self.monitored_item_service.set_triggering(session, request))
                })
            }
            SupportedMessage::DeleteMonitoredItemsRequest(request) => self
                .validate_service_request(message, DELETE_MONITORED_ITEMS_COUNT, |session, _| {
                    Some(
                        self.monitored_item_service
                            .delete_monitored_items(session, request),
                    )
                }),

            // Subscription Service Set, OPC UA Part 4, Section 5.13
            SupportedMessage::CreateSubscriptionRequest(request) => {
                self.validate_service_request(message, CREATE_SUBSCRIPTION_COUNT, |session, _| {
                    Some(self.subscription_service.create_subscription(
                        server_state,
                        session,
                        request,
                    ))
                })
            }
            SupportedMessage::ModifySubscriptionRequest(request) => {
                self.validate_service_request(message, MODIFY_SUBSCRIPTION_COUNT, |session, _| {
                    Some(self.subscription_service.modify_subscription(
                        server_state,
                        session,
                        request,
                    ))
                })
            }
            SupportedMessage::SetPublishingModeRequest(request) => {
                self.validate_service_request(message, SET_PUBLISHING_MODE_COUNT, |session, _| {
                    Some(
                        self.subscription_service
                            .set_publishing_mode(session, request),
                    )
                })
            }
            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                self.validate_service_request(message, DELETE_SUBSCRIPTIONS_COUNT, |session, _| {
                    Some(
                        self.subscription_service
                            .delete_subscriptions(session, request),
                    )
                })
            }
            SupportedMessage::TransferSubscriptionsRequest(request) => self
                .validate_service_request(message, TRANSFER_SUBSCRIPTIONS_COUNT, |session, _| {
                    Some(
                        self.subscription_service
                            .transfer_subscriptions(session, request),
                    )
                }),
            SupportedMessage::PublishRequest(request) => {
                self.validate_service_request(message, "", |session, _| {
                    // TODO publish request diagnostics have to be done asynchronously too

                    // Unlike other calls which return immediately, this one is asynchronous - the
                    // request is queued and the response will come back out of sequence some time in
                    // the future.
                    self.subscription_service.async_publish(
                        &Utc::now(),
                        session,
                        address_space,
                        request_id,
                        request,
                    )
                })
            }
            SupportedMessage::RepublishRequest(request) => {
                self.validate_service_request(message, REPUBLISH_COUNT, |session, _| {
                    Some(self.subscription_service.republish(session, request))
                })
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

    /// Tests if this request should be rejected because of a session timeout
    fn is_session_timed_out(
        session: Arc<RwLock<Session>>,
        request_header: &RequestHeader,
        now: DateTimeUtc,
    ) -> Result<(), SupportedMessage> {
        let mut session = trace_write_lock!(session);
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

    /// Test if the session is activated
    fn is_session_activated(
        &self,
        session: Arc<RwLock<Session>>,
        request_header: &RequestHeader,
    ) -> Result<(), SupportedMessage> {
        let session = trace_read_lock!(session);
        if !session.is_activated() {
            error!("Session is not activated so request fails");
            Err(ServiceFault::new(request_header, StatusCode::BadSessionNotActivated).into())
        } else {
            // Ensure the session's secure channel
            let secure_channel_id = {
                let secure_channel = trace_read_lock!(self.secure_channel);
                secure_channel.secure_channel_id()
            };
            if secure_channel_id != session.secure_channel_id() {
                error!(
                    "service call rejected as secure channel id does not match that on the session"
                );
                Err(ServiceFault::new(request_header, StatusCode::BadSessionIdInvalid).into())
            } else {
                Ok(())
            }
        }
    }

    /// Validate the security of the call
    fn validate_activate_service_request<F>(
        &self,
        request: &SupportedMessage,
        diagnostic_key: &'static str,
        action: F,
    ) -> Option<SupportedMessage>
    where
        F: FnOnce(Arc<RwLock<Session>>) -> SupportedMessage,
    {
        let now = Utc::now();
        let request_header = request.request_header();

        // Look up the session from a map to see if it exists
        let session = {
            let session_manager = trace_read_lock!(self.session_manager);
            session_manager.find_session_by_token(&request_header.authentication_token)
        };
        if let Some(session) = session {
            let (response, authorized) = if let Err(response) =
                Self::is_session_timed_out(session.clone(), request_header, now)
            {
                (response, false)
            } else {
                let response = action(session.clone());
                let mut session = trace_write_lock!(session);
                session.set_last_service_request_timestamp(now);
                (response, true)
            };
            Self::diag_service_response(session, authorized, &response, diagnostic_key);
            Some(response)
        } else {
            warn!(
                "validate_activate_service_request, session not found for token {}",
                &request_header.authentication_token
            );
            Some(ServiceFault::new(request_header, StatusCode::BadSessionIdInvalid).into())
        }
    }

    /// Validate the security of the call and also for an active session
    fn validate_service_request<F>(
        &self,
        request: &SupportedMessage,
        diagnostic_key: &'static str,
        action: F,
    ) -> Option<SupportedMessage>
    where
        F: FnOnce(Arc<RwLock<Session>>, Arc<RwLock<SessionManager>>) -> Option<SupportedMessage>,
    {
        let now = Utc::now();
        let request_header = request.request_header();
        // Look up the session from a map to see if it exists
        let session_manager = self.session_manager.clone();
        let session = {
            let session_manager = trace_read_lock!(session_manager);
            session_manager.find_session_by_token(&request_header.authentication_token)
        };
        if let Some(session) = session {
            let (response, authorized) =
                if let Err(response) = self.is_session_activated(session.clone(), request_header) {
                    (Some(response), false)
                } else if let Err(response) =
                    Self::is_session_timed_out(session.clone(), request_header, now)
                {
                    (Some(response), false)
                } else {
                    let response = action(session.clone(), session_manager);
                    let mut session = trace_write_lock!(session);
                    session.set_last_service_request_timestamp(now);
                    (response, true)
                };
            // Async calls may not return a response here
            response.map(|response| {
                Self::diag_service_response(session, authorized, &response, diagnostic_key);
                response
            })
        } else {
            Some(ServiceFault::new(request_header, StatusCode::BadSessionIdInvalid).into())
        }
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
        let session = trace_read_lock!(session);
        let session_diagnostics = session.session_diagnostics();
        let mut session_diagnostics = trace_write_lock!(session_diagnostics);
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
