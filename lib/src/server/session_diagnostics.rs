use std::collections::HashMap;

use crate::types::{node_ids::ObjectTypeId, service_types::ServiceCounterDataType};

use super::{
    address_space::{address_space::AddressSpace, object::ObjectBuilder},
    session::Session,
};

/// This object tracks session diagnostics for exposure through the address space

pub(crate) struct SessionDiagnostics {
    total_request_count: u32,
    unauthorized_request_count: u32,
    service_counters: HashMap<&'static str, ServiceCounterDataType>,
}

impl Default for SessionDiagnostics {
    fn default() -> Self {
        Self {
            total_request_count: 0,
            unauthorized_request_count: 0,
            service_counters: HashMap::new(),
        }
    }
}

impl SessionDiagnostics {
    /// Registers a session object
    pub(crate) fn register_session(&self, session: &Session, address_space: &mut AddressSpace) {
        // TODO SessionDiagnosticsObjectType

        let session_id = session.session_id();
        debug!("register_session for session id {}", session_id);

        debug!("Adding an object node for the session id {}", session_id);
        let _ = ObjectBuilder::new(
            session_id,
            format!("{}", session_id),
            format!("{}", session_id),
        )
        .has_type_definition(ObjectTypeId::SessionDiagnosticsObjectType)
        .insert(address_space);

        // Now add variables
        /*
             12816 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics),
           12817 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_SessionId),
           12818 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_SessionName),
           12819 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ClientDescription),
           12820 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ServerUri),
           12821 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_EndpointUrl),
           12822 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_LocaleIds),
           12823 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ActualSessionTimeout),
           12824 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_MaxResponseMessageSize),
           12825 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ClientConnectionTime),
           12826 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ClientLastContactTime),
           12827 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_CurrentSubscriptionsCount),
           12828 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_CurrentMonitoredItemsCount),
           12829 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_CurrentPublishRequestsInQueue),

           12830 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_TotalRequestCount),
           12831 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_UnauthorizedRequestCount),

           12832 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ReadCount),
           12833 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_HistoryReadCount),
           12834 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_WriteCount),
           12835 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_HistoryUpdateCount),
           12836 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_CallCount),
           12837 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_CreateMonitoredItemsCount),
           12838 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ModifyMonitoredItemsCount),
           12839 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_SetMonitoringModeCount),
           12840 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_SetTriggeringCount),
           12841 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_DeleteMonitoredItemsCount),
           12842 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_CreateSubscriptionCount),
           12843 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_ModifySubscriptionCount),
           12844 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_SetPublishingModeCount),
           12845 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_PublishCount),
           12846 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_RepublishCount),
           12847 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_TransferSubscriptionsCount),
           12848 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_DeleteSubscriptionsCount),
           12849 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_AddNodesCount),
           12850 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_AddReferencesCount),
           12851 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_DeleteNodesCount),
           12852 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_DeleteReferencesCount),
           12853 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_BrowseCount),
           12854 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_BrowseNextCount),
           12855 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_TranslateBrowsePathsToNodeIdsCount),
           12856 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_QueryFirstCount),
           12857 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_QueryNextCount),
           12858 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_RegisterNodesCount),
           12859 => Ok(VariableId::SessionDiagnosticsArrayType_SessionDiagnostics_UnregisterNodesCount),
        */

        // Browse name shall be session name
        // session id is the nodeid

        // SessionDiagnostics - SessionDiagnosticsDataType
        //   SessionId - NodeId
        //   SessionName - String
        //   ClientDescription - Application Description
        //   ServerUri - String
        //   EndpointUrl - String
        //   LocaleId - LocaleId[]
        //   MaxResponseMessageSize - UInt32
        //   ActualSessionTimeout - Duration
        //   ClientConnectionTime - UtcTime
        //   ClientLastContactTime - UtcTime
        //   CurrentSubscriptionsCount - UInt32
        //   CurrentMonitoredItemsCount - UInt32
        //   CurrentPublishRequestsInQueue - UInt32
        //   TotalRequestCount - ServiceCounterData
        //   UnauthorizedRequestCount - UInt32
        //   ReadCount - ServiceCounterData
        //   HistoryReadCount - ServiceCounterData
        //   WriteCount - ServiceCounterData
        //   HistoryUpdateCount
        // SessionSecurityDiagnostics - SessionSecurityDiagnosticDataType
        // SeubscriptionDiagnosticsArray - SubscriptionDiagnosticsArray
    }

    /// Deregisters a session object
    pub(crate) fn deregister_session(&self, session: &Session, address_space: &mut AddressSpace) {
        address_space.delete(session.session_id(), true);
    }

    /// Called on every request
    pub(crate) fn request(&mut self) {
        self.total_request_count += 1;
    }

    /// Called on an authorized request
    pub(crate) fn unauthorized_request(&mut self) {
        self.unauthorized_request_count += 1;
        self.total_request_count += 1;
    }

    /// Fetches a snapshot of the current service counter value
    pub(crate) fn service_counter(
        &mut self,
        diagnostic_key: &'static str,
    ) -> ServiceCounterDataType {
        if let Some(counter) = self.service_counters.get_mut(diagnostic_key) {
            counter.clone()
        } else {
            ServiceCounterDataType::default()
        }
    }

    /// Increments the service counter for a successful service call
    pub(crate) fn service_success(&mut self, diagnostic_key: &'static str) {
        if let Some(counter) = self.service_counters.get_mut(diagnostic_key) {
            counter.success();
        } else {
            let mut counter = ServiceCounterDataType::default();
            counter.success();
            self.service_counters.insert(diagnostic_key, counter);
        }
    }

    /// Increments the service counter for a failed service call
    pub(crate) fn service_error(&mut self, diagnostic_key: &'static str) {
        if let Some(counter) = self.service_counters.get_mut(diagnostic_key) {
            counter.error();
        } else {
            let mut counter = ServiceCounterDataType::default();
            counter.error();
            self.service_counters.insert(diagnostic_key, counter);
        }
    }
}

pub(crate) const READ_COUNT: &str = "ReadCount";
pub(crate) const HISTORY_READ_COUNT: &str = "HistoryReadCount";
pub(crate) const WRITE_COUNT: &str = "WriteCount";
pub(crate) const HISTORY_UPDATE_COUNT: &str = "HistoryUpdateCount";
pub(crate) const CALL_COUNT: &str = "CallCount";
pub(crate) const CREATE_MONITORED_ITEMS_COUNT: &str = "CreateMonitoredItemsCount";
pub(crate) const MODIFY_MONITORED_ITEMS_COUNT: &str = "ModifyMonitoredItemsCount";
pub(crate) const SET_MONITORING_MODE_COUNT: &str = "SetMonitoringModeCount";
pub(crate) const SET_TRIGGERING_COUNT: &str = "SetTriggeringCount";
pub(crate) const DELETE_MONITORED_ITEMS_COUNT: &str = "DeleteMonitoredItemsCount";
pub(crate) const CREATE_SUBSCRIPTION_COUNT: &str = "CreateSubscriptionCount";
pub(crate) const MODIFY_SUBSCRIPTION_COUNT: &str = "ModifySubscriptionCount";
pub(crate) const SET_PUBLISHING_MODE_COUNT: &str = "SetPublishingModeCount";
//pub(crate) const PUBLISH_COUNT: &str = "PublishCount";
pub(crate) const REPUBLISH_COUNT: &str = "RepublishCount";
pub(crate) const TRANSFER_SUBSCRIPTIONS_COUNT: &str = "TransferSubscriptionsCount";
pub(crate) const DELETE_SUBSCRIPTIONS_COUNT: &str = "DeleteSubscriptionsCount";
pub(crate) const ADD_NODES_COUNT: &str = "AddNodesCount";
pub(crate) const ADD_REFERENCES_COUNT: &str = "AddReferencesCount";
pub(crate) const DELETE_NODES_COUNT: &str = "DeleteNodesCount";
pub(crate) const DELETE_REFERENCES_COUNT: &str = "DeleteReferencesCount";
pub(crate) const BROWSE_COUNT: &str = "BrowseCount";
pub(crate) const BROWSE_NEXT_COUNT: &str = "BrowseNextCount";
pub(crate) const TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_COUNT: &str =
    "TranslateBrowsePathsToNodeIdsCount";
//pub(crate) const QUERY_FIRST_COUNT: &str = "QueryFirstCount";
//pub(crate) const QUERY_NEXT_COUNT: &str = "QueryNextCount";
pub(crate) const REGISTER_NODES_COUNT: &str = "RegisterNodesCount";
pub(crate) const UNREGISTER_NODES_COUNT: &str = "UnregisterNodesCount";
