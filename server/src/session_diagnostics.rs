use std::collections::HashMap;

use opcua_types::{
    service_types::ServiceCounterDataType,
};

pub(crate) struct SessionDiagnostics {
    service_counters: HashMap<&'static str, ServiceCounterDataType>
}

impl Default for SessionDiagnostics {
    fn default() -> Self {
        Self {
            service_counters: HashMap::new()
        }
    }
}

impl SessionDiagnostics {
    pub(crate) fn service_success(&mut self, diagnostic_key: &'static str) {
        if let Some(counter) = self.service_counters.get_mut(diagnostic_key) {
            counter.success();
        } else {
            let mut counter = ServiceCounterDataType::default();
            counter.success();
            self.service_counters.insert(diagnostic_key, counter);
        }
    }

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

pub(crate) const READ_COUNT: &'static str = "ReadCount";
pub(crate) const HISTORY_READ_COUNT: &'static str = "HistoryReadCount";
pub(crate) const WRITE_COUNT: &'static str = "WriteCount";
pub(crate) const HISTORY_UPDATE_COUNT: &'static str = "HistoryUpdateCount";
pub(crate) const CALL_COUNT: &'static str = "CallCount";
pub(crate) const CREATE_MONITORED_ITEMS_COUNT: &'static str = "CreateMonitoredItemsCount";
pub(crate) const MODIFY_MONITORED_ITEMS_COUNT: &'static str = "ModifyMonitoredItemsCount";
pub(crate) const SET_MONITORING_MODE_COUNT: &'static str = "SetMonitoringModeCount";
pub(crate) const SET_TRIGGERING_COUNT: &'static str = "SetTriggeringCount";
pub(crate) const DELETE_MONITORED_ITEMS_COUNT: &'static str = "DeleteMonitoredItemsCount";
pub(crate) const CREATE_SUBSCRIPTION_COUNT: &'static str = "CreateSubscriptionCount";
pub(crate) const MODIFY_SUBSCRIPTION_COUNT: &'static str = "ModifySubscriptionCount";
pub(crate) const SET_PUBLISHING_MODE_COUNT: &'static str = "SetPublishingModeCount";
pub(crate) const PUBLISH_COUNT: &'static str = "PublishCount";
pub(crate) const REPUBLISH_COUNT: &'static str = "RepublishCount";
pub(crate) const TRANSFER_SUBSCRIPTIONS_COUNT: &'static str = "TransferSubscriptionsCount";
pub(crate) const DELETE_SUBSCRIPTIONS_COUNT: &'static str = "DeleteSubscriptionsCount";
pub(crate) const ADD_NODES_COUNT: &'static str = "AddNodesCount";
pub(crate) const ADD_REFERENCES_COUNT: &'static str = "AddReferencesCount";
pub(crate) const DELETE_NODES_COUNT: &'static str = "DeleteNodesCount";
pub(crate) const DELETE_REFERENCES_COUNT: &'static str = "DeleteReferencesCount";
pub(crate) const BROWSE_COUNT: &'static str = "BrowseCount";
pub(crate) const BROWSE_NEXT_COUNT: &'static str = "BrowseNextCount";
pub(crate) const TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_COUNT: &'static str = "TranslateBrowsePathsToNodeIdsCount";
//pub(crate) const QUERY_FIRST_COUNT: &'static str = "QueryFirstCount";
//pub(crate) const QUERY_NEXT_COUNT: &'static str = "QueryNextCount";
pub(crate) const REGISTER_NODES_COUNT: &'static str = "RegisterNodesCount";
pub(crate) const UNREGISTER_NODES_COUNT: &'static str = "UnregisterNodesCount";
