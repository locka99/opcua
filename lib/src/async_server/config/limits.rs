#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Limits {
    /// Max array length in elements
    #[serde(default = "defaults::max_array_length")]
    pub max_array_length: usize,
    /// Max string length in characters
    #[serde(default = "defaults::max_string_length")]
    pub max_string_length: usize,
    /// Max bytestring length in bytes
    #[serde(default = "defaults::max_byte_string_length")]
    pub max_byte_string_length: usize,
    /// Maximum message length in bytes
    #[serde(default = "defaults::max_message_size")]
    pub max_message_size: usize,
    /// Maximum chunk count
    #[serde(default = "defaults::max_chunk_count")]
    pub max_chunk_count: usize,
    /// Send buffer size in bytes
    #[serde(default = "defaults::send_buffer_size")]
    pub send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[serde(default = "defaults::receive_buffer_size")]
    pub receive_buffer_size: usize,
    /// Limits specific to subscriptions.
    #[serde(default)]
    pub subscriptions: SubscriptionLimits,
    /// Limits on service calls.
    #[serde(default)]
    pub operational: OperationalLimits,
    /// Maximum number of browse continuation points per session.
    #[serde(default = "defaults::max_browse_continuation_points")]
    pub max_browse_continuation_points: usize,
    /// Maximum number of history continuation points per session.
    #[serde(default = "defaults::max_history_continuation_points")]
    pub max_history_continuation_points: usize,
    /// Maximum number of query continuation points per session.
    #[serde(default = "defaults::max_query_continuation_points")]
    pub max_query_continuation_points: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_array_length: defaults::max_array_length(),
            max_string_length: defaults::max_string_length(),
            max_byte_string_length: defaults::max_byte_string_length(),
            max_message_size: defaults::max_message_size(),
            max_chunk_count: defaults::max_chunk_count(),
            send_buffer_size: defaults::send_buffer_size(),
            receive_buffer_size: defaults::receive_buffer_size(),
            subscriptions: Default::default(),
            max_browse_continuation_points: defaults::max_browse_continuation_points(),
            max_history_continuation_points: defaults::max_history_continuation_points(),
            max_query_continuation_points: defaults::max_query_continuation_points(),
            operational: OperationalLimits::default(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionLimits {
    #[serde(default = "defaults::max_subscriptions_per_session")]
    pub max_subscriptions_per_session: usize,
    #[serde(default = "defaults::max_pending_publish_requests")]
    pub max_pending_publish_requests: usize,
    #[serde(default = "defaults::max_publish_requests_per_subscription")]
    pub max_publish_requests_per_subscription: usize,
    /// Specifies the minimum sampling interval for this server in seconds.
    #[serde(default = "defaults::min_sampling_interval_ms")]
    pub min_sampling_interval_ms: f64,
    /// Specifies the minimum publishing interval for this server in seconds.
    #[serde(default = "defaults::min_publishing_interval_ms")]
    pub min_publishing_interval_ms: f64,
    #[serde(default = "defaults::max_keep_alive_count")]
    pub max_keep_alive_count: u32,
    #[serde(default = "defaults::default_keep_alive_count")]
    pub default_keep_alive_count: u32,
    /// Maximum number of monitored items per subscription, 0 for no limit
    #[serde(default = "defaults::max_monitored_items_per_sub")]
    pub max_monitored_items_per_sub: usize,
    /// Maximum number of values in a monitored item queue
    #[serde(default = "defaults::max_monitored_item_queue_size")]
    pub max_monitored_item_queue_size: usize,
    /// Maximum lifetime count (3 times as large as max keep alive)
    #[serde(default = "defaults::max_lifetime_count")]
    pub max_lifetime_count: u32,
    /// Maximum number of notifications per publish message.
    #[serde(default = "defaults::max_notifications_per_publish")]
    pub max_notifications_per_publish: u64,
    /// Maximum number of queued notifications per subscription. 0 for unlimited.
    #[serde(default = "defaults::max_queued_notifications")]
    pub max_queued_notifications: usize,
}

impl Default for SubscriptionLimits {
    fn default() -> Self {
        Self {
            max_subscriptions_per_session: defaults::max_subscriptions_per_session(),
            max_pending_publish_requests: defaults::max_pending_publish_requests(),
            max_publish_requests_per_subscription: defaults::max_publish_requests_per_subscription(
            ),
            min_sampling_interval_ms: defaults::min_sampling_interval_ms(),
            min_publishing_interval_ms: defaults::min_publishing_interval_ms(),
            max_keep_alive_count: defaults::max_keep_alive_count(),
            default_keep_alive_count: defaults::default_keep_alive_count(),
            max_monitored_items_per_sub: defaults::max_monitored_items_per_sub(),
            max_monitored_item_queue_size: defaults::max_monitored_item_queue_size(),
            max_lifetime_count: defaults::max_lifetime_count(),
            max_notifications_per_publish: defaults::max_notifications_per_publish(),
            max_queued_notifications: defaults::max_queued_notifications(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct OperationalLimits {
    #[serde(default = "defaults::max_nodes_per_translate_browse_paths_to_node_ids")]
    pub max_nodes_per_translate_browse_paths_to_node_ids: usize,
    #[serde(default = "defaults::max_nodes_per_read")]
    pub max_nodes_per_read: usize,
    #[serde(default = "defaults::max_nodes_per_write")]
    pub max_nodes_per_write: usize,
    #[serde(default = "defaults::max_nodes_per_method_call")]
    pub max_nodes_per_method_call: usize,
    #[serde(default = "defaults::max_nodes_per_browse")]
    pub max_nodes_per_browse: usize,
    #[serde(default = "defaults::max_nodes_per_register_nodes")]
    pub max_nodes_per_register_nodes: usize,
    #[serde(default = "defaults::max_monitored_items_per_call")]
    pub max_monitored_items_per_call: usize,
    #[serde(default = "defaults::max_nodes_per_history_read_data")]
    pub max_nodes_per_history_read_data: usize,
    #[serde(default = "defaults::max_nodes_per_history_read_events")]
    pub max_nodes_per_history_read_events: usize,
    #[serde(default = "defaults::max_nodes_per_history_update")]
    pub max_nodes_per_history_update: usize,
    #[serde(default = "defaults::max_references_per_browse_node")]
    pub max_references_per_browse_node: usize,
    #[serde(default = "defaults::max_node_descs_per_query")]
    pub max_node_descs_per_query: usize,
    #[serde(default = "defaults::max_data_sets_query_return")]
    pub max_data_sets_query_return: usize,
    #[serde(default = "defaults::max_references_query_return")]
    pub max_references_query_return: usize,
    #[serde(default = "defaults::max_nodes_per_node_management")]
    pub max_nodes_per_node_management: usize,
    #[serde(default = "defaults::max_references_per_references_management")]
    pub max_references_per_references_management: usize,
    #[serde(default = "defaults::max_subscriptions_per_call")]
    pub max_subscriptions_per_call: usize,
}

impl Default for OperationalLimits {
    fn default() -> Self {
        Self {
            max_nodes_per_translate_browse_paths_to_node_ids:
                defaults::max_nodes_per_translate_browse_paths_to_node_ids(),
            max_nodes_per_read: defaults::max_nodes_per_read(),
            max_nodes_per_write: defaults::max_nodes_per_write(),
            max_nodes_per_method_call: defaults::max_nodes_per_method_call(),
            max_nodes_per_browse: defaults::max_nodes_per_browse(),
            max_nodes_per_register_nodes: defaults::max_nodes_per_register_nodes(),
            max_monitored_items_per_call: defaults::max_monitored_items_per_call(),
            max_nodes_per_history_read_data: defaults::max_nodes_per_history_read_data(),
            max_nodes_per_history_read_events: defaults::max_nodes_per_history_read_events(),
            max_nodes_per_history_update: defaults::max_nodes_per_history_update(),
            max_references_per_browse_node: defaults::max_references_per_browse_node(),
            max_node_descs_per_query: defaults::max_node_descs_per_query(),
            max_data_sets_query_return: defaults::max_data_sets_query_return(),
            max_references_query_return: defaults::max_references_query_return(),
            max_nodes_per_node_management: defaults::max_nodes_per_node_management(),
            max_references_per_references_management:
                defaults::max_references_per_references_management(),
            max_subscriptions_per_call: defaults::max_subscriptions_per_call(),
        }
    }
}

mod defaults {
    use crate::async_server::constants;
    pub fn max_array_length() -> usize {
        crate::types::constants::MAX_ARRAY_LENGTH
    }
    pub fn max_string_length() -> usize {
        crate::types::constants::MAX_STRING_LENGTH
    }
    pub fn max_byte_string_length() -> usize {
        crate::types::constants::MAX_BYTE_STRING_LENGTH
    }
    pub fn max_message_size() -> usize {
        crate::types::constants::MAX_MESSAGE_SIZE
    }
    pub fn max_chunk_count() -> usize {
        crate::types::constants::MAX_CHUNK_COUNT
    }
    pub fn send_buffer_size() -> usize {
        constants::SEND_BUFFER_SIZE
    }
    pub fn receive_buffer_size() -> usize {
        constants::RECEIVE_BUFFER_SIZE
    }
    pub fn max_browse_continuation_points() -> usize {
        constants::MAX_BROWSE_CONTINUATION_POINTS
    }
    pub fn max_history_continuation_points() -> usize {
        constants::MAX_HISTORY_CONTINUATION_POINTS
    }
    pub fn max_query_continuation_points() -> usize {
        constants::MAX_QUERY_CONTINUATION_POINTS
    }

    pub fn max_subscriptions_per_session() -> usize {
        constants::MAX_SUBSCRIPTIONS_PER_SESSION
    }
    pub fn max_pending_publish_requests() -> usize {
        constants::MAX_PENDING_PUBLISH_REQUESTS
    }
    pub fn max_publish_requests_per_subscription() -> usize {
        constants::MAX_PUBLISH_REQUESTS_PER_SUBSCRIPTION
    }
    pub fn min_sampling_interval_ms() -> f64 {
        constants::MIN_SAMPLING_INTERVAL_MS
    }
    pub fn min_publishing_interval_ms() -> f64 {
        constants::MIN_PUBLISHING_INTERVAL_MS
    }
    pub fn max_keep_alive_count() -> u32 {
        constants::MAX_KEEP_ALIVE_COUNT
    }
    pub fn default_keep_alive_count() -> u32 {
        constants::DEFAULT_KEEP_ALIVE_COUNT
    }
    pub fn max_monitored_items_per_sub() -> usize {
        constants::DEFAULT_MAX_MONITORED_ITEMS_PER_SUB
    }
    pub fn max_monitored_item_queue_size() -> usize {
        constants::MAX_DATA_CHANGE_QUEUE_SIZE
    }
    pub fn max_lifetime_count() -> u32 {
        constants::MAX_KEEP_ALIVE_COUNT * 3
    }
    pub fn max_notifications_per_publish() -> u64 {
        constants::MAX_NOTIFICATIONS_PER_PUBLISH
    }
    pub fn max_queued_notifications() -> usize {
        constants::MAX_QUEUED_NOTIFICATIONS
    }

    pub fn max_nodes_per_translate_browse_paths_to_node_ids() -> usize {
        constants::MAX_NODES_PER_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS
    }
    pub fn max_nodes_per_read() -> usize {
        constants::MAX_NODES_PER_READ
    }
    pub fn max_nodes_per_write() -> usize {
        constants::MAX_NODES_PER_WRITE
    }
    pub fn max_nodes_per_method_call() -> usize {
        constants::MAX_NODES_PER_METHOD_CALL
    }
    pub fn max_nodes_per_browse() -> usize {
        constants::MAX_NODES_PER_BROWSE
    }
    pub fn max_nodes_per_register_nodes() -> usize {
        constants::MAX_NODES_PER_REGISTER_NODES
    }
    pub fn max_monitored_items_per_call() -> usize {
        constants::MAX_MONITORED_ITEMS_PER_CALL
    }
    pub fn max_nodes_per_history_read_data() -> usize {
        constants::MAX_NODES_PER_HISTORY_READ_DATA
    }
    pub fn max_nodes_per_history_read_events() -> usize {
        constants::MAX_NODES_PER_HISTORY_READ_EVENTS
    }
    pub fn max_nodes_per_history_update() -> usize {
        constants::MAX_NODES_PER_HISTORY_UPDATE
    }
    pub fn max_references_per_browse_node() -> usize {
        constants::MAX_REFERENCES_PER_BROWSE_NODE
    }
    pub fn max_node_descs_per_query() -> usize {
        constants::MAX_NODE_DESCS_PER_QUERY
    }
    pub fn max_data_sets_query_return() -> usize {
        constants::MAX_DATA_SETS_QUERY_RETURN
    }
    pub fn max_references_query_return() -> usize {
        constants::MAX_REFERENCES_QUERY_RETURN
    }
    pub fn max_nodes_per_node_management() -> usize {
        constants::MAX_NODES_PER_NODE_MANAGEMENT
    }
    pub fn max_references_per_references_management() -> usize {
        constants::MAX_REFERENCES_PER_REFERENCE_MANAGEMENT
    }
    pub fn max_subscriptions_per_call() -> usize {
        constants::MAX_SUBSCRIPTIONS_PER_CALL
    }
}
