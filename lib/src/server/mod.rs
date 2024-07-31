pub mod address_space;
pub mod authenticator;
mod builder;
mod config;
mod discovery;
mod events;
mod identity_token;
mod info;
pub mod node_manager;
mod server;
mod server_handle;
mod session;
mod subscriptions;
mod transport;

pub use builder::ServerBuilder;
pub use config::*;
pub use events::*;
pub use server::Server;
pub use server_handle::ServerHandle;
pub use session::continuation_points::ContinuationPoint;
pub use subscriptions::{
    CreateMonitoredItem, MonitoredItem, MonitoredItemHandle, SessionSubscriptions, Subscription,
    SubscriptionCache, SubscriptionState,
};

/// Contains constaints for default configuration values.
/// These are for the most part possible to override through server configuration.
pub mod constants {
    /// The default hello timeout period in seconds
    pub const DEFAULT_HELLO_TIMEOUT_SECONDS: u32 = 5;
    /// Default OPC UA server port for this implementation
    pub const DEFAULT_RUST_OPC_UA_SERVER_PORT: u16 = 4855;
    /// Default maximum number of monitored items per subscription
    pub const DEFAULT_MAX_MONITORED_ITEMS_PER_SUB: usize = 1000;
    /// Default, well known address for TCP discovery server
    pub const DEFAULT_DISCOVERY_SERVER_URL: &str = "opc.tcp://localhost:4840/UADiscovery";

    // Internally controlled values

    /// The polling interval in millis on subscriptions and monitored items. The more
    /// fine-grained this is, the more often subscriptions will be checked for changes. The minimum
    /// publish interval cannot be less than this.
    pub const SUBSCRIPTION_TIMER_RATE_MS: u64 = 100;
    /// Minimum publishing interval for subscriptions
    pub const MIN_PUBLISHING_INTERVAL_MS: f64 = SUBSCRIPTION_TIMER_RATE_MS as f64;
    /// Minimum sampling interval on monitored items
    pub const MIN_SAMPLING_INTERVAL_MS: f64 = SUBSCRIPTION_TIMER_RATE_MS as f64;
    /// Maximum data change queue allowed by clients on monitored items
    pub const MAX_DATA_CHANGE_QUEUE_SIZE: usize = 10;
    /// Maximum time in MS that a session can be inactive before a timeout
    pub const MAX_SESSION_TIMEOUT: u64 = 60_000;
    /// Default keep alive count
    pub const DEFAULT_KEEP_ALIVE_COUNT: u32 = 10;
    /// Maximum keep alive count
    pub const MAX_KEEP_ALIVE_COUNT: u32 = 30000;
    /// Maximum browse continuation points
    pub const MAX_BROWSE_CONTINUATION_POINTS: usize = 5000;
    /// Maximum history continuation points
    pub const MAX_HISTORY_CONTINUATION_POINTS: usize = 500;
    /// Maximum query continuation points
    pub const MAX_QUERY_CONTINUATION_POINTS: usize = 500;

    /// Maximum number of nodes in a TranslateBrowsePathsToNodeIdsRequest
    pub const MAX_NODES_PER_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS: usize = 100;
    /// Maximum number of ReadValueIds in a Read request.
    pub const MAX_NODES_PER_READ: usize = 10000;
    /// Maximum number of WriteValues in a Write request.
    pub const MAX_NODES_PER_WRITE: usize = 10000;
    /// Maximum number of method calls in a Call request.
    pub const MAX_NODES_PER_METHOD_CALL: usize = 100;
    /// Maximum number of nodes in a Browse or BrowseNext request.
    pub const MAX_NODES_PER_BROWSE: usize = 1000;
    /// Maximum number of nodes per register/deregister request.
    pub const MAX_NODES_PER_REGISTER_NODES: usize = 1000;
    /// Maximum number of nodes per node manaument operation
    pub const MAX_NODES_PER_NODE_MANAGEMENT: usize = 1000;
    /// Maximum number of references per reference management operation.
    pub const MAX_REFERENCES_PER_REFERENCE_MANAGEMENT: usize = 1000;
    /// Maximum number of monitored items per operation.
    pub const MAX_MONITORED_ITEMS_PER_CALL: usize = 1000;
    /// Maximum number of nodes per history read for data.
    pub const MAX_NODES_PER_HISTORY_READ_DATA: usize = 100;
    /// Maixmum number of nodes per history read for events.
    pub const MAX_NODES_PER_HISTORY_READ_EVENTS: usize = 100;
    /// Maximum number of nodes per history update call. Not separate constants
    /// for data and events because update may mix the two.
    pub const MAX_NODES_PER_HISTORY_UPDATE: usize = 100;
    /// Maximum number of node descriptions per query call.
    pub const MAX_NODE_DESCS_PER_QUERY: usize = 100;
    /// Maximum number of references to return per query data set.
    pub const MAX_REFERENCES_QUERY_RETURN: usize = 100;
    /// Maximum number of data sets to return per query.
    pub const MAX_DATA_SETS_QUERY_RETURN: usize = 1000;
    /// Maximum number of subscriptions per subscription management call, where applicable.
    pub const MAX_SUBSCRIPTIONS_PER_CALL: usize = 10;

    /// Maximum number of sessions active on a server.
    pub const MAX_SESSIONS: usize = 20;
    /// Maximum number of references per node during Browse or BrowseNext.
    pub const MAX_REFERENCES_PER_BROWSE_NODE: usize = 1000;

    /// Maximum number of subscriptions per session.
    pub const MAX_SUBSCRIPTIONS_PER_SESSION: usize = 10;
    /// Maximum number of pending publish requests per session before further requests are rejected.
    pub const MAX_PENDING_PUBLISH_REQUESTS: usize = 20;
    /// Maximum number of pending publish requsts per subscription. The smaller of this * number of subscriptions
    /// and max_pending_publish_requests is used.
    pub const MAX_PUBLISH_REQUESTS_PER_SUBSCRIPTION: usize = 4;

    /// Default publish timeout in milliseconds.
    pub const DEFAULT_PUBLISH_TIMEOUT_MS: u64 = 30000;
    /// Maximum number of notifications per publish, can be set lower by the client.
    pub const MAX_NOTIFICATIONS_PER_PUBLISH: u64 = 0;
    /// Maximum number of queued notifications. Any notifications beyond this are dropped.
    pub const MAX_QUEUED_NOTIFICATIONS: usize = 20;

    /// Receive buffer size default.
    pub const RECEIVE_BUFFER_SIZE: usize = std::u16::MAX as usize;
    /// Send buffer size default.
    pub const SEND_BUFFER_SIZE: usize = std::u16::MAX as usize;
}
