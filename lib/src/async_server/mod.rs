pub mod address_space;
pub mod authenticator;
mod builder;
mod config;
mod events;
mod identity_token;
mod info;
pub mod node_manager;
mod server_core;
mod server_handle;
mod session;
mod subscriptions;
mod transport;

pub use builder::ServerBuilder;
pub use config::*;
pub use events::*;
pub use server_core::ServerCore;
pub use server_handle::ServerHandle;
pub use session::continuation_points::ContinuationPoint;
pub use subscriptions::{
    CreateMonitoredItem, MonitoredItem, MonitoredItemHandle, SessionSubscriptions, Subscription,
    SubscriptionCache, SubscriptionState,
};

pub mod constants {
    //! Provides constants that govern the internal workings of the server implementation.
    /// The default hello timeout period in seconds
    pub const DEFAULT_HELLO_TIMEOUT_SECONDS: u32 = 5;
    /// Default OPC UA server port for this implementation
    pub const DEFAULT_RUST_OPC_UA_SERVER_PORT: u16 = 4855;
    /// Default maximum number of subscriptions in a session
    pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 100;
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
    /// Interval to check for HELLO timeout in millis. This can be fairly coarse because it's not
    /// something that requires huge accuracy.
    pub const HELLO_TIMEOUT_POLL_MS: u64 = 500;
    /// Maximum time in MS that a session can be inactive before a timeout
    pub const MAX_SESSION_TIMEOUT: f64 = 60000f64;
    /// Maximum size in bytes that a request message is allowed to be
    pub const MAX_REQUEST_MESSAGE_SIZE: u32 = 32768;
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
    pub const MAX_NODES_PER_READ: usize = 10000;
    pub const MAX_NODES_PER_WRITE: usize = 10000;
    pub const MAX_NODES_PER_METHOD_CALL: usize = 100;
    pub const MAX_NODES_PER_BROWSE: usize = 1000;
    pub const MAX_NODES_PER_REGISTER_NODES: usize = 1000;
    /// Maximum number of nodes / references per node manaument operation
    pub const MAX_NODES_PER_NODE_MANAGEMENT: usize = 1000;
    pub const MAX_REFERENCES_PER_REFERENCE_MANAGEMENT: usize = 1000;
    pub const MAX_MONITORED_ITEMS_PER_CALL: usize = 1000;
    pub const MAX_NODES_PER_HISTORY_READ_DATA: usize = 100;
    pub const MAX_NODES_PER_HISTORY_READ_EVENTS: usize = 100;
    pub const MAX_NODES_PER_HISTORY_UPDATE: usize = 100;
    pub const MAX_NODE_DESCS_PER_QUERY: usize = 100;
    pub const MAX_REFERENCES_QUERY_RETURN: usize = 100;
    pub const MAX_DATA_SETS_QUERY_RETURN: usize = 1000;
    pub const MAX_SUBSCRIPTIONS_PER_CALL: usize = 10;

    pub const MAX_SESSIONS_PER_CONNECTION: usize = 5;

    pub const MAX_REFERENCES_PER_BROWSE_NODE: usize = 1000;

    pub const MAX_SUBSCRIPTIONS_PER_SESSION: usize = 10;
    pub const MAX_PENDING_PUBLISH_REQUESTS: usize = 20;
    pub const MAX_PUBLISH_REQUESTS_PER_SUBSCRIPTION: usize = 4;

    pub const DEFAULT_PUBLISH_TIMEOUT_MS: u64 = 30000;
    pub const MAX_NOTIFICATIONS_PER_PUBLISH: u64 = 0;
    pub const MAX_QUEUED_NOTIFICATIONS: usize = 20;

    pub const RECEIVE_BUFFER_SIZE: usize = std::u16::MAX as usize;
    pub const SEND_BUFFER_SIZE: usize = std::u16::MAX as usize;
}