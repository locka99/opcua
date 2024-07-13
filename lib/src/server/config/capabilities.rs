use crate::types::NodeId;

#[derive(Debug, Clone, Default)]
/// History capabilities.
/// As all history is implemented by custom node managers,
/// this should be set according to what your node managers support.
pub struct HistoryServerCapabilities {
    pub access_history_data: bool,
    pub access_history_events: bool,
    pub delete_at_time: bool,
    pub delete_event: bool,
    pub delete_raw: bool,
    pub insert_annotation: bool,
    pub insert_data: bool,
    pub insert_event: bool,
    pub max_return_data_values: u32,
    pub max_return_event_values: u32,
    pub replace_data: bool,
    pub replace_event: bool,
    pub server_timestamp_supported: bool,
    pub update_data: bool,
    pub update_event: bool,
    /// Supported history aggregates
    pub aggregates: Vec<NodeId>,
}

#[derive(Debug, Clone, Default)]
/// Server capabilities object.
pub struct ServerCapabilities {
    pub history: HistoryServerCapabilities,
    pub profiles: Vec<String>,
}
