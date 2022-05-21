use std::sync::Arc;

use crate::server::{
    prelude::*,
    services::{monitored_item::MonitoredItemService, subscription::SubscriptionService},
    session::Session,
    state::ServerState,
    tests::*,
};

struct ServiceTest {
    pub server_state: Arc<RwLock<ServerState>>,
    pub address_space: Arc<RwLock<AddressSpace>>,
    pub session: Arc<RwLock<Session>>,
    pub session_manager: Arc<RwLock<SessionManager>>,
}

impl ServiceTest {
    pub fn new() -> ServiceTest {
        Self::new_with_server(ServerBuilder::new_sample())
    }

    pub fn new_with_server(server_builder: ServerBuilder) -> ServiceTest {
        let server = server_builder.server().unwrap();
        let server_state = server.server_state();
        let address_space = server.address_space();
        let session = Arc::new(RwLock::new(Session::new(server_state.clone())));
        let session_manager = Arc::new(RwLock::new(SessionManager::default()));

        {
            let mut session_manager = trace_write_lock!(session_manager);
            session_manager.register_session(session.clone());
        }

        ServiceTest {
            server_state,
            address_space,
            session,
            session_manager,
        }
    }

    pub fn get_server_state_and_session(&self) -> (Arc<RwLock<ServerState>>, Arc<RwLock<Session>>) {
        (self.server_state.clone(), self.session.clone())
    }
}

fn make_request_header() -> RequestHeader {
    RequestHeader {
        authentication_token: NodeId::new(0, 99),
        timestamp: DateTime::now(),
        request_handle: 1,
        return_diagnostics: DiagnosticBits::empty(),
        audit_entry_id: UAString::null(),
        timeout_hint: 123456,
        additional_header: ExtensionObject::null(),
    }
}

fn var_name(idx: usize) -> String {
    format!("v{}", idx)
}

fn var_node_id(idx: usize) -> NodeId {
    NodeId::new(1, var_name(idx))
}

fn add_many_vars_to_address_space(
    address_space: Arc<RwLock<AddressSpace>>,
    vars_to_add: usize,
) -> (NodeId, Vec<NodeId>) {
    let mut address_space = trace_write_lock!(address_space);

    // Create a sample folder under objects folder
    let sample_folder_id = address_space
        .add_folder("Many Vars", "Many Vars", &NodeId::objects_folder_id())
        .unwrap();

    // Add as a bunch of sequential vars to the folder
    let node_ids: Vec<NodeId> = (0..vars_to_add)
        .map(|i| {
            let node_id = var_node_id(i);
            let _ = VariableBuilder::new(&node_id, var_name(i), "")
                .data_type(DataTypeId::Int32)
                .organized_by(&sample_folder_id)
                .value(i as i32)
                .insert(&mut address_space);
            node_id
        })
        .collect();

    (sample_folder_id, node_ids)
}

/// A helper that sets up a subscription service test
fn do_subscription_service_test<T>(f: T)
where
    T: FnOnce(
        Arc<RwLock<ServerState>>,
        Arc<RwLock<Session>>,
        Arc<RwLock<AddressSpace>>,
        SubscriptionService,
        MonitoredItemService,
    ),
{
    let st = ServiceTest::new();
    add_many_vars_to_address_space(st.address_space.clone(), 100);
    f(
        st.server_state.clone(),
        st.session.clone(),
        st.address_space.clone(),
        SubscriptionService::new(),
        MonitoredItemService::new(),
    );
}

/// Creates a blank subscription request
fn create_subscription_request(
    max_keep_alive_count: u32,
    lifetime_count: u32,
) -> CreateSubscriptionRequest {
    CreateSubscriptionRequest {
        request_header: RequestHeader::dummy(),
        requested_publishing_interval: 100f64,
        requested_lifetime_count: lifetime_count,
        requested_max_keep_alive_count: max_keep_alive_count,
        max_notifications_per_publish: 5,
        publishing_enabled: true,
        priority: 0,
    }
}

/// Creates a monitored item request
fn create_monitored_items_request<T>(
    subscription_id: u32,
    node_id: Vec<T>,
) -> CreateMonitoredItemsRequest
where
    T: Into<NodeId>,
{
    let items_to_create = Some(
        node_id
            .into_iter()
            .enumerate()
            .map(|i| {
                let node_id: NodeId = i.1.into();
                MonitoredItemCreateRequest {
                    item_to_monitor: node_id.into(),
                    monitoring_mode: MonitoringMode::Reporting,
                    requested_parameters: MonitoringParameters {
                        client_handle: i.0 as u32,
                        sampling_interval: 0.1,
                        filter: ExtensionObject::null(),
                        queue_size: 1,
                        discard_oldest: true,
                    },
                }
            })
            .collect::<Vec<_>>(),
    );
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::dummy(),
        subscription_id,
        timestamps_to_return: TimestampsToReturn::Both,
        items_to_create,
    }
}

pub mod attribute;
pub mod discovery;
pub mod method;
pub mod monitored_item;
pub mod node_management;
pub mod session;
pub mod subscription;
pub mod view;
