use std::sync::{Arc, RwLock, RwLockWriteGuard};

use crate::{
    prelude::*,
    state::ServerState,
    session::Session,
    services::{
        monitored_item::MonitoredItemService,
        subscription::SubscriptionService,
    },
    comms::transport::Transport,
    tests::*,
};

struct ServiceTest {
    pub server: Server,
    pub server_state: Arc<RwLock<ServerState>>,
    pub address_space: Arc<RwLock<AddressSpace>>,
    pub session: Arc<RwLock<Session>>,
}

impl ServiceTest {
    pub fn new() -> ServiceTest {
        let server = ServerBuilder::new_anonymous("foo").server().unwrap();
        let tcp_transport = server.new_transport();
        let server_state = server.server_state();
        let address_space = server.address_space();
        let session = tcp_transport.session();
        ServiceTest {
            server,
            server_state,
            address_space,
            session,
        }
    }

    pub fn get_server_state_and_session(&self) -> (RwLockWriteGuard<'_, ServerState>, RwLockWriteGuard<'_, Session>) {
        (self.server_state.write().unwrap(), self.session.write().unwrap())
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

fn add_many_vars_to_address_space(address_space: &mut AddressSpace, vars_to_add: usize) -> (NodeId, Vec<NodeId>) {
    // Create a sample folder under objects folder
    let sample_folder_id = address_space.add_folder("Many Vars", "Many Vars", &AddressSpace::objects_folder_id()).unwrap();

    // Add as a bunch of sequential vars to the folder
    let vars: Vec<Variable> = (0..vars_to_add).map(|i| {
        let var_name = var_name(i);
        let node_id = NodeId::new(1, var_name.clone());
        Variable::new(&node_id, &var_name, &var_name, "", i as i32)
    }).collect();

    let node_ids = vars.iter().map(|v| v.node_id().clone()).collect();
    let _ = address_space.add_variables(vars, &sample_folder_id);

    (sample_folder_id, node_ids)
}


/// A helper that sets up a subscription service test
fn do_subscription_service_test<T>(f: T)
    where T: FnOnce(&mut ServerState, &mut Session, &mut AddressSpace, SubscriptionService, MonitoredItemService)
{
    let st = ServiceTest::new();
    let mut server_state = trace_write_lock_unwrap!(st.server_state);
    let mut session = trace_write_lock_unwrap!(st.session);

    {
        let mut address_space = trace_write_lock_unwrap!(st.address_space);
        add_many_vars_to_address_space(&mut address_space, 100);
    }

    let mut address_space = trace_write_lock_unwrap!(st.address_space);
    f(&mut server_state, &mut session, &mut address_space, SubscriptionService::new(), MonitoredItemService::new());
}

/// Creates a blank subscription request
fn create_subscription_request(max_keep_alive_count: u32, lifetime_count: u32) -> CreateSubscriptionRequest {
    CreateSubscriptionRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        requested_publishing_interval: 100f64,
        requested_lifetime_count: lifetime_count,
        requested_max_keep_alive_count: max_keep_alive_count,
        max_notifications_per_publish: 5,
        publishing_enabled: true,
        priority: 0,
    }
}

/// Creates a monitored item request
fn create_monitored_items_request<T>(subscription_id: u32, mut node_id: Vec<T>) -> CreateMonitoredItemsRequest
    where T: Into<NodeId> {
    let items_to_create = Some(node_id.drain(..)
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
        .collect::<Vec<_>>());
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
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
