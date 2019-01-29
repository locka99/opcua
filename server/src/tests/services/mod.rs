use std::sync::{Arc, RwLock, RwLockWriteGuard};

use crate::{
    prelude::*,
    state::ServerState,
    session::Session,
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

fn add_many_vars_to_address_space(address_space: &mut AddressSpace, vars_to_add: usize) -> (NodeId, Vec<NodeId>) {
    // Create a sample folder under objects folder
    let sample_folder_id = address_space.add_folder("Many Vars", "Many Vars", &AddressSpace::objects_folder_id()).unwrap();

    // Add as a bunch of sequential vars to the folder
    let vars: Vec<Variable> = (0..vars_to_add).map(|i| {
        let var_name = format!("v{}", i);
        let node_id = NodeId::new(1, var_name.clone());
        Variable::new(&node_id, &var_name, &var_name, "", i as i32)
    }).collect();

    let node_ids = vars.iter().map(|v| v.node_id().clone()).collect();
    let _ = address_space.add_variables(vars, &sample_folder_id);

    (sample_folder_id, node_ids)
}

pub mod attribute;
pub mod discovery;
pub mod session;
pub mod monitored_item;
pub mod subscription;
pub mod view;
pub mod method;