use std::sync::{Arc, RwLock, RwLockWriteGuard};

use prelude::*;
use server_state::ServerState;
use session::Session;

use tests::*;

struct ServiceTest {
    server: Server,
    server_state: Arc<RwLock<ServerState>>,
    session: Arc<RwLock<Session>>,
}

impl ServiceTest {
    pub fn new() -> ServiceTest {
        let server = Server::new(ServerConfig::new_anonymous("foo"));
        let tcp_transport = server.new_transport();
        let server_state = server.server_state.clone();
        let session = tcp_transport.session();
        ServiceTest {
            server,
            server_state,
            session,
        }
    }

    pub fn get_server_state_and_session(&self) -> (RwLockWriteGuard<ServerState>, RwLockWriteGuard<Session>) {
        (self.server_state.write().unwrap(), self.session.write().unwrap())
    }
}

fn make_request_header() -> RequestHeader {
    RequestHeader {
        authentication_token: NodeId::new(0, 99),
        timestamp: DateTime::now(),
        request_handle: 1,
        return_diagnostics: 0,
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
        let node_id = NodeId::new_string(1, &var_name);
        Variable::new(&node_id, &var_name, &var_name, "", i as Int32)
    }).collect();

    let node_ids = vars.iter().map(|v| v.node_id().clone()).collect();
    let _ = address_space.add_variables(vars, &sample_folder_id);

    (sample_folder_id, node_ids)
}

mod attribute;
mod discovery;
mod session;
mod monitored_item;
mod subscription;
mod view;