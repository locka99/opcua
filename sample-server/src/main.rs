extern crate opcua_core;
extern crate opcua_server;

use opcua_core::address_space::*;
use opcua_core::types::*;

fn main() {
    use opcua_server::{Server};
    let _ = opcua_core::init_logging();
    let mut server = Server::new_default();

    {
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder
        let sample_folder = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

        // Add some variables to it
        let now = DateTime::now();
        let var1 = Variable::new(&NodeId::new_string(2, "var1"), "v1", "v1", &DataValue::new(&now, Variant::Int32(30)));
        // address_space.add_variable(&var1, &sample_folder.node_id());
    }

    server.run();
}
