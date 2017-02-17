extern crate opcua_core;
extern crate opcua_server;

use opcua_core::types::*;

use opcua_server::prelude::*;

fn main() {
    let _ = opcua_core::init_logging();
    let mut server = Server::new_default();

    {
        // Server state is guard locked because all sessions need it
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

        // Add some variables to our sample folder
        let vars = vec![
            Variable::new(&NodeId::new_string(1, "v1"), "v1", "v1", &DataTypeId::Int32, DataValue::new(Variant::Int32(30))),
            Variable::new(&NodeId::new_string(1, "v2"), "v2", "v2", &DataTypeId::Boolean, DataValue::new(Variant::Boolean(true))),
            Variable::new(&NodeId::new_string(1, "v3"), "v3", "v3", &DataTypeId::String, DataValue::new(Variant::String(UAString::from_str("Hello world"))))
        ];
        let _ = address_space.add_variables(&vars, &sample_folder_id);
    }

    // Now our server can run
    server.run();
}
