extern crate opcua_core;
extern crate opcua_server;

extern crate time;
extern crate timer;

use opcua_server::prelude::*;

fn main() {
    let _ = opcua_core::init_logging();

    // Creates the server with the default settings and node set
    let mut server = Server::new_default();

    // Add 3 variables called v1, v3, and v3 to the address space in the server
    let v1_node = NodeId::new_string(1, "v1");
    let v2_node = NodeId::new_string(1, "v2");
    let v3_node = NodeId::new_string(1, "v3");
    let mut counter: Int32 = 0;
    {
        // Server state is guard locked because all sessions need it
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

        // Add some variables to our sample folder
        let vars = vec![
            Variable::new(&v1_node, "v1", "v1", &DataTypeId::Int32, DataValue::new(Variant::Int32(counter))),
            Variable::new(&v2_node, "v2", "v2", &DataTypeId::Boolean, DataValue::new(Variant::Boolean(true))),
            Variable::new(&v3_node, "v3", "v3", &DataTypeId::String, DataValue::new(Variant::String(UAString::from_str("Hello world"))))
        ];

        let _ = address_space.add_variables(&vars, &sample_folder_id);
    }

    // This code will start a timer to alter variables on an interval. Note the timer and timer_guard
    // control the lifetime of the timer, so we'll do the heavy lifting inside a block and then leave
    // those vars in scope to control when the timer stops.
    let timer = timer::Timer::new();
    let timer_guard = {
        let timer_address_space = {
            let server_state = server.server_state.lock().unwrap();
            server_state.address_space.clone()
        };
        timer.schedule_repeating(time::Duration::milliseconds(1000), move || {
            let mut address_space = timer_address_space.lock().unwrap();
            let _ = address_space.set_variable_value(&v1_node, Variant::Int32(counter));
            counter += 1;
        })
    };

    // Now our server can run
    server.run();

    // Timer no longer required
    drop(timer_guard);
}