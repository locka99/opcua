//! This is a simple server for OPC UA. Our sample creates a server with the default settings
//! adds some variables to the address space and the listeners for connections. It also has
//! a timer that updates those variables so anything monitoring variables sees the values changing.

extern crate opcua_core;
extern crate opcua_server;

use opcua_server::prelude::*;

fn main() {
    // This enables logging. If you don't need logging you can omit it
    let _ = opcua_core::init_logging();

    // Create an OPC UA server with the default settings and node set
    let mut server = Server::new_default();

    // Add some variables and update timer actions
    let actions = setup_variable_update_actions(&mut server);

    // Run the server. This does not ordinarily exit.
    server.run();

    // This drop stops compiler complaining that actions var is unused.
    drop(actions);
}

/// Creates some sample variables, and some fast / slow timers to update them
fn setup_variable_update_actions(server: &mut Server) -> Vec<PollingAction> {
    let server_state = server.server_state.lock().unwrap();

    // These will be the node ids of the variables
    let v1_node = NodeId::new_string(2, "v1");
    let v2_node = NodeId::new_string(2, "v2");
    let v3_node = NodeId::new_string(2, "v3");
    let v4_node = NodeId::new_string(2, "v4");

    // Create a folder to hold the variables, then add variables.
    {
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space
            .add_folder("Sample", "Sample", &AddressSpace::objects_folder_id())
            .unwrap();

        // Add some variables to our sample folder. Values will be overwritten by the timer
        let vars = vec![Variable::new_i32(&v1_node, "v1", "v1", 0),
                        Variable::new_bool(&v2_node, "v2", "v2", false),
                        Variable::new_string(&v3_node, "v3", "v3", ""),
                        Variable::new_double(&v4_node, "v4", "v4", 0f64)];
        let _ = address_space.add_variables(&vars, &sample_folder_id);
    }

    // Create a couple of PollingAction objects for our variables. Note how each gets their
    // own cloned reference count to the address space so they can safely modify state.

    let mut actions = Vec::with_capacity(2);

    // Fast changes
    {
        let address_space = server_state.address_space.clone();

        let mut v1_counter: Int32 = 0;
        let mut v2_flag: Boolean = true;

        actions.push(PollingAction::new(250, move || {
            v1_counter += 1;
            v2_flag = !v2_flag;
            let mut address_space = address_space.lock().unwrap();
            let _ = address_space.set_variable_value(&v1_node, Variant::Int32(v1_counter));
            let _ = address_space.set_variable_value(&v2_node, Variant::Boolean(v2_flag));
        }));
    }

    // Slow changes
    {
        let address_space = server_state.address_space.clone();

        let mut counter: Int32 = 0;
        let mut v3_string: String = "Hello world!".to_string();
        let mut v4_double = 0f64;

        actions.push(PollingAction::new(2000, move || {
            counter += 1;
            v3_string = format!("Hello World times {}", counter);
            v4_double = ((counter % 360) as f64).to_radians().sin();
            let mut address_space = address_space.lock().unwrap();
            let _ = address_space.set_variable_value(&v3_node, Variant::String(UAString::from_str(&v3_string)));
            let _ = address_space.set_variable_value(&v4_node, Variant::Double(v4_double));
        }));
    }

    // Caller must hang onto this result for as long as they want actions to happen. When this
    // value is dropped, the action timers will stop.
    actions
}