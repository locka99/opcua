//! This is a simple server for OPC UA. Our sample creates a server with the default settings
//! adds some variables to the address space and the listeners for connections. It also has
//! a timer that updates those variables so anything monitoring variables sees the values changing.

extern crate time;
extern crate timer;

extern crate opcua_core;
extern crate opcua_server;

use opcua_server::prelude::*;

fn main() {
    // This line isn't necessary but it enables logging which tells you what OPC UA is up to.
    let _ = opcua_core::init_logging();

    // Creates the OPC UA server with the default settings and node set
    let mut server = Server::new_default();

    // Add 3 variables called v1, v3, and v3 to the address space in the server
    let v1_node = NodeId::new_string(2, "v1");
    let v2_node = NodeId::new_string(2, "v2");
    let v3_node = NodeId::new_string(2, "v3");

    {
        // Server state is guard locked because all sessions need it
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

        // Add some variables to our sample folder. Values will be overwritten by the timer
        let vars = vec![
            Variable::new_i32(&v1_node, "v1", "v1", 0),
            Variable::new_bool(&v2_node, "v2", "v2", false),
            Variable::new_string(&v3_node, "v3", "v3", "")
        ];
        let _ = address_space.add_variables(&vars, &sample_folder_id);
    }


    // These values will be changed in a timer loop
    let mut v1_counter: Int32 = 0;
    let mut v2_flag: Boolean = true;
    let mut v3_string: String = "Hello world!".to_string();

    // Start a timer to alter variables on an interval. Note the timer and timer_guard are the scope
    // that the timer runs for, so we'll set stuff up inside a block and then leave those vars for the
    // scope that controls when they must stop.
    //
    // Also note that the timer is running on another thread from the server but thanks to the magic
    // of Rust and atomic reference counting, we can modify the value without risking interfering
    // with anything else going on.
    let timer = timer::Timer::new();
    let timer_guard = {
        // The server has a refcounted address space that we will clone (increment) and hand to
        // to the timer scheduler.
        let address_space = {
            let server_state = server.server_state.lock().unwrap();
            server_state.address_space.clone()
        };
        timer.schedule_repeating(time::Duration::milliseconds(1000), move || {
            v1_counter += 1;
            v2_flag = !v2_flag;
            v3_string = format!("Hello World times {}", v1_counter);
            let mut address_space = address_space.lock().unwrap();
            let _ = address_space.set_variable_value(&v1_node, Variant::Int32(v1_counter));
            let _ = address_space.set_variable_value(&v2_node, Variant::Boolean(v2_flag));
            let _ = address_space.set_variable_value(&v3_node, Variant::String(UAString::from_str(&v3_string)));
        })
    };

    // Now our server can run
    server.run();

    // Timer no longer required
    drop(timer_guard);
}