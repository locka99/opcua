//! This is a simple server for OPC UA. Our sample creates a server with the default settings
//! adds some variables to the address space and the listeners for connections. It also has
//! a timer that updates those variables so anything monitoring variables sees the values changing.

extern crate time;
extern crate timer;

extern crate opcua_core;
extern crate opcua_server;

use opcua_server::prelude::*;

fn main() {
    // This enables logging. If you don't need logging you can omit it
    let _ = opcua_core::init_logging();

    // Create an OPC UA server with the default settings and node set
    let mut server = Server::new_default();

    // Create the variables and timers that update the values. The fn returns a timer
    // and timer guard whose scope means timers fire to update
    let (timer, timer_guard) = setup_variables(&mut server);

    // Now our server can run.
    server.run();

    // These drops are not necessary but it stops the compiler warning about unused assignments above
    drop(timer_guard);
    drop(timer);
}

fn setup_variables(server: &mut Server) -> (timer::Timer, timer::Guard) {
    // Add variables to the address space in the server
    let v1_node = NodeId::new_string(2, "v1");
    let v2_node = NodeId::new_string(2, "v2");
    let v3_node = NodeId::new_string(2, "v3");
    let v4_node = NodeId::new_string(2, "v4");

    {
        // Server state and its address space are atomic reference counted so we obtain locks
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

        // Add some variables to our sample folder. Values will be overwritten by the timer
        let vars = vec![
            Variable::new_i32(&v1_node, "v1", "v1", 0),
            Variable::new_bool(&v2_node, "v2", "v2", false),
            Variable::new_string(&v3_node, "v3", "v3", ""),
            Variable::new_double(&v4_node, "v4", "v4", 0f64),
        ];
        let _ = address_space.add_variables(&vars, &sample_folder_id);
    }

    // Start a timer to alter variables on an interval. Note the timer and timer_guard are the scope
    // that the timer runs for, so we'll set stuff up inside a block and then leave those vars for the
    // scope that controls when they must stop.
    //
    // Also note that the timer is running on another thread from the server but thanks to the magic
    // of Rust and atomic reference counting, we can modify the value without risking interfering
    // with anything else going on.
    let timer = timer::Timer::new();
    let timer_guard = {
        // These values will be changed in a timer loop
        let mut v1_counter: Int32 = 0;
        let mut v2_flag: Boolean = true;
        let mut v3_string: String = "Hello world!".to_string();
        let mut v4_double = 0f64;

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
            v4_double = (v1_counter as f64 / 360.0).to_radians().sin();
            let mut address_space = address_space.lock().unwrap();
            let _ = address_space.set_variable_value(&v1_node, Variant::Int32(v1_counter));
            let _ = address_space.set_variable_value(&v2_node, Variant::Boolean(v2_flag));
            let _ = address_space.set_variable_value(&v3_node, Variant::String(UAString::from_str(&v3_string)));
            let _ = address_space.set_variable_value(&v4_node, Variant::Double(v4_double));
        })
    };

    (timer, timer_guard)
}