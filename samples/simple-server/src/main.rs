//! This is a simple server for OPC UA. Our sample creates a server with the default settings
//! adds some variables to the address space and the listeners for connections. It also has
//! a timer that updates those variables so anything monitoring variables sees the values changing.
extern crate chrono;
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_server;

use std::sync::{Arc, Mutex};
use std::path::PathBuf;

use opcua_server::prelude::*;

fn main() {
    // This enables logging via env_logger & log crate macros. If you don't need logging or want
    // to implement your own, omit this line.
    opcua_core::init_logging();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add some variables of our own
    let update_timers = add_example_variables(&mut server);

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();

    // This explicit drop statement prevents the compiler complaining that update_timers is unused.
    drop(update_timers);
}

/// Creates some sample variables, and some push / pull examples that update them
fn add_example_variables(server: &mut Server) -> Vec<PollingAction> {
    // These will be the node ids of the new variables
    let v1_node = NodeId::new_string(2, "v1");
    let v2_node = NodeId::new_string(2, "v2");
    let v3_node = NodeId::new_string(2, "v3");
    let v4_node = NodeId::new_string(2, "v4");

    // The address space is guarded so obtain a lock to change it
    {
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space
            .add_folder("Sample", "Sample", &AddressSpace::objects_folder_id())
            .unwrap();

        // Add some variables to our sample folder. Values will be overwritten by the timer
        let _ = address_space.add_variables(
            vec![Variable::new(&v1_node, "v1", "v1", "v1 variable", 0 as Int32),
                 Variable::new(&v2_node, "v2", "v2", "v2 variable", false),
                 Variable::new(&v3_node, "v3", "v3", "v3 variable", UAString::from("")),
                 Variable::new(&v4_node, "v4", "v4", "v4 variable", 0f64)],
            &sample_folder_id);
    }

    // OPC UA for Rust allows you to push or pull values from a variable so here are examples
    // of each method.

    // 1) Push. This code will use a timer to set the values on variable v1 & v2 on an interval

    let mut v1_counter: Int32 = 0;
    let mut v2_flag: Boolean = true;
    let timers = vec![
        server.create_address_space_polling_action(250, move |address_space: &mut AddressSpace| {
            v1_counter += 1;
            v2_flag = !v2_flag;
            let _ = address_space.set_value_by_node_id(&v1_node, Variant::Int32(v1_counter));
            let _ = address_space.set_value_by_node_id(&v2_node, Variant::Boolean(v2_flag));
        })
    ];

    // 2) Pull. This code will add getters to v3 & v4 that returns their values by calling
    //    function.

    {
        let server_state = server.server_state.lock().unwrap();
        let mut address_space = server_state.address_space.lock().unwrap();

        if let Some(ref mut v) = address_space.find_variable_by_node_id(&v3_node) {
            // Hello world's counter will increment with each get - slower interval == slower increment
            let mut counter = 0;
            let getter = AttrFnGetter::new(move |_, _| -> Option<DataValue> {
                counter += 1;
                Some(DataValue::new(UAString::from(format!("Hello World times {}", counter))))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }

        if let Some(ref mut v) = address_space.find_variable_by_node_id(&v4_node) {
            // Sine wave draws 2*PI over course of 10 seconds
            use std::f64::consts;
            use chrono::Utc;
            let start_time = Utc::now();
            let getter = AttrFnGetter::new(move |_: NodeId, _: AttributeId| -> Option<DataValue> {
                let moment = (Utc::now().signed_duration_since(start_time).num_milliseconds() % 10000) as f64 / 10000.0;
                Some(DataValue::new((2.0 * consts::PI * moment).sin()))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }
    }

    // Caller must hang onto the timers for as long as they want actions to happen. When timers are
    // dropped, they no longer fire
    timers
}