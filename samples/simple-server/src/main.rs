//! This is a simple server for OPC UA. Our sample creates a server with the default settings
//! adds some variables to the address space and the listeners for connections. It also has
//! a timer that updates those variables so anything monitoring variables sees the values changing.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use opcua_server::prelude::*;

fn main() {
    // This enables logging via env_logger & log crate macros. If you don't need logging or want
    // to implement your own, omit this line.
    opcua_console_logging::init();

    // Create an OPC UA server with sample configuration and default node set
    let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());

    // Add some variables of our own
    add_example_variables(&mut server);

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run();
}

/// Creates some sample variables, and some push / pull examples that update them
fn add_example_variables(server: &mut Server) {
    // These will be the node ids of the new variables
    let v1_node = NodeId::new(2, "v1");
    let v2_node = NodeId::new(2, "v2");
    let v3_node = NodeId::new(2, "v3");
    let v4_node = NodeId::new(2, "v4");

    let address_space = server.address_space();

    // The address space is guarded so obtain a lock to change it
    {
        let mut address_space = address_space.write().unwrap();

        // Create a sample folder under objects folder
        let sample_folder_id = address_space
            .add_folder("Sample", "Sample", &AddressSpace::objects_folder_id())
            .unwrap();

        // Add some variables to our sample folder. Values will be overwritten by the timer
        let _ = address_space.add_variables(
            vec![Variable::new(&v1_node, "v1", "v1", 0 as i32),
                 Variable::new(&v2_node, "v2", "v2", false),
                 Variable::new(&v3_node, "v3", "v3", UAString::from("")),
                 Variable::new(&v4_node, "v4", "v4", 0f64)],
            &sample_folder_id);
    }

    // OPC UA for Rust allows you to push or pull values from a variable so here are examples
    // of each method.


    // 1) Pull. This code will add getters to v3 & v4 that returns their values by calling
    //    function.
    {
        let address_space = server.address_space();
        let mut address_space = address_space.write().unwrap();
        if let Some(ref mut v) = address_space.find_variable_mut(v3_node.clone()) {
            // Hello world's counter will increment with each get - slower interval == slower increment
            let mut counter = 0;
            let getter = AttrFnGetter::new(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
                counter += 1;
                Ok(Some(DataValue::new(UAString::from(format!("Hello World times {}", counter)))))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }

        if let Some(ref mut v) = address_space.find_variable_mut(v4_node.clone()) {
            // Sine wave draws 2*PI over course of 10 seconds
            use std::f64::consts;
            use chrono::Utc;
            let start_time = Utc::now();
            let getter = AttrFnGetter::new(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
                let elapsed = Utc::now().signed_duration_since(start_time).num_milliseconds();
                let moment = (elapsed % 10000) as f64 / 10000.0;
                Ok(Some(DataValue::new((2.0 * consts::PI * moment).sin())))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        }
    }

    // 2) Push. This code will use a timer to set the values on variable v1 & v2 on an interval.
    //    Note you can use any kind of timer callback that you like for this. The library
    //    contains a simple add_polling_action for your convenience.
    {
        // Store a counter and a flag in a tuple
        let data = Arc::new(Mutex::new((0, true)));
        server.add_polling_action(300, move || {
            let mut data = data.lock().unwrap();
            data.0 += 1;
            data.1 = !data.1;
            let mut address_space = address_space.write().unwrap();
            let now = DateTime::now();
            let _ = address_space.set_variable_value(v1_node.clone(), data.0 as i32, &now, &now);
            let _ = address_space.set_variable_value(v2_node.clone(), data.1, &now, &now);
        });
    }
}