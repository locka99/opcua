//! This is a OPC UA server that exposes a MODBUS
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

struct ModBusEvent {}

fn main() {

    // Modbus is going to pump events for OPC UA to consume so we'll create a pipe for that

    let (tx, rx) = mpsc::channel();

    run_modbus(tx);
    run_opcua_server(rx);
}

fn run_modbus(tx: mpsc::Sender<ModBusEvent>) {
    use futures::Future;
    use tokio_core::reactor::Core;
    use tokio_modbus::prelude::*;

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    /*
        let socket_addr = "192.168.0.222:502".parse().unwrap();
        let task = tcp::connect(&handle, socket_addr)
            .for_each(move |ctx| {
                println!("Fetching the coupler ID");
                ctx.read_input_registers(0x1000, 7).and_then(move |data| {
                    let bytes: Vec<u8> = data.iter().fold(vec![], |mut x, elem| {
                        x.push((elem & 0xff) as u8);
                        x.push((elem >> 8) as u8);
                        x
                    });
                    let id = String::from_utf8(bytes).unwrap();
                    println!("The coupler ID is '{}'", id);
                    let e = ModBusEvent {};
                    tx.send(e);
                    Ok(())
                })
            });
        core.run(task).unwrap();
        */
}

fn run_opcua_server(rx: mpsc::Receiver<ModBusEvent>) {
    use opcua_server::prelude::*;
    use std::path::PathBuf;
    use std::thread;

    thread::spawn(|| {
        let config = ServerConfig::load(&PathBuf::from("../server.conf")).unwrap();
        let mut server = ServerBuilder::from_config(config)
            .server().unwrap();

        let address_space = server.address_space();

        {
            let mut address_space = address_space.write().unwrap();

            let coupler_id = NodeId::new(2, "coupler");

            // Create a sample folder under objects folder
            let modbus_folder_id = address_space
                .add_folder("MODBUS", "MODBUS", &AddressSpace::objects_folder_id())
                .unwrap();

            let _ = address_space.add_variables(
                vec![Variable::new(&coupler_id, "Coupler", "Coupler", 0 as i32)],
                &modbus_folder_id);

            if let Some(ref mut v) = address_space.find_variable_mut(coupler_id.clone()) {
                // Register a pull handler
                let getter = AttrFnGetter::new(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
                    Ok(Some(DataValue::new(1)))
                });
                v.set_value_getter(Arc::new(Mutex::new(getter)));
            }
        }
        server.run();
    });
}