//! This is a OPC UA server that is a MODBUS master - in MODBUS parlance the master is the thing
//! requesting information from a slave device.
//!
//! See README.md for more info. To make things easy, this code works against a simulator and has
//! hardcoded address and registers that it will map into OPC UA.
use std::sync::{Arc, RwLock, Mutex, mpsc};
use std::time::{Instant, Duration};
use std::thread;

use clap::{App, Arg, value_t_or_exit};

use futures::{Future, stream::Stream};
use tokio_core::reactor::Core;
use tokio_modbus::{
    prelude::*,
    client,
};
use tokio_timer::Interval;

use opcua_server::prelude::*;

#[derive(Clone)]
struct ModBusInfo {
    pub address: String,
    pub register_address: u16,
    pub register_count: usize,
    pub registers: Arc<RwLock<Vec<u16>>>,
}

fn main() {
    let m = App::new("Simple OPC UA Client")
        .arg(Arg::with_name("slave-address")
            .long("slave-address")
            .help("Specify the IP address and port of the MODBUS slave device")
            .takes_value(true)
            .default_value("127.0.0.1:502")
            .required(false))
        .arg(Arg::with_name("input-register-address")
            .long("input-register-address")
            .help("Input Register Address")
            .takes_value(true)
            .default_value("0")
            .required(false))
        .arg(Arg::with_name("input-register-quantity")
            .long("input-register-quantity")
            .help("Input Register Quantity")
            .takes_value(true)
            .default_value("9")
            .required(false))
        .get_matches();

    let register_count = value_t_or_exit!(m, "input-register-quantity", usize);
    let modbus_info = ModBusInfo {
        address: m.value_of("slave-address").unwrap().to_string(),
        register_address: value_t_or_exit!(m, "input-register-address", u16),
        register_count,
        registers: Arc::new(RwLock::new(vec![0u16; register_count])),
    };

    run_modbus(&modbus_info);
    run_opcua_server(&modbus_info);
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn read_timer(handle: tokio_core::reactor::Handle, ctx: client::Context, registers_address: u16, values: Arc<RwLock<Vec<u16>>>) -> impl Future<Error=()> {
    let values_len = {
        let values = values.read().unwrap();
        values.len() as u16
    };

    // This is a bit clunky so worth explaining. The timer fires on an interval. We don't want to
    // keep queuing up calls to MODBUS if for some reason its not responding to calls, so we'll
    // create a channel between the timer and the action. When an action finishes it sends a message
    // to the timer which then knows to create a new action on the next iteration. If the timer
    // doesn't receive an action it will do nothing on the iteration.
    let (tx, rx) = mpsc::channel();
    let _ = tx.send(());
    let handle_for_action = handle.clone();
    Interval::new(Instant::now(), Duration::from_millis(1000u64))
        .map_err(|err| {
            println!("Timer error {:?}", err);
        })
        .for_each(move |_| {
            // Test if the previous action is finished.
            if rx.try_recv().is_ok() {
                let values = values.clone();
                let tx = tx.clone();
                let tx_err = tx.clone();
                handle_for_action.spawn(ctx.read_input_registers(registers_address, values_len)
                    .map_err(move |err| {
                        println!("Read input registers error {:?}", err);
                        let _ = tx_err.send(());
                    })
                    .and_then(move |words| {
                        println!("Updating values");
                        let mut values = values.write().unwrap();
                        values.clear();
                        values.extend(words);
                        // Action finished, so send msg so timer knows
                        let _ = tx.send(());
                        Ok(())
                    }));
            } else {
                println!("Timer is not doing anything because previous MODBUS call has not returned");
            }
            Ok(())
        })
}

fn run_modbus(modbus_info: &ModBusInfo) {
    let socket_addr = modbus_info.address.parse().unwrap();
    let values = modbus_info.registers.clone();
    let registers_address = modbus_info.register_address;
    thread::spawn(move || {
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let task = tcp::connect(&handle, socket_addr)
            .map_err(|_| ())
            .and_then(move |ctx| {
                read_timer(handle, ctx, registers_address, values.clone())
            });
        core.run(task).unwrap();
        println!("MODBUS thread has finished");
    });
}

fn input_register_name(index: usize) -> String {
    format!("Input Register {}", index)
}

fn input_register_node_id(index: usize) -> NodeId {
    NodeId::from((2, input_register_name(index).as_ref()))
}

fn run_opcua_server(modbus_info: &ModBusInfo) {
    use std::path::PathBuf;

    let config = ServerConfig::load(&PathBuf::from("../server.conf")).unwrap();
    let server = ServerBuilder::from_config(config)
        .server().unwrap();

    let address_space = server.address_space();

    {
        let mut address_space = address_space.write().unwrap();

        // Create a folder under objects folder
        let modbus_folder_id = address_space
            .add_folder("MODBUS", "MODBUS", &NodeId::objects_folder_id())
            .unwrap();

        // Add variables to the folder
        let variables = (0..modbus_info.register_count).map(|i| {
            let name = input_register_name(i);
            Variable::new(&input_register_node_id(i), &name, &name, 0 as u16)
        }).collect();
        let _ = address_space.add_variables(variables, &modbus_folder_id);

        // Register a getter for each variable
        let values = modbus_info.registers.clone();
        (0..modbus_info.register_count).for_each(|i| {
            let v = address_space.find_variable_mut(input_register_node_id(i)).unwrap();
            let values = values.clone();
            let getter = AttrFnGetter::new(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
                let values = values.read().unwrap();
                let value = *values.get(i).unwrap();
                Ok(Some(DataValue::new(value)))
            });
            v.set_value_getter(Arc::new(Mutex::new(getter)));
        });
    }

    server.run();
}