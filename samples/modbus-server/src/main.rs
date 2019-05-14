//! This is a OPC UA server that is a MODBUS master (i.e. the thing requesting information)
//! from a defined slave.
//!
//! To make things easy, this code works
use std::sync::{Arc, RwLock, Mutex, mpsc};
use std::time::{Instant, Duration};
use std::thread;

use futures::{Future, stream::Stream};
use tokio_core::reactor::Core;
use tokio_modbus::{
    prelude::*,
    client,
};
use tokio_timer::Interval;

use opcua_server::prelude::*;

const SLAVE_ADDRESS: &str = "127.0.0.1:502";

/// The address offset for the input registers we want to fetch
const INPUT_REGISTERS_ADDRESS: u16 = 0x0000;
/// The quantity of registers to fetch
const INPUT_REGISTERS_QUANTITY: usize = 9;

fn main() {
    let input_registers = Arc::new(RwLock::new(vec![0u16; INPUT_REGISTERS_QUANTITY]));
    run_modbus(input_registers.clone());
    run_opcua_server(input_registers);
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn read_timer(handle: tokio_core::reactor::Handle, ctx: client::Context, values: Arc<RwLock<Vec<u16>>>) -> impl Future<Error=()> {
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
                handle_for_action.spawn(ctx.read_input_registers(INPUT_REGISTERS_ADDRESS, INPUT_REGISTERS_QUANTITY as u16)
                    .map_err(|err| {
                        println!("Read input registers error {:?}", err);
                    })
                    .and_then(move |mut words| {
                        println!("Updating values");
                        let mut values = values.write().unwrap();
                        values.clear();
                        words.drain(..).for_each(|i| values.push(i));
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

fn run_modbus(values: Arc<RwLock<Vec<u16>>>) {
    thread::spawn(|| {
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let socket_addr = SLAVE_ADDRESS.parse().unwrap();
        let task = tcp::connect(&handle, socket_addr)
            .map_err(|_| ())
            .and_then(move |ctx| {
                read_timer(handle, ctx, values.clone())
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

fn run_opcua_server(values: Arc<RwLock<Vec<u16>>>) {
    use std::path::PathBuf;

    let config = ServerConfig::load(&PathBuf::from("../server.conf")).unwrap();
    let server = ServerBuilder::from_config(config)
        .server().unwrap();

    let address_space = server.address_space();

    {
        let mut address_space = address_space.write().unwrap();

        // Create a folder under objects folder
        let modbus_folder_id = address_space
            .add_folder("MODBUS", "MODBUS", &AddressSpace::objects_folder_id())
            .unwrap();

        // Add variables to the folder
        let variables = (0..INPUT_REGISTERS_QUANTITY).map(|i| {
            let name = input_register_name(i);
            Variable::new(&input_register_node_id(i), name.as_ref(), name.as_ref(), 0 as u16)
        }).collect();
        let _ = address_space.add_variables(variables, &modbus_folder_id);

        // Register a getter for each variable
        (0..INPUT_REGISTERS_QUANTITY).for_each(|i| {
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