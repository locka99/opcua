//! This is a OPC UA server that is a MODBUS master - in MODBUS parlance the master is the thing
//! requesting information from a slave device.
//!
//! See README.md for more info. To make things easy, this code works against a simulator and has
//! hardcoded address and registers that it will map into OPC UA.
#[macro_use]
extern crate serde_derive;

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, mpsc, Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};

use clap::{App, Arg};
use futures::{Future, stream::Stream};
use tokio_core::reactor::Core;
use tokio_modbus::{
    client,
    prelude::*,
};
use tokio_timer::Interval;

use opcua_server::prelude::*;

mod slave;

#[derive(Deserialize)]
struct MBConfig {
    pub slave_address: String,
    pub output_coil_base_address: u16,
    pub output_coil_count: usize,
    pub input_coil_base_address: u16,
    pub input_coil_count: usize,
    pub input_register_base_address: u16,
    pub input_register_count: usize,
    pub output_register_base_address: u16,
    pub output_register_count: usize,
}

impl MBConfig {
    pub fn load(path: &Path) -> Result<MBConfig, ()> {
        if let Ok(mut f) = File::open(path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                let config = serde_yaml::from_str(&s);
                if let Ok(config) = config {
                    Ok(config)
                } else {
                    println!("Cannot deserialize configuration from {}", path.to_string_lossy());
                    Err(())
                }
            } else {
                println!("Cannot read configuration file {} to string", path.to_string_lossy());
                Err(())
            }
        } else {
            println!("Cannot open configuration file {}", path.to_string_lossy());
            Err(())
        }
    }
}

struct MBRuntime {
    pub config: MBConfig,
    pub input_registers: Arc<RwLock<Vec<u16>>>,
    pub input_coils: Arc<RwLock<Vec<bool>>>,
}

fn main() {
    let m = App::new("Simple OPC UA Client")
        .arg(Arg::with_name("run-demo-slave")
            .long("run-demo-slave")
            .help("Runs a demo slave to ensure the sample has something to connect to")
            .required(false))
        .arg(Arg::with_name("config")
            .long("config")
            .help("Configuration file")
            .takes_value(true)
            .default_value("./modbus.conf")
            .required(false))
        .get_matches();

    let config_path = m.value_of("config").unwrap();
    let config = MBConfig::load(&PathBuf::from(config_path)).unwrap();

    let input_registers = vec![0u16; config.input_register_count];
    let input_coils = vec![false; config.input_coil_count];

    let modbus_info = MBRuntime {
        config,
        input_registers: Arc::new(RwLock::new(input_registers)),
        input_coils: Arc::new(RwLock::new(input_coils)),
    };

    if m.is_present("run-demo-slave") {
        println!("Running a demo MODBUS slave");
        slave::run_modbus_slave(&modbus_info.config.slave_address);
        thread::sleep(std::time::Duration::from_millis(1000));
    }

    run_modbus_master(&modbus_info);
    run_opcua_server(&modbus_info);
}

fn run_modbus_master(modbus_info: &MBRuntime) {
    let socket_addr = modbus_info.config.slave_address.parse().unwrap();
    let values = modbus_info.input_registers.clone();
    let registers_address = modbus_info.config.input_register_base_address;
    thread::spawn(move || {
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let task = tcp::connect(&handle, socket_addr)
            .map_err(|_| ())
            .and_then(move |ctx| {
                spawn_read_timer(handle, ctx, registers_address, values.clone())
            });
        core.run(task).unwrap();
        println!("MODBUS thread has finished");
    });
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn spawn_read_timer(handle: tokio_core::reactor::Handle, ctx: client::Context, registers_address: u16, values: Arc<RwLock<Vec<u16>>>) -> impl Future<Error=()> {
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

// Runs the OPC UA server which is just a basic server with some variables hooked up to getters
fn run_opcua_server(modbus_info: &MBRuntime) {
    let config = ServerConfig::load(&PathBuf::from("../server.conf")).unwrap();
    let server = ServerBuilder::from_config(config)
        .server().unwrap();

    let address_space = server.address_space();
    {
        let mut address_space = address_space.write().unwrap();
        add_variables(modbus_info, &mut address_space);
    }
    server.run();
}

/// Adds all the MODBUS variables to the address space
fn add_variables(modbus_info: &MBRuntime, address_space: &mut AddressSpace) {
    // Create a folder under objects folder
    let modbus_folder_id = address_space
        .add_folder("MODBUS", "MODBUS", &NodeId::objects_folder_id())
        .unwrap();

    add_input_coils(modbus_info, address_space, &modbus_folder_id);
    add_input_registers(modbus_info, address_space, &modbus_folder_id);
}

fn add_input_coils(modbus_info: &MBRuntime, address_space: &mut AddressSpace, parent_folder_id: &NodeId) {
    let input_coils_id = address_space
        .add_folder("Input Coils", "Input Coils", parent_folder_id)
        .unwrap();

    let start = modbus_info.config.input_coil_base_address as usize;
    let end = start + modbus_info.config.input_coil_count;

    let values = modbus_info.input_coils.clone();
    make_variables(address_space, start, end, &input_coils_id, values, false, |i| format!("Input Coil {}", i));
}


fn add_input_registers(modbus_info: &MBRuntime, address_space: &mut AddressSpace, parent_folder_id: &NodeId) {
    let input_registers_id = address_space
        .add_folder("Input Registers", "Input Registers", parent_folder_id)
        .unwrap();

    // Add variables to the folder
    let start = modbus_info.config.input_register_base_address as usize;
    let end = start + modbus_info.config.input_register_count;

    let values = modbus_info.input_registers.clone();
    make_variables(address_space, start, end, &input_registers_id, values, 0 as u16, |i| format!("Input Register {}", i));
}

/// Creates variables and hooks them up to getters
fn make_variables<T>(address_space: &mut AddressSpace, start: usize, end: usize, parent_folder_id: &NodeId, values: Arc<RwLock<Vec<T>>>, default_value: T, name_formatter: impl Fn(usize) -> String)
    where T: 'static + Copy + Send + Sync + Into<Variant>
{
    // Create variables
    let variables = (start..end).map(|i| {
        let name = name_formatter(i);
        let mut v = Variable::new(&NodeId::new(2, name.clone()), &name, &name, default_value);
        let values = values.clone();
        let getter = AttrFnGetter::new(move |_, _, _| -> Result<Option<DataValue>, StatusCode> {
            let values = values.read().unwrap();
            let value = *values.get(i - start).unwrap();
            Ok(Some(DataValue::new(value)))
        });
        v.set_value_getter(Arc::new(Mutex::new(getter)));
        v
    }).collect();
    let _ = address_space.add_variables(variables, &parent_folder_id);
}
