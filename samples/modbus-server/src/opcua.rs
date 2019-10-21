use std::{
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use opcua_server::prelude::*;

use crate::MBRuntime;

// Runs the OPC UA server which is just a basic server with some variables hooked up to getters
pub fn run(runtime: Arc<RwLock<MBRuntime>>) {
    let config = ServerConfig::load(&PathBuf::from("../server.conf")).unwrap();
    let server = ServerBuilder::from_config(config)
        .server().unwrap();

    let address_space = server.address_space();

    {
        let mut address_space = address_space.write().unwrap();
        let nsidx = address_space.register_namespace("MODBUS").unwrap();
        add_variables(runtime, &mut address_space, nsidx);
    }
    server.run();
}

#[derive(Clone, Copy)]
enum Table {
    /// Discrete Output Coils
    OutputCoils,
    /// Discrete Input Contacts (coils)
    InputCoils,
    /// Analog Input Registers
    InputRegisters,
    /// Analog Output Holding Registers
    OutputRegisters,
}

/// Calculate a register number from the table and data address
fn register_number(table: Table, address: u16) -> u32 {
    let base = match table {
        Table::OutputCoils => 1,
        Table::InputCoils => 10001,
        Table::InputRegisters => 30001,
        Table::OutputRegisters => 40001
    };
    base + address as u32
}

/// Make a node id for the coil/register based on its table and the address
fn make_node_id(nsidx: u16, table: Table, address: u16) -> NodeId {
    NodeId::new(nsidx, register_number(table, address))
}

/// Adds all the MODBUS variables to the address space
fn add_variables(runtime: Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, nsidx: u16) {
    // Create a folder under objects folder
    let modbus_folder_id = address_space
        .add_folder("MODBUS", "MODBUS", &NodeId::objects_folder_id())
        .unwrap();
    add_input_coils(&runtime, address_space, nsidx, &modbus_folder_id);
    add_output_coils(&runtime, address_space, nsidx, &modbus_folder_id);
    add_input_registers(&runtime, address_space, nsidx, &modbus_folder_id);
    add_output_registers(&runtime, address_space, nsidx, &modbus_folder_id);
}

fn start_end(base_address: u16, count: usize) -> (usize, usize) {
    let start = base_address as usize;
    let end = start + count;
    if end > 9998 {
        panic!("Base address and / or count are out of MODBUS addressable range, check your configuration file");
    }
    (start, end)
}

fn add_input_coils(runtime: &Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
    let folder_id = address_space
        .add_folder("Input Coils", "Input Coils", parent_folder_id)
        .unwrap();

    let (start, end, values) = {
        let runtime = runtime.read().unwrap();
        let (start, end) = start_end(runtime.config.input_coil_base_address, runtime.config.input_coil_count);
        let values = runtime.input_coils.clone();
        (start, end, values)
    };

    make_variables(address_space, nsidx, Table::InputCoils, start, end, &folder_id, values, false, |i| format!("Input Coil {}", i));
}

fn add_output_coils(runtime: &Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
    let folder_id = address_space
        .add_folder("Output Coils", "Output Coils", parent_folder_id)
        .unwrap();

    let (start, end, values) = {
        let runtime = runtime.read().unwrap();
        let (start, end) = start_end(runtime.config.output_coil_base_address, runtime.config.output_coil_count);
        let values = runtime.output_coils.clone();
        (start, end, values)
    };

    make_variables(address_space, nsidx, Table::OutputCoils, start, end, &folder_id, values, false, |i| format!("Output Coil {}", i));
}

fn add_input_registers(runtime: &Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
    let folder_id = address_space
        .add_folder("Input Registers", "Input Registers", parent_folder_id)
        .unwrap();
    // Add variables to the folder
    let (start, end, values) = {
        let runtime = runtime.read().unwrap();
        let (start, end) = start_end(runtime.config.input_register_base_address, runtime.config.input_register_count);
        let values = runtime.input_registers.clone();
        (start, end, values)
    };
    make_variables(address_space, nsidx, Table::InputRegisters, start, end, &folder_id, values, 0 as u16, |i| format!("Input Register {}", i));
}

fn add_output_registers(runtime: &Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
    let folder_id = address_space
        .add_folder("Output Registers", "Output Registers", parent_folder_id)
        .unwrap();
    // Add variables to the folder
    let (start, end, values) = {
        let runtime = runtime.read().unwrap();
        let (start, end) = start_end(runtime.config.output_register_base_address, runtime.config.output_register_count);
        let values = runtime.output_registers.clone();
        (start, end, values)
    };
    make_variables(address_space, nsidx, Table::OutputRegisters, start, end, &folder_id, values, 0 as u16, |i| format!("Output Register {}", i));
}

/// Creates variables and hooks them up to getters
fn make_variables<T>(address_space: &mut AddressSpace, nsidx: u16, table: Table, start: usize, end: usize, parent_folder_id: &NodeId, values: Arc<RwLock<Vec<T>>>, default_value: T, name_formatter: impl Fn(usize) -> String)
    where T: 'static + Copy + Send + Sync + Into<Variant>
{
    // Create variables
    let variables = (start..end).map(|i| {
        let name = name_formatter(i);
        let mut v = Variable::new(&make_node_id(nsidx, table, i as u16), &name, &name, default_value);
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
