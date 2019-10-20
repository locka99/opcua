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
        add_variables(runtime, &mut address_space);
    }
    server.run();
}

/// Adds all the MODBUS variables to the address space
fn add_variables(runtime: Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace) {
    // Create a folder under objects folder
    let modbus_folder_id = address_space
        .add_folder("MODBUS", "MODBUS", &NodeId::objects_folder_id())
        .unwrap();

    add_input_coils(runtime.clone(), address_space, &modbus_folder_id);
    add_input_registers(runtime, address_space, &modbus_folder_id);
}

fn add_input_coils(runtime: Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, parent_folder_id: &NodeId) {
    let input_coils_id = address_space
        .add_folder("Input Coils", "Input Coils", parent_folder_id)
        .unwrap();

    let (start, end, values) = {
        let runtime = runtime.read().unwrap();
        let start = runtime.config.input_coil_base_address as usize;
        let end = start + runtime.config.input_coil_count;
        let values = runtime.input_coils.clone();
        (start, end, values)
    };

    make_variables(address_space, start, end, &input_coils_id, values, false, |i| format!("Input Coil {}", i));
}

fn add_input_registers(runtime: Arc<RwLock<MBRuntime>>, address_space: &mut AddressSpace, parent_folder_id: &NodeId) {
    let input_registers_id = address_space
        .add_folder("Input Registers", "Input Registers", parent_folder_id)
        .unwrap();

    // Add variables to the folder
    let (start, end, values) = {
        let runtime = runtime.read().unwrap();
        let start = runtime.config.input_register_base_address as usize;
        let end = start + runtime.config.input_register_count;
        let values = runtime.input_registers.clone();
        (start, end, values)
    };

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
