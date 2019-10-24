use std::{
    i8, i16, u16,
    mem,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use opcua_server::prelude::*;

use crate::{Alias, AliasType, Endianness, Runtime, Table};

// Runs the OPC UA server which is just a basic server with some variables hooked up to getters
pub fn run(runtime: Arc<RwLock<Runtime>>) {
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
fn add_variables(runtime: Arc<RwLock<Runtime>>, address_space: &mut AddressSpace, nsidx: u16) {
    // Create a folder under objects folder
    let modbus_folder_id = address_space
        .add_folder("MODBUS", "MODBUS", &NodeId::objects_folder_id())
        .unwrap();
    add_input_coils(&runtime, address_space, nsidx, &modbus_folder_id);
    add_output_coils(&runtime, address_space, nsidx, &modbus_folder_id);
    add_input_registers(&runtime, address_space, nsidx, &modbus_folder_id);
    add_output_registers(&runtime, address_space, nsidx, &modbus_folder_id);
    add_aliases(&runtime, address_space, nsidx, &modbus_folder_id);
}

fn start_end(base_address: u16, count: u16) -> (usize, usize) {
    let start = base_address as usize;
    let end = start + count as usize;
    if end > 9999 {
        panic!("Base address and / or count are out of MODBUS addressable range, check your configuration file");
    }
    (start, end)
}

fn add_input_coils(runtime: &Arc<RwLock<Runtime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
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

fn add_output_coils(runtime: &Arc<RwLock<Runtime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
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

fn add_input_registers(runtime: &Arc<RwLock<Runtime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
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

fn add_output_registers(runtime: &Arc<RwLock<Runtime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
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

pub struct AliasGetter {
    runtime: Arc<RwLock<Runtime>>,
    alias: Alias,
}

impl AttributeGetter for AliasGetter {
    fn get(&mut self, _node_id: &NodeId, _attribute_id: AttributeId, _max_age: f64) -> Result<Option<DataValue>, StatusCode> {
        AliasGetter::get_alias_value(self.runtime.clone(), self.alias.data_type, self.alias.number)
    }
}

impl AliasGetter {
    pub fn new(runtime: Arc<RwLock<Runtime>>, alias: Alias) -> AliasGetter {
        AliasGetter { runtime, alias }
    }

    fn get_alias_value(runtime: Arc<RwLock<Runtime>>, data_type: AliasType, number: u16) -> Result<Option<DataValue>, StatusCode> {
        let runtime = runtime.read().unwrap();
        let (table, address) = Table::table_from_number(number);
        let value = match table {
            Table::OutputCoils => Self::value_from_coil(address, runtime.config.output_coil_base_address, runtime.config.output_coil_count, &runtime.output_coils),
            Table::InputCoils => Self::value_from_coil(address, runtime.config.input_coil_base_address, runtime.config.input_coil_count, &runtime.input_coils),
            Table::InputRegisters => Self::value_from_register(address, runtime.config.input_register_base_address, runtime.config.input_register_count, data_type, runtime.config.endianness, &runtime.input_registers),
            Table::OutputRegisters => Self::value_from_register(address, runtime.config.output_register_base_address, runtime.config.output_register_count, data_type, runtime.config.endianness, &runtime.output_registers),
        };
        Ok(Some(DataValue::new(value)))
    }

    fn value_from_coil(address: u16, base_address: u16, cnt: u16, values: &Arc<RwLock<Vec<bool>>>) -> Variant {
        if address < base_address || address >= base_address + cnt {
            // This should have been caught when validating config file
            panic!("Address {} is not in the range of register values polled", address);
        }
        let values = values.read().unwrap();
        let idx = (address - base_address) as usize;
        Variant::from(*values.get(idx).unwrap())
    }

    /// Transmuting the value means taking the bytes in the word, and casting those
    /// bytes to be an i16.
    fn transmute_u16_to_i16(w: u16) -> i16 {
        i16::from_le_bytes(w.to_le_bytes())
    }

    fn value_from_word(data_type: AliasType, w: u16) -> Variant {
        // Produce a data value
        match data_type {
            AliasType::Boolean => {
                // non-zero = true
                Variant::from(w != 0)
            }
            AliasType::Byte => {
                // Clamp 0-255
                Variant::from(if w > 255 { 255u8 } else { w as u8 })
            }
            AliasType::SByte => {
                // Transmute word to a i16 and then clamp between MIN and MAX
                let v = Self::transmute_u16_to_i16(w);
                let v = if v < i8::MIN as i16 { i8::MIN } else if v > i8::MAX as i16 { i8::MAX } else { v as i8 };
                Variant::from(v)
            }
            AliasType::UInt16 => {
                // Straight conversion
                Variant::from(w)
            }
            AliasType::Int16 => {
                // Transmute
                Variant::from(Self::transmute_u16_to_i16(w))
            }
            _ => panic!()
        }
    }


    fn value_from_words(data_type: AliasType, endianness: Endianness, w: &[u16]) -> Variant {
        match data_type {
            AliasType::UInt32 => {
                // Transmute
                let (a, b, c, d) = endianness.switch_words_to_bytes([w[0], w[1]]);
                let v = unsafe {
                    mem::transmute::<[u8; 4], u32>([a, b, c, d])
                };
                Variant::from(v)
            }
            AliasType::Int32 => {
                // Transmute
                let (a, b, c, d) = endianness.switch_words_to_bytes([w[0], w[1]]);
                let v = unsafe {
                    mem::transmute::<[u8; 4], i32>([a, b, c, d])
                };
                Variant::from(v)
            }
            AliasType::Float => {
                // Transmute
                let (a, b, c, d) = endianness.switch_words_to_bytes([w[0], w[1]]);
                let v = unsafe {
                    mem::transmute::<[u8; 4], f32>([a, b, c, d])
                };
                Variant::from(v)
            }
            AliasType::UInt64 => {
                // Transmute
                let (a, b, c, d, e, f, g, h) = endianness.switch_double_words_to_bytes([w[0], w[1], w[2], w[3]]);
                let v = unsafe {
                    mem::transmute::<[u8; 8], u64>([a, b, c, d, e, f, g, h])
                };
                Variant::from(v)
            }
            AliasType::Int64 => {
                // Transmute
                let (a, b, c, d, e, f, g, h) = endianness.switch_double_words_to_bytes([w[0], w[1], w[2], w[3]]);
                let v = unsafe {
                    mem::transmute::<[u8; 8], i64>([a, b, c, d, e, f, g, h])
                };
                Variant::from(v)
            }
            AliasType::Double => {
                let (a, b, c, d, e, f, g, h) = endianness.switch_double_words_to_bytes([w[0], w[1], w[2], w[3]]);
                let v = unsafe {
                    mem::transmute::<[u8; 8], f64>([a, b, c, d, e, f, g, h])
                };
                Variant::from(v)
            }
            _ => panic!()
        }
    }

    fn value_from_register(address: u16, base_address: u16, cnt: u16, data_type: AliasType, endianness: Endianness, values: &Arc<RwLock<Vec<u16>>>) -> Variant {
        let size = data_type.size_in_words();
        if address < base_address || address >= (base_address + cnt) || (address + size) >= (base_address + cnt) {
            // This should have been caught when validating config file
            panic!("Address {} is not in the range of register values polled", address);
        }

        let idx = (address - base_address) as usize;
        let values = values.read().unwrap();

        if size == 1 {
            let w = *values.get(idx).unwrap();
            Self::value_from_word(data_type, w)
        } else {
            match data_type {
                AliasType::UInt32 | AliasType::Int32 | AliasType::Float => Self::value_from_words(data_type, endianness, &values[idx..idx + 1]),
                AliasType::UInt64 | AliasType::Int64 | AliasType::Double => Self::value_from_words(data_type, endianness, &values[idx..idx + 3]),
                _ => panic!()
            }
        }
    }
}


#[test]
fn values_1_word() {
    assert_eq!(AliasGetter::value_from_word(AliasType::Boolean, 0u16), Variant::Boolean(false));
    assert_eq!(AliasGetter::value_from_word(AliasType::Boolean, 1u16), Variant::Boolean(true));
    assert_eq!(AliasGetter::value_from_word(AliasType::Boolean, 3u16), Variant::Boolean(true));

    // Tests that rely on bytes in the word, are expressed in little endian notation, created from using https://cryptii.com/pipes/integer-encoder
    // The intent is these tests should be able to run on other endian systems and still work.

    // SByte
    assert_eq!(AliasGetter::value_from_word(AliasType::SByte, u16::from_le_bytes([0x81, 0xff])), Variant::SByte(-127i8));
    assert_eq!(AliasGetter::value_from_word(AliasType::SByte, u16::from_le_bytes([0x80, 0xff])), Variant::SByte(-128i8));
    assert_eq!(AliasGetter::value_from_word(AliasType::SByte, u16::from_le_bytes([0x7f, 0x00])), Variant::SByte(127i8));
    assert_eq!(AliasGetter::value_from_word(AliasType::SByte, u16::from_le_bytes([0xff, 0x00])), Variant::SByte(127i8));

    // Int16
    assert_eq!(AliasGetter::value_from_word(AliasType::Int16, u16::from_le_bytes([0x9f, 0xf0])), Variant::Int16(-3937));
    assert_eq!(AliasGetter::value_from_word(AliasType::Int16, u16::from_le_bytes([0x00, 0x00])), Variant::Int16(0));
    assert_eq!(AliasGetter::value_from_word(AliasType::Int16, u16::from_le_bytes([0x6f, 0x7d])), Variant::Int16(32111));

    // UInt16
    assert_eq!(AliasGetter::value_from_word(AliasType::UInt16, 26555), Variant::UInt16(26555));
}

#[test]
fn values_2_words() {
    // UInt32
    // Int32
    // Float
}

#[test]
fn values_4_words() {
    // TODO
    // UInt64
    // Int64
    // Double
}

fn add_aliases(runtime: &Arc<RwLock<Runtime>>, address_space: &mut AddressSpace, nsidx: u16, parent_folder_id: &NodeId) {
    let aliases = {
        let runtime = runtime.read().unwrap();
        runtime.config.aliases.clone()
    };
    if let Some(aliases) = aliases {
        let parent_folder_id = address_space
            .add_folder("Aliases", "Aliases", parent_folder_id)
            .unwrap();

        let variables = aliases.into_iter().map(move |alias| {
            // Alias node ids are just their name in the list
            let node_id = NodeId::new(nsidx, alias.name.clone());
            let mut v = Variable::new(&node_id, &alias.name, &alias.name, 0u16);
            v.set_value_getter(Arc::new(Mutex::new(AliasGetter::new(runtime.clone(), alias))));
            v
        }).collect();
        let _ = address_space.add_variables(variables, &parent_folder_id);
    }
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
