// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{f32, f64, i16, i32, i64, i8, path::PathBuf, sync::Arc, u16};

use opcua::server::prelude::*;
use opcua::sync::{Mutex, RwLock};

use crate::{
    config::{Alias, AliasType, TableConfig},
    master::MODBUS,
    Runtime, Table,
};

// Runs the OPC UA server which is just a basic server with some variables hooked up to getters
pub fn run(runtime: Arc<RwLock<Runtime>>, modbus: MODBUS) {
    let config = ServerConfig::load(&PathBuf::from("../server.conf")).unwrap();
    let server = ServerBuilder::from_config(config).server().unwrap();

    let address_space = server.address_space();

    let modbus = Arc::new(Mutex::new(modbus));

    {
        let mut address_space = address_space.write();
        let nsidx = address_space.register_namespace("urn:MODBUS").unwrap();
        add_variables(runtime, modbus, &mut address_space, nsidx);
    }
    server.run();
}

/// Calculate a register number from the table and data address
fn register_number(table: Table, address: u16) -> u32 {
    let base = match table {
        Table::OutputCoils => 1,
        Table::InputCoils => 10001,
        Table::InputRegisters => 30001,
        Table::OutputRegisters => 40001,
    };
    base + address as u32
}

/// Make a node id for the coil/register based on its table and the address
fn make_node_id(nsidx: u16, table: Table, address: u16) -> NodeId {
    NodeId::new(nsidx, register_number(table, address))
}

/// Adds all the MODBUS variables to the address space
fn add_variables(
    runtime: Arc<RwLock<Runtime>>,
    modbus: Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
) {
    // Create a folder under objects folder
    let modbus_folder_id = address_space
        .add_folder("MODBUS", "MODBUS", &NodeId::objects_folder_id())
        .unwrap();
    add_input_coils(&runtime, &modbus, address_space, nsidx, &modbus_folder_id);
    add_output_coils(&runtime, &modbus, address_space, nsidx, &modbus_folder_id);
    add_input_registers(&runtime, &modbus, address_space, nsidx, &modbus_folder_id);
    add_output_registers(&runtime, &modbus, address_space, nsidx, &modbus_folder_id);
    add_aliases(&runtime, &modbus, address_space, nsidx, &modbus_folder_id);
}

fn start_end(table_config: &TableConfig) -> (usize, usize) {
    let start = table_config.base_address as usize;
    let end = start + table_config.count as usize;
    if end > 9999 {
        panic!("Base address and / or count are out of MODBUS addressable range, check your configuration file");
    }
    (start, end)
}

fn add_input_coils(
    runtime: &Arc<RwLock<Runtime>>,
    modbus: &Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
    parent_folder_id: &NodeId,
) {
    let folder_id = address_space
        .add_folder("Input Coils", "Input Coils", parent_folder_id)
        .unwrap();

    let (start, end, values) = {
        let runtime = runtime.read();
        let (start, end) = start_end(&runtime.config.input_coils);
        let values = runtime.input_coils.clone();
        (start, end, values)
    };

    make_variables(
        modbus,
        address_space,
        nsidx,
        Table::InputCoils,
        start,
        end,
        &folder_id,
        values,
        false,
        |i| format!("Input Coil {}", i),
    );
}

fn add_output_coils(
    runtime: &Arc<RwLock<Runtime>>,
    modbus: &Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
    parent_folder_id: &NodeId,
) {
    let folder_id = address_space
        .add_folder("Output Coils", "Output Coils", parent_folder_id)
        .unwrap();

    let (start, end, values) = {
        let runtime = runtime.read();
        let (start, end) = start_end(&runtime.config.output_coils);
        let values = runtime.output_coils.clone();
        (start, end, values)
    };

    make_variables(
        modbus,
        address_space,
        nsidx,
        Table::OutputCoils,
        start,
        end,
        &folder_id,
        values,
        false,
        |i| format!("Output Coil {}", i),
    );
}

fn add_input_registers(
    runtime: &Arc<RwLock<Runtime>>,
    modbus: &Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
    parent_folder_id: &NodeId,
) {
    let folder_id = address_space
        .add_folder("Input Registers", "Input Registers", parent_folder_id)
        .unwrap();
    // Add variables to the folder
    let (start, end, values) = {
        let runtime = runtime.read();
        let (start, end) = start_end(&runtime.config.input_registers);
        let values = runtime.input_registers.clone();
        (start, end, values)
    };
    make_variables(
        modbus,
        address_space,
        nsidx,
        Table::InputRegisters,
        start,
        end,
        &folder_id,
        values,
        0 as u16,
        |i| format!("Input Register {}", i),
    );
}

fn add_output_registers(
    runtime: &Arc<RwLock<Runtime>>,
    modbus: &Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
    parent_folder_id: &NodeId,
) {
    let folder_id = address_space
        .add_folder("Output Registers", "Output Registers", parent_folder_id)
        .unwrap();
    // Add variables to the folder
    let (start, end, values) = {
        let runtime = runtime.read();
        let (start, end) = start_end(&runtime.config.output_registers);
        let values = runtime.output_registers.clone();
        (start, end, values)
    };
    make_variables(
        modbus,
        address_space,
        nsidx,
        Table::OutputRegisters,
        start,
        end,
        &folder_id,
        values,
        0 as u16,
        |i| format!("Output Register {}", i),
    );
}

fn add_aliases(
    runtime: &Arc<RwLock<Runtime>>,
    modbus: &Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
    parent_folder_id: &NodeId,
) {
    let aliases = {
        let runtime = runtime.read();
        runtime.config.aliases.clone()
    };
    if let Some(aliases) = aliases {
        let parent_folder_id = address_space
            .add_folder("Aliases", "Aliases", parent_folder_id)
            .unwrap();

        // Create variables for all of the aliases
        aliases.into_iter().for_each(move |alias| {
            // Create a getter/setter
            let getter_setter = Arc::new(Mutex::new(AliasGetterSetter::new(
                runtime.clone(),
                modbus.clone(),
                alias.clone(),
            )));
            // Create a variable for the alias
            let node_id = NodeId::new(nsidx, alias.name.clone());
            let data_type: DataTypeId = alias.data_type.into();
            let v = VariableBuilder::new(&node_id, &alias.name, &alias.name)
                .organized_by(&parent_folder_id)
                .data_type(data_type)
                .value(0u16)
                .value_getter(getter_setter.clone());

            let v = if alias.writable {
                v.value_setter(getter_setter).writable()
            } else {
                v
            };

            v.insert(address_space);
        });
    }
}

/// Creates variables and hooks them up to getters
fn make_variables<T>(
    modbus: &Arc<Mutex<MODBUS>>,
    address_space: &mut AddressSpace,
    nsidx: u16,
    table: Table,
    start: usize,
    end: usize,
    parent_folder_id: &NodeId,
    values: Arc<RwLock<Vec<T>>>,
    default_value: T,
    name_formatter: impl Fn(usize) -> String,
) where
    T: 'static + Copy + Send + Sync + Into<Variant>,
{
    // Create variables
    (start..end).for_each(|i| {
        let addr = i as u16;
        let name = name_formatter(i);
        let values = values.clone();
        let v = VariableBuilder::new(&make_node_id(nsidx, table, addr), &name, &name)
            .organized_by(parent_folder_id)
            .value(default_value)
            .value_getter(AttrFnGetter::new_boxed(
                move |_node_id,
                      _timestamps_to_return,
                      _attribute_id,
                      _numeric_range,
                      _name,
                      _f|
                      -> Result<Option<DataValue>, StatusCode> {
                    let values = values.read();
                    let value = *values.get(i - start).unwrap();
                    Ok(Some(DataValue::new_now(value)))
                },
            ));

        // Output tables have setters too
        let v = match table {
            Table::InputCoils => v.data_type(DataTypeId::Boolean),
            Table::OutputCoils => {
                let modbus = modbus.clone();
                v.data_type(DataTypeId::Boolean)
                    .value_setter(AttrFnSetter::new_boxed(
                        move |_node_id, _attribute_id, _index_range, value| {
                            // Try to cast to a bool
                            let value = if let Some(value) = value.value {
                                value.cast(VariantTypeId::Boolean)
                            } else {
                                Variant::Empty
                            };
                            if let Variant::Boolean(value) = value {
                                let modbus = modbus.lock();
                                modbus.write_to_coil(addr, value);
                                Ok(())
                            } else {
                                Err(StatusCode::BadTypeMismatch)
                            }
                        },
                    ))
                    .writable()
            }
            Table::InputRegisters => v.data_type(DataTypeId::UInt16),
            Table::OutputRegisters => {
                let modbus = modbus.clone();
                v.data_type(DataTypeId::UInt16)
                    .value_setter(AttrFnSetter::new_boxed(
                        move |_node_id, _attribute_id, _index_range, value| {
                            let value = if let Some(value) = value.value {
                                value.cast(VariantTypeId::UInt16)
                            } else {
                                Variant::Empty
                            };
                            if let Variant::UInt16(value) = value {
                                let modbus = modbus.lock();
                                modbus.write_to_register(addr, value);
                                Ok(())
                            } else {
                                Err(StatusCode::BadTypeMismatch)
                            }
                        },
                    ))
                    .writable()
            }
        };
        v.insert(address_space);
    });
}

pub struct AliasGetterSetter {
    runtime: Arc<RwLock<Runtime>>,
    modbus: Arc<Mutex<MODBUS>>,
    alias: Alias,
}

impl AttributeGetter for AliasGetterSetter {
    fn get(
        &mut self,
        _node_id: &NodeId,
        _timestamps_to_return: TimestampsToReturn,
        _attribute_id: AttributeId,
        _index_range: NumericRange,
        _data_encoding: &QualifiedName,
        __max_age: f64,
    ) -> Result<Option<DataValue>, StatusCode> {
        AliasGetterSetter::get_alias_value(
            self.runtime.clone(),
            self.alias.data_type,
            self.alias.number,
        )
    }
}

impl AttributeSetter for AliasGetterSetter {
    fn set(
        &mut self,
        _node_id: &NodeId,
        _attribute_id: AttributeId,
        _index_range: NumericRange,
        data_value: DataValue,
    ) -> Result<(), StatusCode> {
        if !self.is_writable() {
            panic!("Attribute setter should not have been callable")
        }
        if let Some(value) = data_value.value {
            let _ = AliasGetterSetter::set_alias_value(
                self.modbus.clone(),
                self.alias.data_type,
                self.alias.number,
                value,
            )?;
            Ok(())
        } else {
            Err(StatusCode::BadUnexpectedError)
        }
    }
}

impl AliasGetterSetter {
    pub fn new(
        runtime: Arc<RwLock<Runtime>>,
        modbus: Arc<Mutex<MODBUS>>,
        alias: Alias,
    ) -> AliasGetterSetter {
        AliasGetterSetter {
            runtime,
            modbus,
            alias,
        }
    }

    fn is_writable(&self) -> bool {
        let (table, _) = Table::table_from_number(self.alias.number);
        let table_writable = match table {
            Table::OutputCoils | Table::OutputRegisters => true,
            Table::InputCoils | Table::InputRegisters => false,
        };
        self.alias.writable && table_writable
    }

    fn get_alias_value(
        runtime: Arc<RwLock<Runtime>>,
        data_type: AliasType,
        number: u16,
    ) -> Result<Option<DataValue>, StatusCode> {
        let runtime = runtime.read();
        let (table, address) = Table::table_from_number(number);
        let value = match table {
            Table::OutputCoils => {
                Self::value_from_coil(address, &runtime.config.output_coils, &runtime.output_coils)
            }
            Table::InputCoils => {
                Self::value_from_coil(address, &runtime.config.input_coils, &runtime.input_coils)
            }
            Table::InputRegisters => Self::value_from_register(
                address,
                &runtime.config.input_registers,
                data_type,
                &runtime.input_registers,
            ),
            Table::OutputRegisters => Self::value_from_register(
                address,
                &runtime.config.output_registers,
                data_type,
                &runtime.output_registers,
            ),
        };
        Ok(Some(DataValue::new_now(value)))
    }

    fn set_alias_value(
        modbus: Arc<Mutex<MODBUS>>,
        data_type: AliasType,
        number: u16,
        value: Variant,
    ) -> Result<(), StatusCode> {
        let (table, addr) = Table::table_from_number(number);
        match table {
            Table::OutputCoils => {
                let value = value.cast(VariantTypeId::Boolean);
                if let Variant::Boolean(v) = value {
                    let modbus = modbus.lock();
                    modbus.write_to_coil(addr, v);
                    Ok(())
                } else {
                    Err(StatusCode::BadUnexpectedError)
                }
            }
            Table::OutputRegisters => {
                // Cast to the alias' expected type
                let variant_type: VariantTypeId = data_type.into();
                let value = value.cast(variant_type);
                // Write the words
                let (_, words) =
                    Self::value_to_words(value).map_err(|_| StatusCode::BadUnexpectedError)?;
                let modbus = modbus.lock();
                modbus.write_to_registers(addr, words);
                Ok(())
            }
            _ => panic!("Invalid table"),
        }
    }

    fn value_from_coil(
        address: u16,
        table_config: &TableConfig,
        values: &Arc<RwLock<Vec<bool>>>,
    ) -> Variant {
        let base_address = table_config.base_address;
        let cnt = table_config.count;
        if address < base_address || address >= base_address + cnt {
            // This should have been caught when validating config file
            panic!(
                "Address {} is not in the range of register values polled",
                address
            );
        }
        let values = values.read();
        let idx = (address - base_address) as usize;
        Variant::from(*values.get(idx).unwrap())
    }

    fn word_2_to_bytes(w: &[u16]) -> [u8; 4] {
        assert_eq!(w.len(), 2, "Invalid length for 32-bit value");
        let w0 = w[0].to_be_bytes();
        let w1 = w[1].to_be_bytes();
        [w0[0], w0[1], w1[0], w1[1]]
    }

    fn word_4_to_bytes(w: &[u16]) -> [u8; 8] {
        assert_eq!(w.len(), 4, "Invalid length for 64-bit value");
        let w0 = w[0].to_be_bytes();
        let w1 = w[1].to_be_bytes();
        let w2 = w[2].to_be_bytes();
        let w3 = w[3].to_be_bytes();
        [w0[0], w0[1], w1[0], w1[1], w2[0], w2[1], w3[0], w3[1]]
    }

    fn value_to_words(value: Variant) -> Result<(AliasType, Vec<u16>), ()> {
        match value {
            Variant::Boolean(v) => {
                let v = if v { 1u16 } else { 0u16 };
                Ok((AliasType::Boolean, vec![v]))
            }
            Variant::Byte(v) => Ok((AliasType::Byte, vec![v as u16])),
            Variant::SByte(v) => {
                let v = v as u16;
                Ok((AliasType::SByte, vec![v]))
            }
            Variant::UInt16(v) => Ok((AliasType::UInt16, vec![v])),
            Variant::Int16(v) => {
                let v = u16::from_be_bytes(v.to_be_bytes());
                Ok((AliasType::Int16, vec![v]))
            }
            Variant::UInt32(v) => {
                let b = v.to_be_bytes();
                let v0 = u16::from_be_bytes([b[0], b[1]]);
                let v1 = u16::from_be_bytes([b[2], b[3]]);
                Ok((AliasType::UInt32, vec![v0, v1]))
            }
            Variant::Int32(v) => {
                let b = v.to_be_bytes();
                let v0 = u16::from_be_bytes([b[0], b[1]]);
                let v1 = u16::from_be_bytes([b[2], b[3]]);
                Ok((AliasType::Int32, vec![v0, v1]))
            }
            Variant::UInt64(v) => {
                let b = v.to_be_bytes();
                let v0 = u16::from_be_bytes([b[0], b[1]]);
                let v1 = u16::from_be_bytes([b[2], b[3]]);
                let v2 = u16::from_be_bytes([b[4], b[5]]);
                let v3 = u16::from_be_bytes([b[6], b[7]]);
                Ok((AliasType::UInt64, vec![v0, v1, v2, v3]))
            }
            Variant::Int64(v) => {
                let b = v.to_be_bytes();
                let v0 = u16::from_be_bytes([b[0], b[1]]);
                let v1 = u16::from_be_bytes([b[2], b[3]]);
                let v2 = u16::from_be_bytes([b[4], b[5]]);
                let v3 = u16::from_be_bytes([b[6], b[7]]);
                Ok((AliasType::Int64, vec![v0, v1, v2, v3]))
            }
            Variant::Float(v) => {
                let v = v.to_bits();
                let b = v.to_be_bytes();
                let v0 = u16::from_be_bytes([b[0], b[1]]);
                let v1 = u16::from_be_bytes([b[2], b[3]]);
                Ok((AliasType::Float, vec![v0, v1]))
            }
            Variant::Double(v) => {
                let v = v.to_bits();
                let b = v.to_be_bytes();
                let v0 = u16::from_be_bytes([b[0], b[1]]);
                let v1 = u16::from_be_bytes([b[2], b[3]]);
                let v2 = u16::from_be_bytes([b[4], b[5]]);
                let v3 = u16::from_be_bytes([b[6], b[7]]);
                Ok((AliasType::Double, vec![v0, v1, v2, v3]))
            }
            _ => Err(()),
        }
    }

    fn word_to_value(data_type: AliasType, w: u16) -> Variant {
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
                // Transmute bits and then clamp between MIN and MAX
                let v = i16::from_be_bytes(w.to_be_bytes());
                let v = if v < i8::MIN as i16 {
                    i8::MIN
                } else if v > i8::MAX as i16 {
                    i8::MAX
                } else {
                    v as i8
                };
                Variant::from(v)
            }
            AliasType::UInt16 => {
                // Straight conversion
                Variant::from(w)
            }
            AliasType::Int16 => {
                // Transmute bits
                Variant::from(i16::from_be_bytes(w.to_be_bytes()))
            }
            _ => panic!(),
        }
    }
    fn words_to_value(data_type: AliasType, w: &[u16]) -> Variant {
        match data_type {
            AliasType::UInt32 => {
                // Transmute bits
                let b = Self::word_2_to_bytes(w);
                let v = u32::from_be_bytes(b);
                Variant::from(v)
            }
            AliasType::Int32 => {
                // Transmute bits
                let b = Self::word_2_to_bytes(w);
                let v = i32::from_be_bytes(b);
                Variant::from(v)
            }
            AliasType::Float => {
                // Transmute bits
                // f32::from_be_bytes is a nightly function so code turns to u32 bits and then calls a function
                // to transmute the bits to a float.
                let b = Self::word_2_to_bytes(w);
                let bits = u32::from_be_bytes(b);
                let v = f32::from_bits(bits);
                Variant::from(v)
            }
            AliasType::UInt64 => {
                // Transmute bits
                let b = Self::word_4_to_bytes(w);
                let v = u64::from_be_bytes(b);
                Variant::from(v)
            }
            AliasType::Int64 => {
                // Transmute bits
                let b = Self::word_4_to_bytes(w);
                let v = i64::from_be_bytes(b);
                Variant::from(v)
            }
            AliasType::Double => {
                // Transmute bits
                // f64::from_be_bytes is a nightly function so code turns to u64 bits and then calls a function
                // to transmute the bits to a float.
                let b = Self::word_4_to_bytes(w);
                let bits = u64::from_be_bytes(b);
                let v = f64::from_bits(bits);
                Variant::from(v)
            }
            _ => panic!(),
        }
    }

    fn value_from_register(
        address: u16,
        table_config: &TableConfig,
        data_type: AliasType,
        values: &Arc<RwLock<Vec<u16>>>,
    ) -> Variant {
        let size = data_type.size_in_words();
        let base_address = table_config.base_address;
        let cnt = table_config.count;
        if address < base_address
            || address >= (base_address + cnt)
            || (address + size) >= (base_address + cnt)
        {
            // This should have been caught when validating config file
            panic!(
                "Address {} is not in the range of register values polled",
                address
            );
        }

        let idx = (address - base_address) as usize;
        let values = values.read();

        if size == 1 {
            let w = *values.get(idx).unwrap();
            Self::word_to_value(data_type, w)
        } else {
            match data_type {
                AliasType::UInt32 | AliasType::Int32 | AliasType::Float => {
                    Self::words_to_value(data_type, &values[idx..=idx + 1])
                }
                AliasType::UInt64 | AliasType::Int64 | AliasType::Double => {
                    Self::words_to_value(data_type, &values[idx..=idx + 3])
                }
                _ => panic!(),
            }
        }
    }
}

#[test]
fn values_1_word() {
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::Boolean, 0u16),
        Variant::Boolean(false)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::Boolean, 1u16),
        Variant::Boolean(true)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::Boolean, 3u16),
        Variant::Boolean(true)
    );

    // Tests that rely on bytes in the word, are expressed in little endian notation, created from using https://cryptii.com/pipes/integer-encoder
    // The intent is these tests should be able to run on other endian systems and still work.

    // SByte
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::SByte, u16::from_le_bytes([0x81, 0xff])),
        Variant::SByte(-127i8)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::SByte, u16::from_le_bytes([0x80, 0xff])),
        Variant::SByte(-128i8)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::SByte, u16::from_le_bytes([0x7f, 0x00])),
        Variant::SByte(127i8)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::SByte, u16::from_le_bytes([0xff, 0x00])),
        Variant::SByte(127i8)
    );

    // Int16
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::Int16, u16::from_le_bytes([0x9f, 0xf0])),
        Variant::Int16(-3937)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::Int16, u16::from_le_bytes([0x00, 0x00])),
        Variant::Int16(0)
    );
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::Int16, u16::from_le_bytes([0x6f, 0x7d])),
        Variant::Int16(32111)
    );

    // UInt16
    assert_eq!(
        AliasGetterSetter::word_to_value(AliasType::UInt16, 26555),
        Variant::UInt16(26555)
    );
}

#[test]
fn values_2_words() {
    // UInt32
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::UInt32, &[0x0000, 0x0001]),
        Variant::UInt32(1)
    );
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::UInt32, &[0x0001, 0x0000]),
        Variant::UInt32(0x00010000)
    );

    // Int32
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::Int32, &[0xfffe, 0x1dc0]),
        Variant::Int32(-123456i32)
    );
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::Int32, &[0x3ade, 0x68b1]),
        Variant::Int32(987654321i32)
    );

    // Float
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::Float, &[0x0000, 0x0000]),
        Variant::Float(0f32)
    );
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::Float, &[0x4400, 0x0000]),
        Variant::Float(512f32)
    );
    if let Variant::Float(v) =
        AliasGetterSetter::words_to_value(AliasType::Float, &[0x449A, 0x522B])
    {
        // Expect value to be 1234.5678
        assert!((v - 1234.5678).abs() < f32::EPSILON);
    } else {
        panic!();
    }
}

#[test]
fn values_4_words() {
    // UInt64
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::UInt64, &[0x0000, 0x0000, 0x0000, 0x0001]),
        Variant::UInt64(1)
    );
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::UInt64, &[0x0000, 0x0000, 0x0001, 0x0000]),
        Variant::UInt64(0x0000000000010000)
    );
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::UInt64, &[0x0123, 0x4567, 0x89AB, 0xCDEF]),
        Variant::UInt64(0x0123456789ABCDEF)
    );

    // Int64
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::UInt64, &[0x0123, 0x4567, 0x89AB, 0xCDEF]),
        Variant::UInt64(0x0123456789ABCDEF)
    );

    // Double
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::Double, &[0x0000, 0x0000, 0x0000, 0x0000]),
        Variant::Double(0f64)
    );
    assert_eq!(
        AliasGetterSetter::words_to_value(AliasType::Double, &[0x4080, 0x0000, 0x0000, 0x0000]),
        Variant::Double(512f64)
    );
    if let Variant::Double(v) =
        AliasGetterSetter::words_to_value(AliasType::Double, &[0x4093, 0x4A45, 0x6D5C, 0xFAAD])
    {
        // Expect value to be 1234.5678
        assert!((v - 1234.5678).abs() < f64::EPSILON);
    } else {
        panic!();
    }
}
