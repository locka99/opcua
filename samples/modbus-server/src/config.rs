// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{fs::File, io::Read, path::Path};

use opcua::server::prelude::*;

use crate::Table;

#[derive(Deserialize, Clone, Copy, PartialEq)]
pub enum AliasType {
    Default,
    Boolean,
    Byte,
    SByte,
    UInt16,
    Int16,
    UInt32,
    Int32,
    UInt64,
    Int64,
    Float,
    Double,
}

impl Into<DataTypeId> for AliasType {
    fn into(self) -> DataTypeId {
        match self {
            Self::Boolean => DataTypeId::Boolean,
            Self::Byte => DataTypeId::Byte,
            Self::SByte => DataTypeId::SByte,
            Self::UInt16 | Self::Default => DataTypeId::UInt16,
            Self::Int16 => DataTypeId::Int16,
            Self::UInt32 => DataTypeId::UInt32,
            Self::Int32 => DataTypeId::Int32,
            Self::UInt64 => DataTypeId::UInt64,
            Self::Int64 => DataTypeId::Int64,
            Self::Float => DataTypeId::Float,
            Self::Double => DataTypeId::Double,
        }
    }
}

impl Into<VariantTypeId> for AliasType {
    fn into(self) -> VariantTypeId {
        match self {
            Self::Boolean => VariantTypeId::Boolean,
            Self::Byte => VariantTypeId::Byte,
            Self::SByte => VariantTypeId::SByte,
            Self::UInt16 | AliasType::Default => VariantTypeId::UInt16,
            Self::Int16 => VariantTypeId::Int16,
            Self::UInt32 => VariantTypeId::UInt32,
            Self::Int32 => VariantTypeId::Int32,
            Self::UInt64 => VariantTypeId::UInt64,
            Self::Int64 => VariantTypeId::Int64,
            Self::Float => VariantTypeId::Float,
            Self::Double => VariantTypeId::Double,
        }
    }
}

impl AliasType {
    /// Returns the size of the type in number of registers
    pub fn size_in_words(&self) -> u16 {
        match self {
            Self::Default
            | Self::Boolean
            | Self::Byte
            | Self::SByte
            | Self::UInt16
            | Self::Int16 => 1,
            Self::UInt32 => 2,
            Self::Int32 => 2,
            Self::UInt64 => 4,
            Self::Int64 => 4,
            Self::Float => 2,
            Self::Double => 4,
        }
    }
}

fn default_as_u16() -> AliasType {
    AliasType::Default
}

fn default_as_false() -> bool {
    false
}

#[derive(Deserialize, Clone)]
pub struct Alias {
    pub name: String,
    pub number: u16,
    #[serde(default = "default_as_u16")]
    pub data_type: AliasType,
    #[serde(default = "default_as_false")]
    pub writable: bool,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
pub enum AccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Default,
}

fn default_access_mode() -> AccessMode {
    AccessMode::Default
}

#[derive(Deserialize, Clone)]
pub struct TableConfig {
    pub base_address: u16,
    pub count: u16,
    #[serde(default = "default_access_mode")]
    pub access_mode: AccessMode,
}

impl Default for TableConfig {
    fn default() -> Self {
        Self {
            base_address: 0u16,
            count: 0u16,
            access_mode: AccessMode::Default,
        }
    }
}

impl TableConfig {
    pub fn valid(&self, table: Table) -> bool {
        let range_valid = if self.base_address >= 9998 || self.base_address + self.count > 9999 {
            println!("Base address or base address + count exceeds 0-9998 range");
            false
        } else {
            true
        };

        let access_valid = match self.access_mode {
            AccessMode::ReadWrite | AccessMode::WriteOnly => {
                if table == Table::InputCoils || table == Table::InputRegisters {
                    println!("Only output tables can have write access");
                    false
                } else {
                    true
                }
            }
            _ => true,
        };

        range_valid && access_valid
    }

    pub fn in_range(&self, addr: u16) -> bool {
        addr >= self.base_address && addr < self.base_address + self.count
    }

    pub fn writable(&self) -> bool {
        self.count > 0
            && (self.access_mode == AccessMode::WriteOnly
                || self.access_mode == AccessMode::ReadWrite)
    }

    pub fn readable(&self) -> bool {
        self.count > 0
            && (self.access_mode == AccessMode::ReadOnly
                || self.access_mode == AccessMode::ReadWrite)
    }
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub slave_address: String,
    pub read_interval: u32,
    pub input_coils: TableConfig,
    pub output_coils: TableConfig,
    pub input_registers: TableConfig,
    pub output_registers: TableConfig,
    pub aliases: Option<Vec<Alias>>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ()> {
        if let Ok(mut f) = File::open(path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                let config: std::result::Result<Config, _> = serde_yaml::from_str(&s);
                if let Ok(mut config) = config {
                    if config.input_coils.access_mode == AccessMode::Default {
                        config.input_coils.access_mode = AccessMode::ReadOnly;
                    }
                    if config.input_registers.access_mode == AccessMode::Default {
                        config.input_registers.access_mode = AccessMode::ReadOnly;
                    }
                    if config.output_coils.access_mode == AccessMode::Default {
                        config.output_coils.access_mode = AccessMode::ReadWrite;
                    }
                    if config.output_registers.access_mode == AccessMode::Default {
                        config.output_registers.access_mode = AccessMode::ReadWrite;
                    }
                    Ok(config)
                } else {
                    println!(
                        "Cannot deserialize configuration from {}",
                        path.to_string_lossy()
                    );
                    Err(())
                }
            } else {
                println!(
                    "Cannot read configuration file {} to string",
                    path.to_string_lossy()
                );
                Err(())
            }
        } else {
            println!("Cannot open configuration file {}", path.to_string_lossy());
            Err(())
        }
    }

    pub fn valid(&self) -> bool {
        let mut valid = true;
        if self.slave_address.is_empty() {
            println!("No slave IP address specified");
            valid = false;
        }
        if !self.input_coils.valid(Table::InputCoils) {
            println!("Input coils are invalid, check access mode and register range");
            valid = false;
        }
        if !self.output_coils.valid(Table::OutputCoils) {
            println!("Output coils are invalid, check access mode and register range");
            valid = false;
        }
        if !self.input_registers.valid(Table::InputRegisters) {
            println!("Input registers are invalid, check access mode and register range");
            valid = false;
        }
        if !self.output_registers.valid(Table::OutputRegisters) {
            println!("Input registers are invalid, check access mode and register range");
            valid = false;
        }
        if let Some(ref aliases) = self.aliases {
            let set: std::collections::HashSet<&str> =
                aliases.iter().map(|a| a.name.as_ref()).collect::<_>();
            if set.len() != aliases.len() {
                println!("Aliases contains duplicate names");
                valid = false;
            }
            aliases.iter().for_each(|a| {
                // Check the register is addressable
                let number = a.number;
                let (table, addr) = Table::table_from_number(number);
                let in_range = match table {
                    Table::OutputCoils => self.output_coils.in_range(addr),
                    Table::InputCoils => self.input_coils.in_range(addr),
                    Table::InputRegisters => self.input_registers.in_range(addr),
                    Table::OutputRegisters => self.output_registers.in_range(addr),
                };
                if !in_range {
                    println!("Alias {} has an out of range register of {}, check base address and count of the corresponding table", a.name, number);
                    valid = false;
                }

                let valid_writable = match table {
                    Table::OutputCoils => !a.writable || (a.writable && self.output_coils.access_mode != AccessMode::ReadOnly),
                    Table::InputCoils => !a.writable,
                    Table::InputRegisters => !a.writable,
                    Table::OutputRegisters => !a.writable || (a.writable && self.output_registers.access_mode != AccessMode::ReadOnly),
                };
                if !valid_writable {
                    println!("Alias {} is writable but table is not writable - check table", a.name);
                    valid = false;
                }
                if table == Table::OutputCoils || table == Table::InputCoils {
                    // Coils
                    // Coils must be booleans
                    if a.data_type != AliasType::Boolean && a.data_type != AliasType::Default {
                        println!("Alias {} for coil must be of type Boolean", a.name);
                        valid = false;
                    }
                } else {
                    // Check that the size of the type does not exceed the range
                    let cnt = a.data_type.size_in_words();
                    let end = number + cnt;
                    let max = if table == Table::InputRegisters { 39999 } else { 49999 };
                    if end > max {
                        println!("Alias {} starts with number {} but has a data type whose word size {} that exceeds the table max of {}", a.name, number, cnt, max);
                        valid = false;
                    }
                }
            });
        }
        valid
    }
}
