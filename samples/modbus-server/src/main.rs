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
    sync::{Arc, RwLock},
    thread,
};

use clap::{App, Arg};

mod opcua;
mod master;
mod slave;

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

impl AliasType {
    /// Returns the size of the type in number of registers
    pub fn size_in_words(&self) -> u16 {
        match self {
            Self::Default | Self::Boolean | Self::Byte | Self::SByte | Self::UInt16 | Self::Int16 => 1,
            Self::UInt32 => 2,
            Self::Int32 => 2,
            Self::UInt64 => 4,
            Self::Int64 => 4,
            Self::Float => 2,
            Self::Double => 4
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

#[derive(Clone, Copy, PartialEq)]
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

impl Table {
    pub fn table_from_number(number: u16) -> (Table, u16) {
        if number <= 9999 {
            (Table::OutputCoils, number)
        } else if number >= 10001 && number <= 19999 {
            (Table::InputCoils, number - 10001)
        } else if number >= 30001 && number <= 39999 {
            (Table::InputRegisters, number - 30001)
        } else if number >= 40001 && number <= 49990 {
            (Table::OutputRegisters, number - 40001)
        } else {
            // This should have been caught when validating config file
            panic!("Number {} is out of range of any table", number);
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub slave_address: String,
    pub read_interval: u32,
    pub input_coil_base_address: u16,
    pub input_coil_count: u16,
    pub output_coil_base_address: u16,
    pub output_coil_count: u16,
    pub input_register_base_address: u16,
    pub input_register_count: u16,
    pub output_register_base_address: u16,
    pub output_register_count: u16,
    pub aliases: Option<Vec<Alias>>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ()> {
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

    pub fn valid(&self) -> bool {
        let mut valid = true;
        if self.slave_address.is_empty() {
            println!("No slave IP address specified");
            valid = false;
        }
        if self.input_coil_base_address >= 9998 || self.input_coil_base_address + self.input_coil_count > 9999 {
            println!("Input coil addresses are out of range");
            valid = false;
        }
        if self.output_coil_base_address >= 9998 || self.output_coil_base_address + self.output_coil_count > 9999 {
            println!("Output coil addresses are out of range");
            valid = false;
        }
        if self.input_register_base_address >= 9998 || self.input_register_base_address + self.input_register_count > 9999 {
            println!("Input register addresses are out of range");
            valid = false;
        }
        if self.output_register_base_address >= 9998 || self.output_register_base_address + self.output_register_count > 9999 {
            println!("Input register addresses are out of range");
            valid = false;
        }
        if let Some(ref aliases) = self.aliases {
            let set: std::collections::HashSet<&str> = aliases.iter().map(|a| a.name.as_ref()).collect::<_>();
            if set.len() != aliases.len() {
                println!("Aliases contains duplicate names");
                valid = false;
            }
            aliases.iter().for_each(|a| {
                // Check the register is addressable
                let number = a.number;
                let (table, addr) = Table::table_from_number(number);
                let in_range = match table {
                    Table::OutputCoils => {
                        addr >= self.output_coil_base_address && addr < self.output_coil_base_address + self.output_coil_count
                    }
                    Table::InputCoils => {
                        addr >= self.input_coil_base_address && addr < self.input_coil_base_address + self.input_coil_count
                    }
                    Table::InputRegisters => {
                        addr >= self.input_register_base_address && addr < self.input_register_base_address + self.input_register_count
                    }
                    Table::OutputRegisters => {
                        addr >= self.output_register_base_address && addr < self.output_register_base_address + self.output_register_base_address
                    }
                };

                if !in_range {
                    println!("Alias {} has an out of range register of {}, check base address and count of the corresponding table", a.name, number);
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
                    if end > 39999 || end > 49999 {
                        println!("Alias {} starts with number {} but has a data type whose word size {} that exceeds the table range", a.name, number, cnt);
                        valid = false;
                    }
                }
            });
        }
        valid
    }
}

#[derive(Clone)]
pub struct Runtime {
    pub config: Config,
    pub reading_input_registers: bool,
    pub reading_input_coils: bool,
    pub reading_output_registers: bool,
    pub reading_output_coils: bool,
    pub input_registers: Arc<RwLock<Vec<u16>>>,
    pub output_registers: Arc<RwLock<Vec<u16>>>,
    pub input_coils: Arc<RwLock<Vec<bool>>>,
    pub output_coils: Arc<RwLock<Vec<bool>>>,
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
    let config = if let Ok(config) = Config::load(&PathBuf::from(config_path)) {
        if !config.valid() {
            println!("Configuration file {} contains errors", config_path);
            std::process::exit(1);
        }
        config
    } else {
        println!("Configuration file {} could not be loaded", config_path);
        std::process::exit(1);
    };

    run(config, m.is_present("run-demo-slave"));
}

fn run(config: Config, run_demo_slave: bool) {
    let input_registers = vec![0u16; config.input_register_count as usize];
    let output_registers = vec![0u16; config.output_register_count as usize];
    let input_coils = vec![false; config.input_coil_count as usize];
    let output_coils = vec![false; config.output_coil_count as usize];

    let runtime = Runtime {
        config,
        reading_input_registers: false,
        reading_input_coils: false,
        reading_output_registers: false,
        reading_output_coils: false,
        input_registers: Arc::new(RwLock::new(input_registers)),
        output_registers: Arc::new(RwLock::new(output_registers)),
        input_coils: Arc::new(RwLock::new(input_coils)),
        output_coils: Arc::new(RwLock::new(output_coils)),
    };

    if run_demo_slave {
        println!("Running a demo MODBUS slave");
        slave::run_modbus_slave(&runtime.config.slave_address);
        // Wait for slave to be ready (a more sophisticated correct solution would listen for a Ready message or something)
        thread::sleep(std::time::Duration::from_millis(1000));
    }

    let runtime = Arc::new(RwLock::new(runtime));
    let modbus = master::MBMaster::run(runtime.clone());
    opcua::run(runtime, modbus);
}

