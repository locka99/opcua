//! This is a OPC UA server that is a MODBUS master - in MODBUS parlance the master is the thing
//! requesting information from a slave device.
//!
//! See README.md for more info. To make things easy, this code works against a simulator and has
//! hardcoded address and registers that it will map into OPC UA.
#[macro_use]
extern crate serde_derive;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    thread,
};

use clap::{App, Arg};

mod config;
mod opcua;
mod master;
mod slave;

#[derive(Clone, Copy, PartialEq)]
pub enum Table {
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

#[derive(Clone)]
pub struct Runtime {
    pub config: config::Config,
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
    let config = if let Ok(config) = config::Config::load(&PathBuf::from(config_path)) {
        if !config.valid() {
            println!("Configuration file {} contains errors", config_path);
            std::process::exit(1);
        }
        config
    } else {
        println!("Configuration file {} could not be loaded", config_path);
        std::process::exit(1);
    };

    opcua_console_logging::init();

    run(config, m.is_present("run-demo-slave"));
}

fn run(config: config::Config, run_demo_slave: bool) {
    let input_registers = vec![0u16; config.input_registers.count as usize];
    let output_registers = vec![0u16; config.output_registers.count as usize];
    let input_coils = vec![false; config.input_coils.count as usize];
    let output_coils = vec![false; config.output_coils.count as usize];

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
    let modbus = master::MODBUS::run(runtime.clone());
    opcua::run(runtime, modbus);
}

