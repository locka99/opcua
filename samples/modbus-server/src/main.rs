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

#[derive(Deserialize, Clone)]
pub struct MBAlias {
    pub name: String,
    pub register_number: u32,
    pub data_type: String,
}

#[derive(Deserialize, Clone)]
pub struct MBConfig {
    pub slave_address: String,
    pub read_interval: u32,
    pub output_coil_base_address: u16,
    pub output_coil_count: usize,
    pub input_coil_base_address: u16,
    pub input_coil_count: usize,
    pub input_register_base_address: u16,
    pub input_register_count: usize,
    pub output_register_base_address: u16,
    pub output_register_count: usize,
    pub aliases: Option<Vec<MBAlias>>,
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

#[derive(Clone)]
pub struct MBRuntime {
    pub config: MBConfig,
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
    let config = MBConfig::load(&PathBuf::from(config_path)).unwrap();

    let input_registers = vec![0u16; config.input_register_count];
    let output_registers = vec![0u16; config.output_register_count];
    let input_coils = vec![false; config.input_coil_count];
    let output_coils = vec![false; config.output_coil_count];

    let runtime = MBRuntime {
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

    if m.is_present("run-demo-slave") {
        println!("Running a demo MODBUS slave");
        slave::run_modbus_slave(&runtime.config.slave_address);
        // Wait for slave to be ready (a more sophisticated correct solution would listen for a Ready message or something)
        thread::sleep(std::time::Duration::from_millis(1000));
    }

    let runtime = Arc::new(RwLock::new(runtime));
    master::run(runtime.clone());
    opcua::run(runtime);
}

