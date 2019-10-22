use std::{
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

use futures::{Future, stream::Stream};
use tokio_core::reactor::Core;
use tokio_modbus::{
    client,
    prelude::*,
};
use tokio_timer::Interval;

use crate::Runtime;

pub fn run(runtime: Arc<RwLock<Runtime>>) {
    let socket_addr = {
        let runtime = runtime.read().unwrap();
        runtime.config.slave_address.parse().unwrap()
    };
    thread::spawn(move || {
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let task = tcp::connect(&handle, socket_addr)
            .map_err(|_| ())
            .and_then(move |ctx| {
                spawn_timer(&handle, ctx, runtime)
            });
        core.run(task).unwrap();
        println!("MODBUS thread has finished");
    });
}

fn write_to_coils(values: Vec<bool>, coils: Arc<RwLock<Vec<bool>>>) {
    let mut coils = coils.write().unwrap();
    coils.clear();
    coils.extend(values);
}

fn write_to_registers(values: Vec<u16>, registers: Arc<RwLock<Vec<u16>>>) {
    let mut registers = registers.write().unwrap();
    registers.clear();
    registers.extend(values);
}

struct InputCoil;

impl InputCoil {
    pub fn async_read(handle: &tokio_core::reactor::Handle, ctx: &client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (coils, address, count) = InputCoil::begin_read_input_coils(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(ctx.read_discrete_inputs(address, count as u16)
            .map_err(move |err| {
                println!("Read input coils error {:?}", err);
                InputCoil::end_read_input_coils(&runtime_for_err);
            })
            .and_then(move |values| {
                write_to_coils(values, coils.clone());
                InputCoil::end_read_input_coils(&runtime);
                Ok(())
            }));
    }

    fn begin_read_input_coils(runtime: &Arc<RwLock<Runtime>>) -> (Arc<RwLock<Vec<bool>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_coils = true;
        (runtime.input_coils.clone(), runtime.config.input_coil_base_address, runtime.config.input_coil_count)
    }

    fn end_read_input_coils(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_coils = false;
    }
}

struct OutputCoil;

impl OutputCoil {
    pub fn async_read(handle: &tokio_core::reactor::Handle, ctx: &client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (coils, address, count) = OutputCoil::begin_read_output_coils(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(ctx.read_coils(address, count as u16)
            .map_err(move |err| {
                println!("Read output coils error {:?}", err);
                OutputCoil::end_read_output_coils(&runtime_for_err);
            })
            .and_then(move |values| {
                write_to_coils(values, coils.clone());
                OutputCoil::end_read_output_coils(&runtime);
                Ok(())
            }));
    }

    fn begin_read_output_coils(runtime: &Arc<RwLock<Runtime>>) -> (Arc<RwLock<Vec<bool>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_output_coils = true;
        (runtime.output_coils.clone(), runtime.config.output_coil_base_address, runtime.config.output_coil_count)
    }

    fn end_read_output_coils(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_output_coils = false;
    }
}

struct InputRegister;

impl InputRegister {
    pub fn async_read(handle: &tokio_core::reactor::Handle, ctx: &client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (registers, address, count) = InputRegister::begin_read_input_registers(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(ctx.read_input_registers(address, count as u16)
            .map_err(move |err| {
                println!("Read input registers error {:?}", err);
                InputRegister::end_read_input_registers(&runtime_for_err);
            })
            .and_then(move |values| {
                write_to_registers(values, registers.clone());
                InputRegister::end_read_input_registers(&runtime);
                Ok(())
            }));
    }

    fn begin_read_input_registers(runtime: &Arc<RwLock<Runtime>>) -> (Arc<RwLock<Vec<u16>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = true;
        (runtime.input_registers.clone(), runtime.config.input_register_base_address, runtime.config.input_register_count)
    }

    fn end_read_input_registers(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = false;
    }
}

struct OutputRegister;

impl OutputRegister {
    pub fn async_read(handle: &tokio_core::reactor::Handle, ctx: &client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (registers, address, count) = OutputRegister::begin_read_output_registers(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(ctx.read_holding_registers(address, count as u16)
            .map_err(move |err| {
                println!("Read input registers error {:?}", err);
                OutputRegister::end_read_output_registers(&runtime_for_err);
            })
            .and_then(move |values| {
                write_to_registers(values, registers.clone());
                OutputRegister::end_read_output_registers(&runtime);
                Ok(())
            }));
    }

    fn begin_read_output_registers(runtime: &Arc<RwLock<Runtime>>) -> (Arc<RwLock<Vec<u16>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = true;
        (runtime.output_registers.clone(), runtime.config.output_register_base_address, runtime.config.output_register_count)
    }

    fn end_read_output_registers(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_output_registers = false;
    }
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn spawn_timer(handle: &tokio_core::reactor::Handle, ctx: client::Context, runtime: Arc<RwLock<Runtime>>) -> impl Future<Error=()> {
    let interval = {
        let runtime = runtime.read().unwrap();
        Duration::from_millis(runtime.config.read_interval as u64)
    };
    let handle_for_action = handle.clone();
    Interval::new(Instant::now(), interval)
        .map_err(|err| {
            println!("Timer error {:?}", err);
        })
        .for_each(move |_| {
            // Test if the previous action is finished.
            let (read_input_registers, read_output_registers, read_input_coils, read_output_coils) = {
                let runtime = runtime.read().unwrap();
                (!runtime.reading_input_registers && runtime.config.input_register_count > 0,
                 !runtime.reading_output_registers && runtime.config.output_register_count > 0,
                 !runtime.reading_input_coils && runtime.config.input_coil_count > 0,
                 !runtime.reading_output_coils && runtime.config.output_coil_count > 0)
            };
            if read_input_registers {
                InputRegister::async_read(&handle_for_action, &ctx, &runtime);
            }
            if read_output_registers {
                OutputRegister::async_read(&handle_for_action, &ctx, &runtime);
            }
            if read_input_coils {
                InputCoil::async_read(&handle_for_action, &ctx, &runtime);
            }
            if read_output_coils {
                OutputCoil::async_read(&handle_for_action, &ctx, &runtime);
            }
            Ok(())
        })
}