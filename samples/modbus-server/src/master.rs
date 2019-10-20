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

use crate::MBRuntime;

pub fn run(runtime: Arc<RwLock<MBRuntime>>) {
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

fn async_read_input_coils(handle: &tokio_core::reactor::Handle, ctx: &client::Context, runtime: Arc<RwLock<MBRuntime>>) {
    let (input_coils, input_coil_address, input_coil_count) = {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_coils = true;
        (runtime.input_coils.clone(), runtime.config.input_coil_base_address, runtime.config.input_coil_count)
    };
    let runtime_for_err = runtime.clone();
    handle.spawn(ctx.read_discrete_inputs(input_coil_address, input_coil_count as u16)
        .map_err(move |err| {
            println!("Read input coils error {:?}", err);
            let mut runtime = runtime_for_err.write().unwrap();
            runtime.reading_input_coils = false;
        })
        .and_then(move |values| {
            write_to_coils(values, input_coils.clone());
            let mut runtime = runtime.write().unwrap();
            runtime.reading_input_coils = false;
            Ok(())
        }));
}

fn async_read_input_registers(handle: &tokio_core::reactor::Handle, ctx: &client::Context, runtime: Arc<RwLock<MBRuntime>>) {
    let (input_registers, input_register_address, input_register_count) = {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = true;
        (runtime.input_registers.clone(), runtime.config.input_register_base_address, runtime.config.input_register_count)
    };
    let runtime_for_err = runtime.clone();
    handle.spawn(ctx.read_input_registers(input_register_address, input_register_count as u16)
        .map_err(move |err| {
            println!("Read input registers error {:?}", err);
            let mut runtime = runtime_for_err.write().unwrap();
            runtime.reading_input_registers = false;
        })
        .and_then(move |values| {
            write_to_registers(values, input_registers.clone());
            let mut runtime = runtime.write().unwrap();
            runtime.reading_input_registers = false;
            Ok(())
        }));
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn spawn_timer(handle: &tokio_core::reactor::Handle, ctx: client::Context, runtime: Arc<RwLock<MBRuntime>>) -> impl Future<Error=()> {
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
            let (read_input_registers, read_input_coils) = {
                let runtime = runtime.read().unwrap();
                (!runtime.reading_input_registers && runtime.config.input_register_count > 0, !runtime.reading_input_coils && runtime.config.input_coil_count > 0)
            };
            if read_input_registers {
                async_read_input_registers(&handle_for_action, &ctx, runtime.clone());
            }
            if read_input_coils {
                async_read_input_coils(&handle_for_action, &ctx, runtime.clone());
            }
            Ok(())
        })
}