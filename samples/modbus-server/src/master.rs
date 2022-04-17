// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use futures::{sink::Sink, stream::Stream, Future};
use tokio::sync as tsync;
use tokio_core::reactor::Core;
use tokio_modbus::{client, prelude::*};
use tokio_timer::Interval;

use opcua::sync::RwLock;

use crate::Runtime;

pub struct MODBUS {
    /// A remote handle
    remote: tokio_core::reactor::Remote,
    /// Sender of messages
    tx: tsync::mpsc::UnboundedSender<Message>,
}

impl MODBUS {
    pub fn run(runtime: Arc<RwLock<Runtime>>) -> MODBUS {
        let socket_addr = {
            let runtime = runtime.read();
            runtime.config.slave_address.parse().unwrap()
        };

        let (tx, rx) = tsync::mpsc::unbounded_channel();

        // This is a bit messy but the core needs to be created on the thread, but the handle
        // to the core is needed by the master to spawn tasks on it.
        let tx_for_master = tx.clone();
        let (rx_send_handle, tx_recv_handle) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let mut core = Core::new().unwrap();
            let handle = core.handle();

            let _ = rx_send_handle.send(core.remote());

            let task = tcp::connect(&handle, socket_addr)
                .map_err(|_| ())
                .and_then(move |ctx| {
                    spawn_receiver(&handle, rx, ctx, runtime.clone());
                    spawn_timer(&handle, tx, runtime)
                });
            core.run(task).unwrap();
            println!("MODBUS thread has finished");
        });

        let remote = tx_recv_handle.recv().unwrap();

        let master = MODBUS {
            tx: tx_for_master,
            remote,
        };

        master
    }

    pub fn write_to_coil(&self, addr: u16, value: bool) {
        println!("Writing to coil {} with value {:?}", addr, value);
        let tx = self.tx.clone();
        self.remote.spawn(move |_handle| {
            tx.send(Message::WriteCoil(addr, value))
                .map_err(|_| ())
                .map(|_| ())
        });
    }

    pub fn write_to_register(&self, addr: u16, value: u16) {
        println!("Writing to register {} with value {:x}", addr, value);
        let tx = self.tx.clone();
        self.remote.spawn(move |_handle| {
            tx.send(Message::WriteRegister(addr, value))
                .map_err(|_| ())
                .map(|_| ())
        });
    }
    pub fn write_to_registers(&self, addr: u16, values: Vec<u16>) {
        println!("Writing to registers {} with values {:x?}", addr, values);
        let tx = self.tx.clone();
        self.remote.spawn(move |_handle| {
            tx.send(Message::WriteRegisters(addr, values))
                .map_err(|_| ())
                .map(|_| ())
        });
    }
}

fn store_values_in_coils(values: Vec<bool>, coils: Arc<RwLock<Vec<bool>>>) {
    let mut coils = coils.write();
    coils.clear();
    coils.extend(values);
}

fn store_values_in_registers(values: Vec<u16>, registers: Arc<RwLock<Vec<u16>>>) {
    let mut registers = registers.write();
    registers.clear();
    registers.extend(values);
}

struct InputCoil;

impl InputCoil {
    pub fn async_read(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        runtime: &Arc<RwLock<Runtime>>,
    ) {
        let (coils, address, count) = InputCoil::begin_read_input_coils(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(
            ctx.read_discrete_inputs(address, count as u16)
                .map_err(move |err| {
                    println!("Read input coils error {:?}", err);
                    InputCoil::end_read_input_coils(&runtime_for_err);
                })
                .and_then(move |values| {
                    store_values_in_coils(values, coils.clone());
                    InputCoil::end_read_input_coils(&runtime);
                    Ok(())
                }),
        );
    }

    fn begin_read_input_coils(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<bool>>>, u16, u16) {
        let mut runtime = runtime.write();
        runtime.reading_input_coils = true;
        (
            runtime.input_coils.clone(),
            runtime.config.input_coils.base_address,
            runtime.config.input_coils.count,
        )
    }

    fn end_read_input_coils(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write();
        runtime.reading_input_coils = false;
    }
}

struct OutputCoil;

impl OutputCoil {
    pub fn async_read(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        runtime: &Arc<RwLock<Runtime>>,
    ) {
        let (coils, address, count) = OutputCoil::begin_read_output_coils(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(
            ctx.read_coils(address, count as u16)
                .map_err(move |err| {
                    println!("Read output coils error {:?}", err);
                    OutputCoil::end_read_output_coils(&runtime_for_err);
                })
                .and_then(move |values| {
                    store_values_in_coils(values, coils.clone());
                    OutputCoil::end_read_output_coils(&runtime);
                    Ok(())
                }),
        );
    }

    pub fn async_write(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        addr: u16,
        value: bool,
    ) {
        handle.spawn(ctx.write_single_coil(addr, value).map_err(move |_err| ()));
    }

    fn begin_read_output_coils(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<bool>>>, u16, u16) {
        let mut runtime = runtime.write();
        runtime.reading_output_coils = true;
        (
            runtime.output_coils.clone(),
            runtime.config.output_coils.base_address,
            runtime.config.output_coils.count,
        )
    }

    fn end_read_output_coils(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write();
        runtime.reading_output_coils = false;
    }
}

struct InputRegister;

impl InputRegister {
    pub fn async_read(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        runtime: &Arc<RwLock<Runtime>>,
    ) {
        let (registers, address, count) = InputRegister::begin_read_input_registers(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(
            ctx.read_input_registers(address, count as u16)
                .map_err(move |err| {
                    println!("Read input registers error {:?}", err);
                    InputRegister::end_read_input_registers(&runtime_for_err);
                })
                .and_then(move |values| {
                    store_values_in_registers(values, registers.clone());
                    InputRegister::end_read_input_registers(&runtime);
                    Ok(())
                }),
        );
    }

    fn begin_read_input_registers(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<u16>>>, u16, u16) {
        let mut runtime = runtime.write();
        runtime.reading_input_registers = true;
        (
            runtime.input_registers.clone(),
            runtime.config.input_registers.base_address,
            runtime.config.input_registers.count,
        )
    }

    fn end_read_input_registers(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write();
        runtime.reading_input_registers = false;
    }
}

struct OutputRegister;

impl OutputRegister {
    pub fn async_read(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        runtime: &Arc<RwLock<Runtime>>,
    ) {
        let (registers, address, count) = OutputRegister::begin_read_output_registers(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();
        handle.spawn(
            ctx.read_holding_registers(address, count as u16)
                .map_err(move |err| {
                    println!("Read input registers error {:?}", err);
                    OutputRegister::end_read_output_registers(&runtime_for_err);
                })
                .and_then(move |values| {
                    store_values_in_registers(values, registers.clone());
                    OutputRegister::end_read_output_registers(&runtime);
                    Ok(())
                }),
        );
    }

    pub fn async_write_register(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        addr: u16,
        value: u16,
    ) {
        handle.spawn(ctx.write_single_register(addr, value).map_err(|_| ()));
    }

    pub fn async_write_registers(
        handle: &tokio_core::reactor::Handle,
        ctx: &client::Context,
        addr: u16,
        values: &[u16],
    ) {
        handle.spawn(ctx.write_multiple_registers(addr, values).map_err(|_| ()));
    }

    fn begin_read_output_registers(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<u16>>>, u16, u16) {
        let mut runtime = runtime.write();
        runtime.reading_input_registers = true;
        (
            runtime.output_registers.clone(),
            runtime.config.output_registers.base_address,
            runtime.config.output_registers.count,
        )
    }

    fn end_read_output_registers(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write();
        runtime.reading_output_registers = false;
    }
}

enum Message {
    UpdateValues,
    WriteCoil(u16, bool),
    WriteRegister(u16, u16),
    WriteRegisters(u16, Vec<u16>),
}

fn spawn_receiver(
    handle: &tokio_core::reactor::Handle,
    rx: tsync::mpsc::UnboundedReceiver<Message>,
    ctx: client::Context,
    runtime: Arc<RwLock<Runtime>>,
) {
    let handle_for_action = handle.clone();
    let task = rx
        .for_each(move |msg| {
            match msg {
                Message::UpdateValues => {
                    // Test if the previous action is finished.
                    let (
                        read_input_registers,
                        read_output_registers,
                        read_input_coils,
                        read_output_coils,
                    ) = {
                        let runtime = runtime.read();
                        (
                            !runtime.reading_input_registers
                                && runtime.config.input_registers.readable(),
                            !runtime.reading_output_registers
                                && runtime.config.output_registers.readable(),
                            !runtime.reading_input_coils && runtime.config.input_coils.readable(),
                            !runtime.reading_output_coils && runtime.config.output_coils.readable(),
                        )
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
                }
                Message::WriteCoil(addr, value) => {
                    let runtime = runtime.read();
                    if runtime.config.output_coils.writable() {
                        OutputCoil::async_write(&handle_for_action, &ctx, addr, value);
                    }
                }
                Message::WriteRegister(addr, value) => {
                    let runtime = runtime.read();
                    if runtime.config.output_registers.writable() {
                        OutputRegister::async_write_register(&handle_for_action, &ctx, addr, value);
                    }
                }
                Message::WriteRegisters(addr, values) => {
                    let runtime = runtime.read();
                    if runtime.config.output_registers.writable() {
                        OutputRegister::async_write_registers(
                            &handle_for_action,
                            &ctx,
                            addr,
                            &values,
                        );
                    }
                }
            }
            Ok(())
        })
        .map_err(|_| ());
    handle.spawn(task);
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn spawn_timer(
    handle: &tokio_core::reactor::Handle,
    tx: tsync::mpsc::UnboundedSender<Message>,
    runtime: Arc<RwLock<Runtime>>,
) -> impl Future<Error = ()> {
    let interval = {
        let runtime = runtime.read();
        Duration::from_millis(runtime.config.read_interval as u64)
    };
    let handle = handle.clone();
    Interval::new(Instant::now(), interval)
        .map_err(|err| {
            println!("Timer error {:?}", err);
        })
        .map(move |x| (x, handle.clone(), tx.clone()))
        .for_each(|(_instant, handle, tx)| {
            handle.spawn(tx.send(Message::UpdateValues).map(|_| ()).map_err(|_| ()));
            Ok(())
        })
}
