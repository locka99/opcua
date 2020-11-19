// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use tokio::sync as tsync;

use tokio_modbus::{client, prelude::*};

use crate::Runtime;
use tokio::stream::StreamExt;

pub struct MODBUS {
    /// Sender of messages
    tx: tsync::mpsc::UnboundedSender<Message>,
}

impl MODBUS {
    pub fn run(runtime: Arc<RwLock<Runtime>>) -> MODBUS {
        let socket_addr = {
            let runtime = runtime.read().unwrap();
            runtime.config.slave_address.parse().unwrap()
        };

        let (tx, rx) = tsync::mpsc::unbounded_channel();

        // This is a bit messy but the core needs to be created on the thread, but the handle
        // to the core is needed by the master to spawn tasks on it.
        let tx_for_master = tx.clone();
        tokio_compat::run_std(async move {
            let task = tcp::connect(socket_addr).await;
            if task.is_err() {
                return;
            }

            spawn_receiver(rx, task.unwrap(), runtime.clone());
            spawn_timer(tx, runtime)
        });

        let master = MODBUS { tx: tx_for_master };

        master
    }
    //todo why run on the conext of tokio?
    fn send_message(&self, m: Message) {
        let r = self.tx.send(m);
        match r {
            Err(err) => println!("sendMessage  err={}", err),
            Ok(_) => {}
        }
    }
    pub fn write_to_coil(&self, addr: u16, value: bool) {
        println!("Writing to coil {} with value {:?}", addr, value);
        self.send_message(Message::WriteCoil(addr, value));
    }

    pub fn write_to_register(&self, addr: u16, value: u16) {
        println!("Writing to register {} with value {:x}", addr, value);
        self.send_message(Message::WriteRegister(addr, value));
    }
    pub fn write_to_registers(&self, addr: u16, values: Vec<u16>) {
        println!("Writing to registers {} with values {:x?}", addr, values);
        self.send_message(Message::WriteRegisters(addr, values));
    }
}

fn store_values_in_coils(values: Vec<bool>, coils: Arc<RwLock<Vec<bool>>>) {
    let mut coils = coils.write().unwrap();
    coils.clear();
    coils.extend(values);
}

fn store_values_in_registers(values: Vec<u16>, registers: Arc<RwLock<Vec<u16>>>) {
    let mut registers = registers.write().unwrap();
    registers.clear();
    registers.extend(values);
}

struct InputCoil;

impl InputCoil {
    pub async fn async_read(ctx: &mut client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (coils, address, count) = InputCoil::begin_read_input_coils(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();

        let r = ctx.read_discrete_inputs(address, count as u16).await;
        match r {
            Err(err) => {
                println!("Read input coils error {:?}", err);
                InputCoil::end_read_input_coils(&runtime_for_err);
            }
            Ok(values) => {
                store_values_in_coils(values, coils.clone());
                InputCoil::end_read_input_coils(&runtime);
            }
        }
    }

    fn begin_read_input_coils(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<bool>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_coils = true;
        (
            runtime.input_coils.clone(),
            runtime.config.input_coils.base_address,
            runtime.config.input_coils.count,
        )
    }

    fn end_read_input_coils(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_coils = false;
    }
}

struct OutputCoil;

impl OutputCoil {
    pub async fn async_read(ctx: &mut client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (coils, address, count) = OutputCoil::begin_read_output_coils(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();

        let r = ctx.read_coils(address, count as u16).await;
        match r {
            Err(err) => {
                println!("Read output coils error {:?}", err);
                OutputCoil::end_read_output_coils(&runtime_for_err);
            }
            Ok(values) => {
                store_values_in_coils(values, coils.clone());
                OutputCoil::end_read_output_coils(&runtime);
            }
        }
    }

    pub async fn async_write(ctx: &mut client::Context, addr: u16, value: bool) {
        let r = ctx.write_single_coil(addr, value).await;
        if r.is_err() {
            println!("async write {:?}", r);
        }
    }

    fn begin_read_output_coils(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<bool>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_output_coils = true;
        (
            runtime.output_coils.clone(),
            runtime.config.output_coils.base_address,
            runtime.config.output_coils.count,
        )
    }

    fn end_read_output_coils(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_output_coils = false;
    }
}

struct InputRegister;

impl InputRegister {
    pub async fn async_read(ctx: &mut client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (registers, address, count) = InputRegister::begin_read_input_registers(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();

        let r = ctx.read_input_registers(address, count as u16).await;
        match r {
            Err(err) => {
                println!("Read input registers error {:?}", err);
                InputRegister::end_read_input_registers(&runtime_for_err);
            }
            Ok(values) => {
                store_values_in_registers(values, registers.clone());
                InputRegister::end_read_input_registers(&runtime);
            }
        }
    }

    fn begin_read_input_registers(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<u16>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = true;
        (
            runtime.input_registers.clone(),
            runtime.config.input_registers.base_address,
            runtime.config.input_registers.count,
        )
    }

    fn end_read_input_registers(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = false;
    }
}

struct OutputRegister;

impl OutputRegister {
    pub async fn async_read(ctx: &mut client::Context, runtime: &Arc<RwLock<Runtime>>) {
        let (registers, address, count) = OutputRegister::begin_read_output_registers(runtime);
        let runtime = runtime.clone();
        let runtime_for_err = runtime.clone();

        let r = ctx.read_holding_registers(address, count as u16).await;
        match r {
            Err(err) => {
                println!("Read input registers error {:?}", err);
                OutputRegister::end_read_output_registers(&runtime_for_err);
            }
            Ok(values) => {
                store_values_in_registers(values, registers.clone());
                OutputRegister::end_read_output_registers(&runtime);
            }
        }
    }

    pub async fn async_write_register(ctx: &mut client::Context, addr: u16, value: u16) {
        let r = ctx.write_single_register(addr, value).await;
        if r.is_err() {
            println!("async_write_register {:?}", r);
        }
    }

    pub async fn async_write_registers(ctx: &mut client::Context, addr: u16, values: &[u16]) {
        let r = ctx.write_multiple_registers(addr, values).await;
        if r.is_err() {
            println!("async_write_registers {:?}", r);
        }
    }

    fn begin_read_output_registers(
        runtime: &Arc<RwLock<Runtime>>,
    ) -> (Arc<RwLock<Vec<u16>>>, u16, u16) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_input_registers = true;
        (
            runtime.output_registers.clone(),
            runtime.config.output_registers.base_address,
            runtime.config.output_registers.count,
        )
    }

    fn end_read_output_registers(runtime: &Arc<RwLock<Runtime>>) {
        let mut runtime = runtime.write().unwrap();
        runtime.reading_output_registers = false;
    }
}

#[derive(Debug)]
enum Message {
    UpdateValues,
    WriteCoil(u16, bool),
    WriteRegister(u16, u16),
    WriteRegisters(u16, Vec<u16>),
}

fn spawn_receiver(
    mut rx: tsync::mpsc::UnboundedReceiver<Message>,
    mut ctx: client::Context,
    runtime: Arc<RwLock<Runtime>>,
) {
    let task = async move {
        while let Some(msg) = rx.next().await {
            match msg {
                Message::UpdateValues => {
                    // Test if the previous action is finished.
                    let (
                        read_input_registers,
                        read_output_registers,
                        read_input_coils,
                        read_output_coils,
                    ) = {
                        let runtime = runtime.read().unwrap();
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
                        InputRegister::async_read(&mut ctx, &runtime).await;
                    }
                    if read_output_registers {
                        OutputRegister::async_read(&mut ctx, &runtime).await;
                    }
                    if read_input_coils {
                        InputCoil::async_read(&mut ctx, &runtime).await;
                    }
                    if read_output_coils {
                        OutputCoil::async_read(&mut ctx, &runtime).await;
                    }
                }
                Message::WriteCoil(addr, value) => {
                    let is_writable = {
                        let runtime = runtime.read().unwrap();
                        runtime.config.output_coils.writable()
                    };

                    if is_writable {
                        OutputCoil::async_write(&mut ctx, addr, value).await;
                    }
                }
                Message::WriteRegister(addr, value) => {
                    let is_writable = {
                        let runtime = runtime.read().unwrap();
                        runtime.config.output_coils.writable()
                    };

                    if is_writable {
                        OutputRegister::async_write_register(&mut ctx, addr, value).await;
                    }
                }
                Message::WriteRegisters(addr, values) => {
                    let is_writable = {
                        let runtime = runtime.read().unwrap();
                        runtime.config.output_coils.writable()
                    };

                    if is_writable {
                        OutputRegister::async_write_registers(&mut ctx, addr, &values).await;
                    }
                }
            }
        }
    };
    tokio::spawn(task);
}

/// Returns a read timer future which periodically polls the MODBUS slave for some values
fn spawn_timer(tx: tsync::mpsc::UnboundedSender<Message>, runtime: Arc<RwLock<Runtime>>) {
    let interval = {
        let runtime = runtime.read().unwrap();
        Duration::from_millis(runtime.config.read_interval as u64)
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now(), interval);
        loop {
            interval.next().await;
            let _ = tx.send(Message::UpdateValues);
        }
    });
}
