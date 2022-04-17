// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock
use std::{sync::Arc, thread, time};

use futures::future::{self, FutureResult};
use tokio_service::Service;

use tokio_modbus::prelude::*;

use opcua::sync::RwLock;

struct Data {
    pub input_coils: Vec<bool>,
    pub output_coils: Vec<bool>,
    pub input_registers: Vec<u16>,
    pub output_registers: Vec<u16>,
}

impl Data {
    const ACTIVE_VALUES: usize = 10;
    const NUM_VALUES: usize = 9999;

    pub fn new() -> Data {
        Data {
            input_coils: vec![false; Self::NUM_VALUES],
            output_coils: vec![false; Self::NUM_VALUES],
            input_registers: vec![0u16; Self::NUM_VALUES],
            output_registers: vec![0u16; Self::NUM_VALUES],
        }
    }

    pub fn update_values(&mut self, elapsed: std::time::Duration) {
        let elapsed = elapsed.as_secs();
        // Some values will be updated, some will remain static for testing purposes
        for i in 0..Self::ACTIVE_VALUES {
            let register_value = (i as u64 + elapsed) % std::u16::MAX as u64;
            self.input_registers[i] = register_value as u16;
            self.output_registers[i] = register_value as u16;
            self.input_coils[i] = (i as u64 + elapsed) % 2 == 0;
            self.output_coils[i] = (i as u64 + elapsed) % 2 == 0;
        }
    }
}

struct MbServer {
    start_time: time::Instant,
    data: Arc<RwLock<Data>>,
}

impl MbServer {
    fn update_values(&self) {
        let mut data = self.data.write();
        data.update_values(time::Instant::now() - self.start_time);
    }
}

impl Service for MbServer {
    type Request = Request;
    type Response = Response;
    type Error = std::io::Error;
    type Future = FutureResult<Self::Response, Self::Error>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.update_values();
        match req {
            Request::ReadInputRegisters(addr, cnt) => {
                let data = self.data.read();
                let start = addr as usize;
                let end = start + cnt as usize;
                let rsp = Response::ReadInputRegisters(data.input_registers[start..end].to_vec());
                future::ok(rsp)
            }
            Request::ReadHoldingRegisters(addr, cnt) => {
                let data = self.data.read();
                let start = addr as usize;
                let end = start + cnt as usize;
                let rsp =
                    Response::ReadHoldingRegisters(data.output_registers[start..end].to_vec());
                future::ok(rsp)
            }
            Request::ReadDiscreteInputs(addr, cnt) => {
                let data = self.data.read();
                let start = addr as usize;
                let end = start + cnt as usize;
                let rsp = Response::ReadDiscreteInputs(data.input_coils[start..end].to_vec());
                future::ok(rsp)
            }
            Request::ReadCoils(addr, cnt) => {
                let data = self.data.read();
                let start = addr as usize;
                let end = start + cnt as usize;
                let rsp = Response::ReadCoils(data.output_coils[start..end].to_vec());
                future::ok(rsp)
            }
            Request::WriteSingleCoil(addr, value) => {
                let mut data = self.data.write();
                data.output_coils[addr as usize] = value;
                let rsp = Response::WriteSingleCoil(addr);
                future::ok(rsp)
            }
            Request::WriteSingleRegister(addr, value) => {
                let mut data = self.data.write();
                data.output_registers[addr as usize] = value;
                let rsp = Response::WriteSingleRegister(addr, value);
                future::ok(rsp)
            }
            Request::WriteMultipleRegisters(addr, words) => {
                let mut data = self.data.write();
                words
                    .iter()
                    .enumerate()
                    .for_each(|(i, w)| data.output_registers[addr as usize + i] = *w);
                let rsp = Response::WriteMultipleRegisters(addr, words.len() as u16);
                future::ok(rsp)
            }
            _ => unimplemented!(),
        }
    }
}

pub fn run_modbus_slave(address: &str) {
    let socket_addr = address.parse().unwrap();
    println!("Starting up slave...");
    let _server = thread::spawn(move || {
        tcp::Server::new(socket_addr).serve(|| {
            Ok(MbServer {
                start_time: time::Instant::now(),
                data: Arc::new(RwLock::new(Data::new())),
            })
        });
    });
}
