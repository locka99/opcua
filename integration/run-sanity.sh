#!/bin/sh
export RUST_OPCUA_LOG=debug
cargo test -- --exact --test-threads=1 --ignored tests::connect_none
