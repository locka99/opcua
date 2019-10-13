#!/bin/sh
export RUST_OPCUA_LOG=debug
cargo test -- --test-threads=1 --ignored $1 $2 $3 $4
