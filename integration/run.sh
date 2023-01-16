#!/bin/sh
export RUST_OPCUA_LOG=debug
cd $(git rev-parse --show-toplevel)
cargo test --features test-vendored-openssl -- --test-threads=1 --ignored --exact $1 $2 $3 $4
