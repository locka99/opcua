#!/bin/sh
export RUST_OPCUA_LOG=debug
cd $(git rev-parse --show-toplevel)
cargo test --features test-vendored-openssl -- --exact --test-threads=1 --ignored tests::connect_none
