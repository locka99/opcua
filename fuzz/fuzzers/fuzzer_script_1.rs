#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate opcua_core;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
});
