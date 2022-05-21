#![no_main]
use libfuzzer_sys::fuzz_target;

use crate::types::*;
use std::io::Cursor;

pub fn deserialize(data: &[u8], decoding_options: &DecodingOptions) -> Result<Variant, StatusCode> {
    // Decode this, don't expect panics or whatever
    let mut stream = Cursor::new(data);
    Variant::decode(&mut stream, &decoding_options)
}

fuzz_target!(|data: &[u8]| {
    crate::console_logging::init();
    let decoding_options = DecodingOptions::default();
    // With some random data, just try and deserialize it. The deserialize should either return
    // a Variant or an error. It shouldn't panic.
    let _ = deserialize(data, &decoding_options);
});
