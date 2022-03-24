#![no_main]
use libfuzzer_sys::fuzz_target;

use std::sync::{Arc, RwLock};

use bytes::BytesMut;
use tokio_util::codec::Decoder;

use opcua_core::prelude::*;

pub fn decode(buf: &mut BytesMut, codec: &mut TcpCodec) -> Result<Option<Message>, std::io::Error> {
    codec.decode(buf)
}

fuzz_target!(|data: &[u8]| {
    opcua_console_logging::init();
    // With some random data, just try and deserialize it
    let decoding_options = DecodingOptions::default();
    let abort = Arc::new(RwLock::new(false));
    let mut codec = TcpCodec::new(abort, decoding_options);
    let mut buf = BytesMut::from(data);
    let _ = decode(&mut buf, &mut codec);
});
