#![no_main]
use std::io;

use libfuzzer_sys::fuzz_target;

use bytes::BytesMut;

use opcua::core::prelude::*;
use tokio_util::codec::Decoder;

pub fn decode(buf: &mut BytesMut, codec: &mut dyn Decoder<Item = Message, Error = io::Error>) -> Result<Option<Message>, std::io::Error> {
    codec.decode(buf)
}

fuzz_target!(|data: &[u8]| {
    opcua::console_logging::init();
    // With some random data, just try and deserialize it
    let decoding_options = DecodingOptions::default();
    let mut codec = TcpCodec::new(decoding_options);
    let mut buf = BytesMut::from(data);
    let _ = decode(&mut buf, &mut codec);
});
