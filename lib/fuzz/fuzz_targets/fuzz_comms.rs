#![no_main]
use libfuzzer_sys::fuzz_target;

use bytes::BytesMut;
use tokio_util::codec::Decoder;

use opcua::core::comms::tcp_codec::TcpCodec;
use opcua::types::DecodingOptions;

fuzz_target!(|data: &[u8]| {
    opcua::console_logging::init();
    // With some random data, just try and deserialize it
    let decoding_options = DecodingOptions::default();
    let mut codec = TcpCodec::new(decoding_options);
    let mut buf = BytesMut::from(data);
    let _ = codec.decode(&mut buf);
});
