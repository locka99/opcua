use std::fmt::Debug;

use types::*;
use comms::*;
use services::*;

struct Test;

impl Test {
    pub fn setup() -> Test {
        let _ = ::init_logging();
        Test {}
    }
}

fn serialize_test_and_return<T>(value: T) -> T
    where T: BinaryEncoder<T> + Debug + PartialEq
{
    use std::io::Cursor;
    let mut buf = Cursor::new(vec![0u8; 16384]);

    let result = value.encode(&mut buf);
    assert!(result.is_ok());

    buf.set_position(0);

    let new_value: T = T::decode(&mut buf).unwrap();
    assert_eq!(value, new_value);
    new_value
}

fn get_sample_data_security_none() -> Vec<u8> {
    return vec![
        0x2f, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x63, 0x66,
        0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55,
        0x41, 0x2f, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63,
        0x79, 0x23, 0x4e, 0x6f, 0x6e, 0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x20, 0x9b,
        0xa2, 0xfa, 0xcc, 0x65, 0xd2, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
        0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x40, 0x9c, 0x00, 0x00];
}

fn get_sample_chunk() -> Chunk {
    let sample_data = get_sample_data_security_none();
    let sample_data_len = sample_data.len() as u32;
    Chunk {
        chunk_header: ChunkHeader {
            message_type: ChunkMessageType::OpenSecureChannel,
            is_final: ChunkType::Final,
            message_size: 12 + sample_data_len,
            secure_channel_id: 1,
            is_valid: true,
        },
        chunk_body: sample_data
    }
}

#[test]
fn test_read_open_secure_channel() {
    let _ = Test::setup();

    let chunker = Chunker::new();

    let chunk = get_sample_chunk();
    let chunks = vec![&chunk];

    let open_secure_channel_request: OpenSecureChannelRequest = chunker.decode_open_secure_channel_request(&chunks).unwrap();
    {
        let ref request_header = open_secure_channel_request.request_header;
        assert_eq!(request_header.timestamp.ticks(), 131279270199860000);
        assert_eq!(request_header.request_handle, 1);
        assert_eq!(request_header.return_diagnostics, 0);
        assert_eq!(request_header.audit_entry_id.is_null(), true);
        assert_eq!(request_header.timeout_hint, 0);
    }

    // TODO validate fields of open_secure_channel_request
}

// Encode the same chunk from a struct to data and back and again and compare
#[test]
fn test_reencode_open_secure_channel() {
    let _ = Test::setup();

    let chunker = Chunker::new();

    let chunk = get_sample_chunk();
    let chunks = vec![&chunk];

    //let open_secure_channel_request: OpenSecureChannelRequest = chunker.decode_open_secure_channel_request(&chunks).unwrap();
    //let new_open_secure_channel_request = serialize_test_and_return(open_secure_channel_request.clone());

    //assert_eq!(open_secure_channel_request, new_open_secure_channel_request);
}