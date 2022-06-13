mod date_time;
mod encoding;
mod node_id;
mod serde;
mod variant;

use std::cmp::PartialEq;
use std::fmt::Debug;
use std::io::Cursor;

use crate::types::{argument::Argument, status_codes::StatusCode, *};

pub fn serialize_test_and_return<T>(value: T) -> T
where
    T: BinaryEncoder<T> + Debug + PartialEq + Clone,
{
    serialize_test_and_return_expected(value.clone(), value)
}

pub fn serialize_as_stream<T>(value: T) -> Cursor<Vec<u8>>
where
    T: BinaryEncoder<T> + Debug,
{
    // Ask the struct for its byte length
    let byte_len = value.byte_len();
    let mut stream = Cursor::new(vec![0u8; byte_len]);

    // Encode to stream
    let start_pos = stream.position();
    let result = value.encode(&mut stream);
    let end_pos = stream.position();
    assert!(result.is_ok());

    // This ensures the size reported is the same as the byte length impl
    assert_eq!(result.unwrap(), byte_len);

    // Test that the position matches the byte_len
    assert_eq!((end_pos - start_pos) as usize, byte_len);

    let actual = stream.into_inner();
    println!("value = {:?}", value);
    println!("encoded bytes = {:?}", actual);
    Cursor::new(actual)
}

pub fn serialize_test_and_return_expected<T>(value: T, expected_value: T) -> T
where
    T: BinaryEncoder<T> + Debug + PartialEq,
{
    let mut stream = serialize_as_stream(value);

    let decoding_options = DecodingOptions::test();
    let new_value: T = T::decode(&mut stream, &decoding_options).unwrap();
    println!("new value = {:?}", new_value);
    assert_eq!(expected_value, new_value);
    new_value
}

pub fn serialize_test<T>(value: T)
where
    T: BinaryEncoder<T> + Debug + PartialEq + Clone,
{
    let _ = serialize_test_and_return(value);
}

pub fn serialize_test_expected<T>(value: T, expected_value: T)
where
    T: BinaryEncoder<T> + Debug + PartialEq,
{
    let _ = serialize_test_and_return_expected(value, expected_value);
}

pub fn serialize_and_compare<T>(value: T, expected: &[u8])
where
    T: BinaryEncoder<T> + Debug + PartialEq,
{
    // Ask the struct for its byte length
    let byte_len = value.byte_len();
    let mut stream = Cursor::new(vec![0; byte_len]);

    let result = value.encode(&mut stream);
    assert!(result.is_ok());

    let size = result.unwrap();
    assert_eq!(size, expected.len());
    println!("Size of encoding = {}", size);
    assert_eq!(size, byte_len);

    let actual = stream.into_inner();

    println!("actual {:?}", actual);
    println!("expected {:?}", expected);

    for i in 0..size {
        assert_eq!(actual[i], expected[i])
    }
}
