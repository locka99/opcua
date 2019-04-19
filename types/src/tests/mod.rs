mod encoding;
mod date_time;
mod parse;
mod serialize;
mod variant;
mod hello;
mod supported_message;

use std::fmt::Debug;
use std::cmp::PartialEq;
use std::io::Cursor;

use crate::*;
use crate::argument::Argument;
use crate::status_codes::StatusCode;
use crate::node_ids::*;

pub fn serialize_test_and_return<T>(value: T) -> T
    where T: BinaryEncoder<T> + Debug + PartialEq + Clone
{
    serialize_test_and_return_expected(value.clone(), value)
}

pub fn serialize_test_and_return_expected<T>(value: T, expected_value: T) -> T
    where T: BinaryEncoder<T> + Debug + PartialEq
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
    let mut stream = Cursor::new(actual);

    let decoding_limits = DecodingLimits::default();
    let new_value: T = T::decode(&mut stream, &decoding_limits).unwrap();
    println!("new value = {:?}", new_value);
    assert_eq!(expected_value, new_value);
    new_value
}

pub fn serialize_test<T>(value: T)
    where T: BinaryEncoder<T> + Debug + PartialEq + Clone
{
    let _ = serialize_test_and_return(value);
}

pub fn serialize_test_expected<T>(value: T, expected_value: T)
    where T: BinaryEncoder<T> + Debug + PartialEq
{
    let _ = serialize_test_and_return_expected(value, expected_value);
}


pub fn serialize_and_compare<T>(value: T, expected: &[u8])
    where T: BinaryEncoder<T> + Debug + PartialEq
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
