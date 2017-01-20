use std::io::{Read, Write, Result};

use types::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum SecurityTokenRequestType {
    Issue = 0,
    Renew = 1
}

impl BinaryEncoder<SecurityTokenRequestType> for SecurityTokenRequestType {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        // All enums are Int32
        write_i32(stream, *self as Int32)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        // All enums are Int32
        let security_token_request_type = read_i32(stream)?;
        Ok(match security_token_request_type {
            0 => SecurityTokenRequestType::Issue,
            1 => SecurityTokenRequestType::Renew,
            _ => {
                error!("Don't know what security token request type {} is", security_token_request_type);
                SecurityTokenRequestType::Issue
            }
        })
    }
}