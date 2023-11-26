// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::io::{Read, Write};

use crate::types::{constants, status_code::StatusCode, *};

use crate::crypto::{SecurityPolicy, Thumbprint, X509};

/// Holds the security header associated with the chunk. Secure channel requests use an asymmetric
/// security header, regular messages use a symmetric security header.
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityHeader {
    Asymmetric(AsymmetricSecurityHeader),
    Symmetric(SymmetricSecurityHeader),
}

impl BinaryEncoder<SecurityHeader> for SecurityHeader {
    fn byte_len(&self) -> usize {
        match self {
            SecurityHeader::Asymmetric(value) => value.byte_len(),
            SecurityHeader::Symmetric(value) => value.byte_len(),
        }
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        match self {
            SecurityHeader::Asymmetric(value) => value.encode(stream),
            SecurityHeader::Symmetric(value) => value.encode(stream),
        }
    }

    fn decode<S: Read>(_: &mut S, _: &DecodingOptions) -> EncodingResult<Self> {
        unimplemented!();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SymmetricSecurityHeader {
    pub token_id: u32,
}

impl BinaryEncoder<SymmetricSecurityHeader> for SymmetricSecurityHeader {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        self.token_id.encode(stream)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let token_id = u32::decode(stream, decoding_options)?;
        Ok(SymmetricSecurityHeader { token_id })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsymmetricSecurityHeader {
    pub security_policy_uri: UAString,
    pub sender_certificate: ByteString,
    pub receiver_certificate_thumbprint: ByteString,
}

impl BinaryEncoder<AsymmetricSecurityHeader> for AsymmetricSecurityHeader {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.security_policy_uri.byte_len();
        size += self.sender_certificate.byte_len();
        size += self.receiver_certificate_thumbprint.byte_len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.security_policy_uri.encode(stream)?;
        size += self.sender_certificate.encode(stream)?;
        size += self.receiver_certificate_thumbprint.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let security_policy_uri = UAString::decode(stream, decoding_options)?;
        let sender_certificate = ByteString::decode(stream, decoding_options)?;
        let receiver_certificate_thumbprint = ByteString::decode(stream, decoding_options)?;

        // validate sender_certificate_length < MaxCertificateSize
        if sender_certificate.value.is_some()
            && sender_certificate.value.as_ref().unwrap().len() >= constants::MAX_CERTIFICATE_LENGTH
        {
            error!("Sender certificate exceeds max certificate size");
            Err(StatusCode::BadDecodingError)
        } else {
            // validate receiver_certificate_thumbprint_length == 20
            let thumbprint_len = if receiver_certificate_thumbprint.value.is_some() {
                receiver_certificate_thumbprint
                    .value
                    .as_ref()
                    .unwrap()
                    .len()
            } else {
                0
            };
            if thumbprint_len > 0 && thumbprint_len != Thumbprint::THUMBPRINT_SIZE {
                error!(
                    "Receiver certificate thumbprint is not 20 bytes long, {} bytes",
                    receiver_certificate_thumbprint
                        .value
                        .as_ref()
                        .unwrap()
                        .len()
                );
                Err(StatusCode::BadDecodingError)
            } else {
                Ok(AsymmetricSecurityHeader {
                    security_policy_uri,
                    sender_certificate,
                    receiver_certificate_thumbprint,
                })
            }
        }
    }
}

impl AsymmetricSecurityHeader {
    pub fn none() -> AsymmetricSecurityHeader {
        AsymmetricSecurityHeader {
            security_policy_uri: UAString::from(SecurityPolicy::None.to_uri()),
            sender_certificate: ByteString::null(),
            receiver_certificate_thumbprint: ByteString::null(),
        }
    }

    pub fn new(
        security_policy: SecurityPolicy,
        sender_certificate: &X509,
        receiver_certificate_thumbprint: ByteString,
    ) -> AsymmetricSecurityHeader {
        AsymmetricSecurityHeader {
            security_policy_uri: UAString::from(security_policy.to_uri()),
            sender_certificate: sender_certificate.as_byte_string(),
            receiver_certificate_thumbprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SequenceHeader {
    pub sequence_number: u32,
    pub request_id: u32,
}

impl BinaryEncoder<SequenceHeader> for SequenceHeader {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        size += self.sequence_number.encode(stream)?;
        size += self.request_id.encode(stream)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let sequence_number = u32::decode(stream, decoding_options)?;
        let request_id = u32::decode(stream, decoding_options)?;
        Ok(SequenceHeader {
            sequence_number,
            request_id,
        })
    }
}
