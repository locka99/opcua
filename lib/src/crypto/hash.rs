// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Hashing functions used for producing and verifying digital signatures

use std::result::Result;

use hmac::{digest, Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use crate::types::status_code::StatusCode;

use super::{SHA1_SIZE, SHA256_SIZE};

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;
type Sha1Output = digest::CtOutput<HmacSha1>;
type Sha256Output = digest::CtOutput<HmacSha256>;

/// Pseudo random `P_SHA` implementation for creating pseudo random range of bytes from an input
///
/// https://www.ietf.org/rfc/rfc4346.txt
/// https://tools.ietf.org/html/rfc5246
///
/// P_SHA1(secret, seed) = HMAC_SHA1(secret, A(1) + seed) +
///                        HMAC_SHA1(secret, A(2) + seed) +
///                        HMAC_SHA1(secret, A(3) + seed) + ...
///
/// Where A(n) is defined as:
///   A(0) = seed
///   A(n) = HMAC_SHA1(secret, A(n-1))
/// + indicates that the results are appended to previous results.
pub fn p_sha1(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);

    let mut hmac = Vec::with_capacity(seed.len() * 2);

    let mut a_last = Vec::with_capacity(seed.len());
    a_last.extend_from_slice(seed); // A(0) = seed

    while result.len() < length {
        // A(n) = HMAC_SHA1(secret, A(n-1))
        let signed = sign_sha1(secret, &a_last);
        let a_next = signed.into_bytes(); //hmac_vec(message_digest, secret, &a_last);

        // Append a slice of random data
        let bytes = {
            hmac.clear();
            hmac.extend(&a_next);
            hmac.extend_from_slice(seed);

            sign_sha1(secret, &hmac).into_bytes()
            //hmac_vec(message_digest, secret, &hmac)
        };
        result.extend(&bytes);

        a_last.clear();
        a_last.extend(&a_next);
    }

    result.truncate(length);
    result
}

pub fn p_sha256(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);

    let mut hmac = Vec::with_capacity(seed.len() * 2);

    let mut a_last = Vec::with_capacity(seed.len());
    a_last.extend_from_slice(seed); // A(0) = seed

    while result.len() < length {
        // A(n) = HMAC_SHA1(secret, A(n-1))
        let signed = sign_sha256(secret, &a_last);
        let a_next = signed.into_bytes(); //hmac_vec(message_digest, secret, &a_last);

        // Append a slice of random data
        let bytes = {
            hmac.clear();
            hmac.extend(&a_next);
            hmac.extend_from_slice(seed);

            sign_sha256(secret, &hmac).into_bytes()
            //hmac_vec(message_digest, secret, &hmac)
        };
        result.extend(&bytes);

        a_last.clear();
        a_last.extend(&a_next);
    }

    result.truncate(length);
    result
}

/*
fn hmac_vec(digest: hash::MessageDigest, key: &[u8], data: &[u8]) -> Vec<u8> {
    // Compute a signature
    let pkey = pkey::PKey::hmac(key).unwrap();
    let mut signer = sign::Signer::new(digest, &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

fn hmac(
    digest: hash::MessageDigest,
    key: &[u8],
    data: &[u8],
    signature: &mut [u8],
) -> Result<(), StatusCode> {
    let hmac = hmac_vec(digest, key, data);
    trace!("hmac length = {}", hmac.len());
    signature.copy_from_slice(&hmac);
    Ok(())
}
*/

fn sign_sha1(key: &[u8], data: &[u8]) -> Sha1Output {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
}

fn sign_sha256(key: &[u8], data: &[u8]) -> Sha256Output {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
}

pub fn hmac_sha1(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
    if signature.len() == SHA1_SIZE {
        let result = sign_sha1(key, data);
        signature.copy_from_slice(&result.into_bytes());
        Ok(())
    } else {
        error!(
            "Signature buffer length must be exactly {} bytes to receive hmac_sha1 signature",
            SHA1_SIZE
        );
        Err(StatusCode::BadInvalidArgument)
    }
}

/// Verify that the HMAC for the data block matches the supplied signature
pub fn verify_hmac_sha1(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    if signature.len() != SHA1_SIZE {
        false
    } else {
        let mut mac = HmacSha1::new_from_slice(key).unwrap();
        mac.update(data);
        mac.verify_slice(signature).is_ok()
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
    if signature.len() == SHA256_SIZE {
        let result = sign_sha256(key, data);
        signature.copy_from_slice(&result.into_bytes());
        Ok(())
    } else {
        error!(
            "Signature buffer length must be exactly {} bytes to receive hmac_sha256 signature",
            SHA256_SIZE
        );
        Err(StatusCode::BadInvalidArgument)
    }
}

/// Verify that the HMAC for the data block matches the supplied signature
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    if signature.len() != SHA256_SIZE {
        false
    } else {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac.verify_slice(signature).is_ok()
    }
}
