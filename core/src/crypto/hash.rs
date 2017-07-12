use std::result::Result;

use openssl::pkey;
use openssl::sign;
use openssl::hash;

use opcua_types::StatusCode;
use opcua_types::StatusCode::*;

/// Pseudo random P_SHA implementation for creating pseudo random range of bytes from an input
///
/// https://www.ietf.org/rfc/rfc4346.txt
///
/// P_SHA1(secret, seed) = HMAC_SHA1(secret, A(1) + seed) +
///                        HMAC_SHA1(secret, A(2) + seed) +
///                        HMAC_SHA1 (secret, A(3) + seed) + ...
///
/// Where A(n) is defined as:
///   A(0) = seed
///   A(n) = HMAC_SHA1(secret, A(n-1))
/// + indicates that the results are appended to previous results.
pub fn p_sha(message_digest: hash::MessageDigest, secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);

    let mut hmac = Vec::with_capacity(seed.len() * 2);
    let mut a = vec![seed.to_vec()];
    while result.len() < length {
        let next_hmac = hmac_vec(message_digest, secret, a.last().as_ref().unwrap());
        a.push(next_hmac);
        // Append a slice of random data
        let data_slice = {
            hmac.clear();
            hmac.extend_from_slice(a.last().as_ref().unwrap());
            hmac.extend_from_slice(seed);
            hmac_vec(message_digest, secret, &hmac)
        };
        result.extend_from_slice(&hmac_vec(message_digest, secret, &data_slice));
    }
    result.truncate(length);
    result
}

pub fn hmac_vec(digest: hash::MessageDigest, key: &[u8], data: &[u8]) -> Vec<u8> {
    // Compute a signature
    let pkey = pkey::PKey::hmac(key).unwrap();
    let mut signer = sign::Signer::new(digest, &pkey).unwrap();
    signer.update(data).unwrap();
    signer.finish().unwrap()
}

pub fn hmac(digest: hash::MessageDigest, key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
    &signature[..].copy_from_slice(&hmac_vec(digest, key, data)[..]);
    Ok(())
}

pub fn hmac_sha1(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
    if signature.len() != 20 {
        Err(BAD_INVALID_ARGUMENT)
    } else {
        hmac(hash::MessageDigest::sha1(), key, data, signature)
    }
}

/// Verify that the HMAC for the data block matches the supplied signature
pub fn verify_hmac_sha1(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let mut tmp_signature = [0u8; 20];
    if hmac_sha1(key, data, &mut tmp_signature).is_err() {
        false
    } else {
        signature == tmp_signature
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
    if signature.len() != 32 {
        Err(BAD_INVALID_ARGUMENT)
    } else {
        hmac(hash::MessageDigest::sha256(), key, data, signature)
    }
}

/// Verify that the HMAC for the data block matches the supplied signature
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let mut tmp_signature = [0u8; 32];
    if hmac_sha256(key, data, &mut tmp_signature).is_err() {
        false
    } else {
        signature == tmp_signature
    }
}
