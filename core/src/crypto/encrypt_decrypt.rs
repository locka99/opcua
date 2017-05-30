use super::types::*;

use openssl::aes::aes_ige;
use openssl::symm::Mode;

fn validate_aes_args(inx: &[u8], out: &mut [u8], nonce: &[u8], _: &AesKey) -> Result<(), String> {
    if inx.len() != out.len() {
        Err(format!("In and out buffers have different lengths {} vs {}", inx.len(), out.len()))
    } else if inx.len() % 16 != 0 {
        // Works for out too because inx.len == out.len
        Err(format!("In and out buffers are not 16-byte padded, len = {}", inx.len()))
    } else if nonce.len() != 16 && nonce.len() != 32 {
        // ... It would be nice to compare nonce size to be exact to the key size here (should be the
        // same) but AesKey doesn't tell us that info. Have to check elsewhere
        Err(format!("Nonce is not an expected size, len = {}", nonce.len()))
    } else {
        Ok(())
    }
}

/// Encrypts data using AES. The initialization vector is the nonce generated for the secure channel.
/// The key can be 128, 160 or 256bits.
pub fn encrypt_aes(inx: &[u8], out: &mut [u8], nonce: &mut [u8], key: &AesKey) -> Result<(), String> {
    let _ = validate_aes_args(inx, out, nonce, key)?;
    aes_ige(inx, out, &key.value, nonce, Mode::Encrypt);
    Ok(())
}

/// Encrypts data using AES. The initialization vector is the nonce generated for the secure channel
pub fn decrypt_aes(inx: &[u8], out: &mut [u8], nonce: &mut [u8], key: &AesKey) -> Result<(), String> {
    let _ = validate_aes_args(inx, out, nonce, key)?;
    aes_ige(inx, out, &key.value, nonce, Mode::Decrypt);
    Ok(())
}
