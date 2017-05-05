use openssl::aes::*;
use openssl::symm::Mode;

/// Encrypts data using AES. The initialization vector should be supplied and comes
/// from the OPC UA secure channel
pub fn encrypt_aes(inx: &[u8], out: &mut [u8], iv: &[u8], key: &AesKey) -> Result<(), ()> {
    //    aes_ige(inx, out, key, iv, Mode::Encrypt);
    Err(())
}

/// Encrypts data using AES. The initialization vector should be supplied and comes
/// from the OPC UA secure channel
pub fn decrypt_aes(inx: &[u8], out: &mut [u8], iv: &[u8], key: &AesKey) -> Result<(), ()> {
    //    aes_ige(inx, out, key, iv, Mode::Decrypt);
    Err(())
}
