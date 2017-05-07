use openssl::aes::*;
use openssl::symm::Mode;

fn validate_aes_args(inx: &[u8], out: &mut [u8], nonce: &[u8], key: &AesKey) -> Result<(), String> {
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
    aes_ige(inx, out, key, nonce, Mode::Encrypt);
    Ok(())
}

/// Encrypts data using AES. The initialization vector is the nonce generated for the secure channel
pub fn decrypt_aes(inx: &[u8], out: &mut [u8], nonce: &mut [u8], key: &AesKey) -> Result<(), String> {
    let _ = validate_aes_args(inx, out, nonce, key)?;
    aes_ige(inx, out, key, nonce, Mode::Decrypt);
    Ok(())
}

#[test]
fn aes_test() {
    use rand::{self, Rng};

    // Multiple of 16
    let plaintext = b"0123456789012345";
    let mut ciphertext: [u8; 16] = [0; 16];

    let mut rng = rand::thread_rng();

    // Random key
    let mut key = vec![0u8; 16];
    rng.fill_bytes(&mut key);

    // Random nonce(iv). Not obvious why iv should be 2*blocksize
    let mut nonce = vec![0u8; 32];
    rng.fill_bytes(&mut nonce);

    {
        let key = AesKey::new_encrypt(&key).unwrap();
        let r = encrypt_aes(plaintext, &mut ciphertext, &mut nonce, &key);
        assert!(r.is_ok());
    }

    let mut plaintext2: [u8; 16] = [0; 16];

    {
        let key = AesKey::new_decrypt(&key).unwrap();
        let r = decrypt_aes(&ciphertext, &mut plaintext2, &mut nonce, &key);
        assert!(r.is_ok());
    }

    assert_eq!(&plaintext[..], &plaintext2[..]);
}
