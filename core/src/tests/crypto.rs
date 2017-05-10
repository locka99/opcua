use crypto;

#[test]
fn have_crypto() {
    assert!(crypto::is_crypto_enabled());
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
