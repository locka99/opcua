use crypto;
use crypto::encrypt_decrypt::*;
use crypto::cert_manager::*;

use openssl::aes::*;

#[test]
fn aes_test() {
    use rand::{self, Rng};
    let mut rng = rand::thread_rng();

    // Create a random 128-bit key
    let mut raw_key = vec![0u8; 16];
    rng.fill_bytes(&mut raw_key);

    // Create a random nonce(iv). Not obvious why iv should be 2*blocksize
    let mut nonce = vec![0u8; 32];
    rng.fill_bytes(&mut nonce);

    let plaintext = b"01234567890123450123456789012345";
    let mut ciphertext: [u8; 32] = [0; 32];
    {
        let mut nonce = nonce.clone();
        let aes_key = AesKey::new_encrypt(&raw_key).unwrap();
        println!("Plaintext = {}, ciphertext = {}", plaintext.len(), ciphertext.len());
        let r = encrypt_aes(plaintext, &mut ciphertext, &mut nonce, &aes_key);
        println!("result = {:?}", r);
        assert!(r.is_ok());
    }

    let mut plaintext2: [u8; 32] = [0; 32];
    {
        let mut nonce = nonce.clone();
        let aes_key = AesKey::new_decrypt(&raw_key).unwrap();
        let r = decrypt_aes(&ciphertext, &mut plaintext2, &mut nonce, &aes_key);
        println!("result = {:?}", r);
        assert!(r.is_ok());
    }

    assert_eq!(&plaintext[..], &plaintext2[..]);
}

#[test]
fn create_cert() {
    //    let cert = CertificateStore::create_cert_and_pkey(&args);
}

#[test]
fn sign_bytes() {}

#[test]
fn verify_bytes() {}