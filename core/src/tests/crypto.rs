extern crate rustc_serialize as serialize;

use std::fs::File;
use std::io::Write;

use crypto::{SecurityPolicy, SHA1_SIZE, SHA256_SIZE};
use crypto::types::*;
use crypto::certificate_store::*;

use tests::{make_certificate_store, make_test_cert};

#[test]
fn aes_test() {
    use rand::{self, Rng};
    let mut rng = rand::thread_rng();

    // Create a random 128-bit key
    let mut raw_key = [0u8; 16];
    rng.fill_bytes(&mut raw_key);

    // Create a random iv.
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    let aes_key = AesKey::new(SecurityPolicy::Basic128Rsa15, &raw_key);

    let plaintext = b"01234567890123450123456789012345";
    let buf_size = plaintext.len() + aes_key.block_size();
    let mut ciphertext = vec![0u8; buf_size];

    let ciphertext = {
        println!("Plaintext = {}, ciphertext = {}", plaintext.len(), ciphertext.len());
        let r = aes_key.encrypt(plaintext, &iv, &mut ciphertext);
        println!("result = {:?}", r);
        assert!(r.is_ok());
        &ciphertext[..r.unwrap()]
    };

    let buf_size = ciphertext.len() + aes_key.block_size();
    let mut plaintext2 = vec![0u8; buf_size];

    let plaintext2 = {
        let r = aes_key.decrypt(&ciphertext, &iv, &mut plaintext2);
        println!("result = {:?}", r);
        assert!(r.is_ok());
        &plaintext2[..r.unwrap()]
    };

    assert_eq!(&plaintext[..], &plaintext2[..]);
}

#[test]
fn create_cert() {
    let (x509, _) = make_test_cert();
    let not_before = x509.value.not_before().to_string();
    println!("Not before = {}", not_before);
    let not_after = x509.value.not_after().to_string();
    println!("Not after = {}", not_after);
}

#[test]
fn ensure_pki_path() {
    let (tmp_dir, cert_store) = make_certificate_store();
    let pki = cert_store.pki_path.clone();
    for dirname in ["rejected", "trusted", "private", "own"].iter() {
        let mut subdir = pki.to_path_buf();
        subdir.push(dirname);
        assert!(subdir.exists());
    }
    drop(tmp_dir);
}

#[test]
fn create_own_cert_in_pki() {
    let args = X509Data {
        key_size: 2045,
        common_name: "x".to_string(),
        organization: "x.org".to_string(),
        organizational_unit: "x.org ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec!["host1".to_string(), "host2".to_string()],
        certificate_duration_days: 60,
    };

    let (tmp_dir, cert_store) = make_certificate_store();
    let result = cert_store.create_and_store_application_instance_cert(&args, false);
    assert!(result.is_ok());

    // Create again with no overwrite
    let result = cert_store.create_and_store_application_instance_cert(&args, false);
    assert!(result.is_err());

    // Create again with overwrite
    let result = cert_store.create_and_store_application_instance_cert(&args, true);
    assert!(result.is_ok());
    drop(tmp_dir)
}

#[test]
fn create_rejected_cert_in_pki() {
    let (tmp_dir, cert_store) = make_certificate_store();

    let (cert, _) = make_test_cert();
    let result = cert_store.store_rejected_cert(&cert);
    assert!(result.is_ok());

    let path = result.unwrap();
    assert!(path.exists());
    drop(tmp_dir);
}

#[test]
fn test_and_reject_application_instance_cert() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make an unrecognized cert
    let (cert, _) = make_test_cert();
    let result = cert_store.validate_or_reject_application_instance_cert(&cert);
    assert!(result.is_bad());

    drop(tmp_dir);
}

#[test]
fn test_and_trust_application_instance_cert() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make a cert, write it to the trusted dir
    let (cert, _) = make_test_cert();

    // Simulate user/admin copying cert to the trusted folder
    let der = cert.value.to_der().unwrap();
    let mut cert_trusted_path = cert_store.trusted_certs_dir();
    cert_trusted_path.push(CertificateStore::cert_file_name(&cert));
    {
        println!("Writing der file to {:?}", cert_trusted_path);
        let mut file = File::create(cert_trusted_path).unwrap();
        assert!(file.write(&der).is_ok());
    }

    // Now validate the cert was stored properly
    let result = cert_store.validate_or_reject_application_instance_cert(&cert);
    assert!(result.is_good());

    drop(tmp_dir);
}

#[test]
fn test_and_reject_thumbprint_mismatch() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make two certs, write it to the trusted dir
    let (cert, _) = make_test_cert();
    let (cert2, _) = make_test_cert();

    // Simulate user/admin copying cert to the trusted folder and renaming it to cert2's name,
    // e.g. to trick the cert store to trust an untrusted cert
    let der = cert.value.to_der().unwrap();
    let mut cert_trusted_path = cert_store.trusted_certs_dir();
    cert_trusted_path.push(CertificateStore::cert_file_name(&cert2));
    {
        let mut file = File::create(cert_trusted_path).unwrap();
        assert!(file.write(&der).is_ok());
    }

    // Now validate the cert was rejected because the thumbprint does not match the one on disk
    let result = cert_store.validate_or_reject_application_instance_cert(&cert2);
    assert!(result.is_bad());

    drop(tmp_dir);
}

fn test_asymmetric_encrypt_and_decrypt(cert: &X509, key: &PKey, security_policy: SecurityPolicy, plaintext_size: usize) {
    let mut plaintext = vec![0u8; plaintext_size];
    for i in 0..plaintext_size {
        plaintext[i] = (i % 256) as u8;
    }
    let mut ciphertext = vec![0u8; plaintext_size + 4096];
    let mut plaintext2 = vec![0u8; plaintext_size + 4096];

    trace!("Encrypting data of length {}", plaintext_size);
    let encrypted_size = security_policy.asymmetric_encrypt(&cert.public_key().unwrap(), &plaintext, &mut ciphertext).unwrap();
    trace!("Encrypted size = {}", encrypted_size);
    trace!("Decrypting cipher text back");
    let decrypted_size = security_policy.asymmetric_decrypt(key, &ciphertext[..encrypted_size], &mut plaintext2).unwrap();
    trace!("Decrypted size = {}", decrypted_size);

    assert_eq!(plaintext_size, decrypted_size);
    assert_eq!(&plaintext[..], &plaintext2[..decrypted_size]);
}


#[test]
fn asymmetric_encrypt_and_decrypt() {
    let (cert, key) = make_test_cert();
    // Try all security policies, ensure they encrypt / decrypt for various sizes
    for security_policy in [SecurityPolicy::Basic128Rsa15, SecurityPolicy::Basic256, SecurityPolicy::Basic256Sha256].iter() {
        for data_size in [0, 1, 127, 128, 129, 255, 256, 257, 13001].iter() {
            test_asymmetric_encrypt_and_decrypt(&cert, &key, *security_policy, *data_size);
        }
    }
}

#[test]
fn sign_verify_sha1() {
    let (_, pkey) = make_test_cert();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = pkey.sign_sha1(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    assert!(pkey.verify_sha1(msg, &signature).unwrap());
    assert!(!pkey.verify_sha1(msg2, &signature).unwrap());

    assert!(!pkey.verify_sha1(msg, &signature[..signature.len() - 1]).unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!pkey.verify_sha1(msg, &signature).unwrap());
}

#[test]
fn sign_verify_sha256() {
    let (_, pkey) = make_test_cert();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = pkey.sign_sha256(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    assert!(pkey.verify_sha256(msg, &signature).unwrap());
    assert!(!pkey.verify_sha256(msg2, &signature).unwrap());

    assert!(!pkey.verify_sha256(msg, &signature[..signature.len() - 1]).unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!pkey.verify_sha256(msg, &signature).unwrap());
}

#[test]
fn sign_hmac_sha1() {
    use crypto::hash;
    use tests::crypto::serialize::hex::FromHex;

    let key = b"";
    let data = b"";

    let mut signature_wrong_size = [0u8; SHA1_SIZE - 1];
    assert!(hash::hmac_sha1(key, data, &mut signature_wrong_size).is_err());

    let mut signature = [0u8; SHA1_SIZE];
    assert!(hash::hmac_sha1(key, data, &mut signature).is_ok());
    let expected = "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d".from_hex().unwrap();
    assert_eq!(&signature, &expected[..]);

    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    assert!(hash::hmac_sha1(key, data, &mut signature).is_ok());
    let expected = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9".from_hex().unwrap();
    assert_eq!(&signature, &expected[..]);

    assert!(hash::verify_hmac_sha1(key, data, &expected));
    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));
}

#[test]
fn sign_hmac_sha256() {
    use crypto::hash;
    use tests::crypto::serialize::hex::FromHex;

    let key = b"";
    let data = b"";

    let mut signature_wrong_size = [0u8; SHA256_SIZE - 1];
    assert!(hash::hmac_sha256(key, data, &mut signature_wrong_size).is_err());

    let mut signature = [0u8; SHA256_SIZE];
    assert!(hash::hmac_sha256(key, data, &mut signature).is_ok());
    let expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad".from_hex().unwrap();
    assert_eq!(&signature, &expected[..]);

    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    assert!(hash::hmac_sha256(key, data, &mut signature).is_ok());
    let expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8".from_hex().unwrap();
    assert_eq!(&signature, &expected[..]);

    assert!(hash::verify_hmac_sha256(key, data, &expected));
    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));
}

#[test]
fn keys_from_nonce() {
    use tests::crypto::serialize::hex::FromHex;

    // Create a pair of "random" nonces.
    let nonce1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".from_hex().unwrap();
    let nonce2 = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".from_hex().unwrap();

    // Create a security policy Basic128Rsa15 policy
    //
    /// a) SigningKeyLength = 16
    /// b) EncryptingKeyLength = 16
    /// c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Basic128Rsa15;
    let (signing_key, encryption_key, iv) = security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 16);
    assert_eq!(encryption_key.value.len(), 16);
    assert_eq!(iv.len(), 16);

    // Create a security policy Basic256 policy
    //
    /// a) SigningKeyLength = 24
    /// b) EncryptingKeyLength = 32
    /// c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Basic256;
    let (signing_key, encryption_key, iv) = security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 24);
    assert_eq!(encryption_key.value.len(), 32);
    assert_eq!(iv.len(), 16);

    // Create a security policy Basic256Sha256 policy
    //
    /// a) SigningKeyLength = 32
    /// b) EncryptingKeyLength = 32
    /// c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Basic256Sha256;
    let (signing_key, encryption_key, iv) = security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 32);
    assert_eq!(encryption_key.value.len(), 32);
    assert_eq!(iv.len(), 16);
}
