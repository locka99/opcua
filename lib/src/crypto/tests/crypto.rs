extern crate rustc_serialize as serialize;

use std::fs::File;
use std::io::Write;

use crate::types::status_code::StatusCode;

use crate::crypto::tests::{
    make_certificate_store, make_test_cert_1024, make_test_cert_2048, APPLICATION_HOSTNAME,
    APPLICATION_URI,
};
use crate::crypto::{
    aeskey::AesKey,
    certificate_store::*,
    pkey::{KeySize, PrivateKey, RsaPadding},
    random,
    user_identity::{legacy_password_decrypt, legacy_password_encrypt},
    x509::{X509Data, X509},
    SecurityPolicy, SHA1_SIZE, SHA256_SIZE,
};

#[test]
fn aes_test() {
    // Create a random 128-bit key
    let mut raw_key = [0u8; 16];
    random::bytes(&mut raw_key);

    // Create a random iv.
    let mut iv = [0u8; 16];
    random::bytes(&mut iv);

    let aes_key = AesKey::new(SecurityPolicy::Basic128Rsa15, &raw_key);

    let plaintext = b"01234567890123450123456789012345";
    let buf_size = plaintext.len() + aes_key.block_size();
    let mut ciphertext = vec![0u8; buf_size];

    let ciphertext = {
        println!(
            "Plaintext = {}, ciphertext = {}",
            plaintext.len(),
            ciphertext.len()
        );
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
    let (x509, _) = make_test_cert_1024();
    let not_before = x509.not_before().unwrap().to_string();
    println!("Not before = {}", not_before);
    let not_after = x509.not_after().unwrap().to_string();
    println!("Not after = {}", not_after);
}

#[test]
fn ensure_pki_path() {
    let (tmp_dir, cert_store) = make_certificate_store();
    let pki = cert_store.pki_path.clone();
    for dirname in ["rejected", "trusted"].iter() {
        let mut subdir = pki.to_path_buf();
        subdir.push(dirname);
        assert!(subdir.exists());
    }
    drop(tmp_dir);
}

#[test]
fn create_own_cert_in_pki() {
    let args = X509Data {
        key_size: 2048,
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

    let (cert, _) = make_test_cert_1024();
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
    let (cert, _) = make_test_cert_1024();
    let result = cert_store.validate_or_reject_application_instance_cert(
        &cert,
        SecurityPolicy::Basic128Rsa15,
        None,
        None,
    );
    assert!(result.is_bad());

    drop(tmp_dir);
}

#[test]
fn test_and_trust_application_instance_cert() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make a cert, write it to the trusted dir
    let (cert, _) = make_test_cert_1024();

    // Simulate user/admin copying cert to the trusted folder
    let der = cert.to_der().unwrap();
    let mut cert_trusted_path = cert_store.trusted_certs_dir();
    cert_trusted_path.push(CertificateStore::cert_file_name(&cert));
    {
        println!("Writing der file to {:?}", cert_trusted_path);
        let mut file = File::create(cert_trusted_path).unwrap();
        assert!(file.write(&der).is_ok());
    }

    // Now validate the cert was stored properly
    let result = cert_store.validate_or_reject_application_instance_cert(
        &cert,
        SecurityPolicy::Basic128Rsa15,
        None,
        None,
    );
    assert!(result.is_good());

    drop(tmp_dir);
}

#[test]
fn test_and_reject_thumbprint_mismatch() {
    let (tmp_dir, cert_store) = make_certificate_store();

    // Make two certs, write it to the trusted dir
    let (cert, _) = make_test_cert_1024();
    let (cert2, _) = make_test_cert_1024();

    // Simulate user/admin copying cert to the trusted folder and renaming it to cert2's name,
    // e.g. to trick the cert store to trust an untrusted cert
    let der = cert.to_der().unwrap();
    let mut cert_trusted_path = cert_store.trusted_certs_dir();
    cert_trusted_path.push(CertificateStore::cert_file_name(&cert2));
    {
        let mut file = File::create(cert_trusted_path).unwrap();
        assert!(file.write(&der).is_ok());
    }

    // Now validate the cert was rejected because the thumbprint does not match the one on disk
    let result = cert_store.validate_or_reject_application_instance_cert(
        &cert2,
        SecurityPolicy::Basic128Rsa15,
        None,
        None,
    );
    assert!(result.is_bad());

    drop(tmp_dir);
}

fn test_asymmetric_encrypt_and_decrypt(
    cert: &X509,
    key: &PrivateKey,
    security_policy: SecurityPolicy,
    plaintext_size: usize,
) {
    let plaintext = (0..plaintext_size)
        .map(|i| (i % 256) as u8)
        .collect::<Vec<u8>>();

    let mut ciphertext = vec![0u8; plaintext_size + 8192];
    let mut plaintext2 = vec![0u8; plaintext_size + 8192];

    println!("Encrypt with security policy {:?}", security_policy);
    println!("Encrypting data of length {}", plaintext_size);
    let encrypted_size = security_policy
        .asymmetric_encrypt(&cert.public_key().unwrap(), &plaintext, &mut ciphertext)
        .unwrap();
    println!("Encrypted size = {}", encrypted_size);
    println!("Decrypting cipher text back");
    let decrypted_size = security_policy
        .asymmetric_decrypt(key, &ciphertext[..encrypted_size], &mut plaintext2)
        .unwrap();
    println!("Decrypted size = {}", decrypted_size);

    assert_eq!(plaintext_size, decrypted_size);
    assert_eq!(&plaintext[..], &plaintext2[..decrypted_size]);
}

#[test]
fn asymmetric_encrypt_and_decrypt() {
    crate::console_logging::init();

    let (cert, key) = make_test_cert_2048();
    // Try all security policies, ensure they encrypt / decrypt for various sizes
    for security_policy in &[
        SecurityPolicy::Basic128Rsa15,
        SecurityPolicy::Basic256,
        SecurityPolicy::Basic256Sha256,
        SecurityPolicy::Aes128Sha256RsaOaep,
        SecurityPolicy::Aes256Sha256RsaPss,
    ] {
        for data_size in &[0, 1, 127, 128, 129, 255, 256, 257, 13001] {
            test_asymmetric_encrypt_and_decrypt(&cert, &key, *security_policy, *data_size);
        }
    }
}

#[test]
fn calculate_cipher_text_size() {
    let (_, pkey) = make_test_cert_2048();

    // Testing -11 bounds
    let padding = RsaPadding::Pkcs1;
    assert_eq!(pkey.calculate_cipher_text_size(1, padding), 256);
    assert_eq!(pkey.calculate_cipher_text_size(245, padding), 256);
    assert_eq!(pkey.calculate_cipher_text_size(246, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(255, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(256, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(512, padding), 768);

    // Testing -42 bounds
    let padding = RsaPadding::OaepSha1;
    assert_eq!(pkey.calculate_cipher_text_size(1, padding), 256);
    assert_eq!(pkey.calculate_cipher_text_size(214, padding), 256);
    assert_eq!(pkey.calculate_cipher_text_size(215, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(255, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(256, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(512, padding), 768);

    // Testing -66 bounds
    let padding = RsaPadding::OaepSha256;
    assert_eq!(pkey.calculate_cipher_text_size(1, padding), 256);
    assert_eq!(pkey.calculate_cipher_text_size(190, padding), 256);
    assert_eq!(pkey.calculate_cipher_text_size(191, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(255, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(256, padding), 512);
    assert_eq!(pkey.calculate_cipher_text_size(512, padding), 768);
}

#[test]
fn calculate_cipher_text_size2() {
    let (cert, private_key) = make_test_cert_1024();
    let public_key = cert.public_key().unwrap();

    // The cipher text size function should report exactly the same value as the value returned
    // by encrypting bytes. This is especially important on boundary values.
    for padding in &[
        RsaPadding::Pkcs1,
        RsaPadding::OaepSha1,
        RsaPadding::OaepSha256,
    ] {
        for src_len in 1..550 {
            let src = vec![127u8; src_len];

            // Encrypt the bytes to a dst buffer of the expected size with padding
            let expected_size = private_key.calculate_cipher_text_size(src_len, *padding);
            let mut dst = vec![0u8; expected_size];
            let actual_size = public_key.public_encrypt(&src, &mut dst, *padding).unwrap();
            if expected_size != actual_size {
                println!(
                    "Expected size {} != actual size {} for src length {}",
                    expected_size, actual_size, src_len
                );
                assert_eq!(expected_size, actual_size);
            }

            // Decrypt to be sure the data is same as input
            let mut src2 = vec![0u8; expected_size];
            let src2_len = private_key
                .private_decrypt(&dst, &mut src2, *padding)
                .unwrap();
            assert_eq!(src_len, src2_len);
            assert_eq!(&src[..], &src[..src2_len]);
        }
    }
}

#[test]
fn sign_verify_sha1() {
    let (cert, private_key) = make_test_cert_2048();
    let public_key = cert.public_key().unwrap();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = private_key.sign_sha1(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    assert!(public_key.verify_sha1(msg, &signature).unwrap());
    assert!(!public_key.verify_sha1(msg2, &signature).unwrap());

    assert!(!public_key
        .verify_sha1(msg, &signature[..signature.len() - 1])
        .unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!public_key.verify_sha1(msg, &signature).unwrap());
}

#[test]
fn sign_verify_sha256() {
    let (cert, private_key) = make_test_cert_2048();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = private_key.sign_sha256(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    let public_key = cert.public_key().unwrap();

    assert!(public_key.verify_sha256(msg, &signature).unwrap());
    assert!(!public_key.verify_sha256(msg2, &signature).unwrap());

    assert!(!public_key
        .verify_sha256(msg, &signature[..signature.len() - 1])
        .unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!public_key.verify_sha256(msg, &signature).unwrap());
}

#[test]
fn sign_verify_sha256_pss() {
    let (cert, private_key) = make_test_cert_2048();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = [0u8; 256];
    let signed_len = private_key.sign_sha256_pss(msg, &mut signature).unwrap();

    assert_eq!(signed_len, 256);
    let public_key = cert.public_key().unwrap();

    assert!(public_key.verify_sha256_pss(msg, &signature).unwrap());
    assert!(!public_key.verify_sha256_pss(msg2, &signature).unwrap());

    assert!(!public_key
        .verify_sha256_pss(msg, &signature[..signature.len() - 1])
        .unwrap());
    signature[0] = !signature[0]; // bitwise not
    assert!(!public_key.verify_sha256_pss(msg, &signature).unwrap());
}

#[test]
fn sign_hmac_sha1() {
    use crate::crypto::hash;
    use serialize::hex::FromHex;

    let key = b"";
    let data = b"";

    let mut signature_wrong_size = [0u8; SHA1_SIZE - 1];
    assert!(hash::hmac_sha1(key, data, &mut signature_wrong_size).is_err());

    let mut signature = [0u8; SHA1_SIZE];
    assert!(hash::hmac_sha1(key, data, &mut signature).is_ok());
    let expected = "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
        .from_hex()
        .unwrap();
    assert_eq!(&signature, &expected[..]);

    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    assert!(hash::hmac_sha1(key, data, &mut signature).is_ok());
    let expected = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        .from_hex()
        .unwrap();
    assert_eq!(&signature, &expected[..]);

    assert!(hash::verify_hmac_sha1(key, data, &expected));
    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));
}

#[test]
fn sign_hmac_sha256() {
    use crate::crypto::hash;
    use serialize::hex::FromHex;

    let key = b"";
    let data = b"";

    let mut signature_wrong_size = [0u8; SHA256_SIZE - 1];
    assert!(hash::hmac_sha256(key, data, &mut signature_wrong_size).is_err());

    let mut signature = [0u8; SHA256_SIZE];
    assert!(hash::hmac_sha256(key, data, &mut signature).is_ok());
    let expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        .from_hex()
        .unwrap();
    assert_eq!(&signature, &expected[..]);

    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    assert!(hash::hmac_sha256(key, data, &mut signature).is_ok());
    let expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        .from_hex()
        .unwrap();
    assert_eq!(&signature, &expected[..]);

    assert!(hash::verify_hmac_sha256(key, data, &expected));
    assert!(!hash::verify_hmac_sha1(key, &data[1..], &expected));
}

#[test]
fn generate_nonce() {
    // Generate a random nonce through the function and ensure it is the expected length
    assert!(SecurityPolicy::None.random_nonce().is_null());
    assert_eq!(
        SecurityPolicy::Basic128Rsa15.random_nonce().as_ref().len(),
        16
    );
    assert_eq!(SecurityPolicy::Basic256.random_nonce().as_ref().len(), 32);
    assert_eq!(
        SecurityPolicy::Basic256Sha256.random_nonce().as_ref().len(),
        32
    );
}

#[test]
fn derive_keys_from_nonce() {
    // Create a pair of "random" nonces.
    let nonce1 = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce2 = vec![
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];

    // Create a security policy Basic128Rsa15 policy
    //
    // a) SigningKeyLength = 16
    // b) EncryptingKeyLength = 16
    // c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Basic128Rsa15;
    let (signing_key, encryption_key, iv) =
        security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 16);
    assert_eq!(encryption_key.value().len(), 16);
    assert_eq!(iv.len(), 16);

    // Create a security policy Basic256 policy
    //
    // a) SigningKeyLength = 24
    // b) EncryptingKeyLength = 32
    // c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Basic256;
    let (signing_key, encryption_key, iv) =
        security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 24);
    assert_eq!(encryption_key.value().len(), 32);
    assert_eq!(iv.len(), 16);

    // Create a security policy Basic256Sha256 policy
    //
    // a) SigningKeyLength = 32
    // b) EncryptingKeyLength = 32
    // c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Basic256Sha256;
    let (signing_key, encryption_key, iv) =
        security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 32);
    assert_eq!(encryption_key.value().len(), 32);
    assert_eq!(iv.len(), 16);

    // Create a security policy Aes128Sha256RsaOaep policy
    //
    // a) SigningKeyLength = 32
    // b) EncryptingKeyLength = 32
    // c) EncryptingBlockSize = 16
    let security_policy = SecurityPolicy::Aes128Sha256RsaOaep;
    let (signing_key, encryption_key, iv) =
        security_policy.make_secure_channel_keys(&nonce1, &nonce2);
    assert_eq!(signing_key.len(), 32);
    assert_eq!(encryption_key.value().len(), 16);
    assert_eq!(iv.len(), 16);
}

#[test]
fn derive_keys_from_nonce_basic128rsa15() {
    let security_policy = SecurityPolicy::Basic128Rsa15;

    // This test takes two nonces generated from a real client / server session
    let local_nonce = vec![
        0x88, 0x65, 0x13, 0xb6, 0xee, 0xad, 0x68, 0xa2, 0xcb, 0xa7, 0x29, 0x0f, 0x79, 0xb3, 0x84,
        0xf3,
    ];
    let remote_nonce = vec![
        0x17, 0x0c, 0xe8, 0x68, 0x3e, 0xe6, 0xb3, 0x80, 0xb3, 0xf4, 0x67, 0x5c, 0x1e, 0xa2, 0xcc,
        0xb1,
    ];

    // Expected local keys
    let local_signing_key: Vec<u8> = vec![
        0x66, 0x58, 0xa5, 0xa7, 0x8c, 0x7d, 0xa8, 0x4e, 0x57, 0xd3, 0x9b, 0x4d, 0x6b, 0xdc, 0x93,
        0xad,
    ];
    let local_encrypting_key: Vec<u8> = vec![
        0x44, 0x8f, 0x0d, 0x7d, 0x2e, 0x08, 0x99, 0xdd, 0x5b, 0x56, 0x8d, 0xaf, 0x70, 0xc2, 0x26,
        0xfc,
    ];
    let local_iv = vec![
        0x6c, 0x83, 0x7c, 0xd1, 0xa8, 0x61, 0xb9, 0xd7, 0xae, 0xdf, 0x2d, 0xe4, 0x85, 0x26, 0x81,
        0x89,
    ];

    // Expected remote keys
    let remote_signing_key: Vec<u8> = vec![
        0x27, 0x23, 0x92, 0xb7, 0x47, 0xad, 0x48, 0xf6, 0xae, 0x20, 0x30, 0x2f, 0x88, 0x4f, 0x96,
        0x40,
    ];
    let remote_encrypting_key: Vec<u8> = vec![
        0x85, 0x84, 0x1c, 0xcc, 0xcb, 0x3c, 0x39, 0xd4, 0x14, 0x11, 0xa4, 0xfe, 0x01, 0x5a, 0x0a,
        0xcf,
    ];
    let remote_iv = vec![
        0xab, 0xc6, 0x26, 0x78, 0xb9, 0xa4, 0xe6, 0x93, 0x21, 0x9e, 0xc1, 0x7e, 0xd5, 0x8b, 0x0e,
        0xf2,
    ];

    // Make the keys using the two nonce values
    let local_keys = security_policy.make_secure_channel_keys(&remote_nonce, &local_nonce);
    let remote_keys = security_policy.make_secure_channel_keys(&local_nonce, &remote_nonce);

    // Compare the keys we received against the expected
    assert_eq!(local_keys.0, local_signing_key);
    assert_eq!(local_keys.1.value().to_vec(), local_encrypting_key);
    assert_eq!(local_keys.2, local_iv);

    assert_eq!(remote_keys.0, remote_signing_key);
    assert_eq!(remote_keys.1.value().to_vec(), remote_encrypting_key);
    assert_eq!(remote_keys.2, remote_iv);
}

#[test]
fn certificate_with_hostname_mismatch() {
    let (cert, _) = make_test_cert_2048();
    let wrong_host_name = format!("wrong_{}", APPLICATION_HOSTNAME);

    // Create a certificate and ensure that when the hostname does not match, the verification fails
    // with the correct error
    let result = cert.is_hostname_valid(&wrong_host_name);
    assert_eq!(result, StatusCode::BadCertificateHostNameInvalid);

    // Create a certificate and ensure that when the hostname does  match, the verification succeeds
    let result = cert.is_hostname_valid(APPLICATION_HOSTNAME);
    assert_eq!(result, StatusCode::Good);

    // Try a few times with different case
    let result = cert.is_hostname_valid(&APPLICATION_HOSTNAME.to_string().to_uppercase());
    assert_eq!(result, StatusCode::Good);
    let result = cert.is_hostname_valid(&APPLICATION_HOSTNAME.to_string().to_lowercase());
    assert_eq!(result, StatusCode::Good);
}

#[test]
fn certificate_with_application_uri_mismatch() {
    let (cert, _) = make_test_cert_2048();

    // Compare the certificate to the wrong application uri in the description, expect error
    let result = cert.is_application_uri_valid("urn:WrongURI");
    assert_eq!(result, StatusCode::BadCertificateUriInvalid);

    // Compare the certificate to the correct application uri in the description, expect success
    let result = cert.is_application_uri_valid(APPLICATION_URI);
    assert_eq!(result, StatusCode::Good);
}

#[test]
fn encrypt_decrypt_password() {
    let password = String::from("abcdef123456");
    let nonce = random::byte_string(20);

    let (cert, pkey) = make_test_cert_1024();

    let padding = RsaPadding::OaepSha1;
    let secret = legacy_password_encrypt(&password, nonce.as_ref(), &cert, padding).unwrap();
    let password2 = legacy_password_decrypt(&secret, nonce.as_ref(), &pkey, padding).unwrap();

    assert_eq!(password, password2);
}
