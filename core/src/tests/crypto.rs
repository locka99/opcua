use std::fs::File;
use std::io::Write;

use tempdir::TempDir;

use crypto::SecurityPolicy;
use crypto::types::*;
use crypto::certificate_store::*;

#[test]
fn aes_test() {
    use rand::{self, Rng};
    let mut rng = rand::thread_rng();

    // Create a random 128-bit key
    let mut raw_key = vec![0u8; 16];
    rng.fill_bytes(&mut raw_key);

    // Create a random iv.
    let mut iv = vec![0u8; 16];
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

fn make_certificate_store() -> (TempDir, CertificateStore) {
    let tmp_dir = TempDir::new("pki").unwrap();
    let cert_store = CertificateStore::new(&tmp_dir.path());
    assert!(cert_store.ensure_pki_path().is_ok());
    (tmp_dir, cert_store)
}

fn make_test_cert() -> (X509, PKey) {
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
    let cert = CertificateStore::create_cert_and_pkey(&args);
    cert.unwrap()
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

#[test]
fn sign_verify_sha1() {
    let (_, pkey) = make_test_cert();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = pkey.sign_sha1(msg);

    assert_eq!(signature.len(), 256);
    assert!(pkey.verify_sha1(msg, &signature));
    assert!(!pkey.verify_sha1(msg2, &signature));

    assert!(!pkey.verify_sha1(msg, &signature[..signature.len() - 1]));
    signature[0] = !signature[0]; // bitwise not
    assert!(!pkey.verify_sha1(msg, &signature));
}

#[test]
fn sign_verify_sha256() {
    let (_, pkey) = make_test_cert();

    let msg = b"Mary had a little lamb";
    let msg2 = b"It's fleece was white as snow";
    let mut signature = pkey.sign_sha256(msg);

    assert_eq!(signature.len(), 256);
    assert!(pkey.verify_sha256(msg, &signature));
    assert!(!pkey.verify_sha256(msg2, &signature));

    assert!(!pkey.verify_sha256(msg, &signature[..signature.len() - 1]));
    signature[0] = !signature[0]; // bitwise not
    assert!(!pkey.verify_sha256(msg, &signature));
}
