use crypto::types::*;
use crypto::encrypt_decrypt::*;
use crypto::certificate_store::*;

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
        let aes_key = AesKey::new_encrypt(&raw_key);
        println!("Plaintext = {}, ciphertext = {}", plaintext.len(), ciphertext.len());
        let r = encrypt_aes(plaintext, &mut ciphertext, &mut nonce, &aes_key);
        println!("result = {:?}", r);
        assert!(r.is_ok());
    }

    let mut plaintext2: [u8; 32] = [0; 32];
    {
        let mut nonce = nonce.clone();
        let aes_key = AesKey::new_decrypt(&raw_key);
        let r = decrypt_aes(&ciphertext, &mut plaintext2, &mut nonce, &aes_key);
        println!("result = {:?}", r);
        assert!(r.is_ok());
    }

    assert_eq!(&plaintext[..], &plaintext2[..]);
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
    let (x509, pkey) = make_test_cert();
    let not_before = x509.value.not_before().to_string();
    println!("Not before = {}", not_before);
    let not_after = x509.value.not_after().to_string();
    println!("Not after = {}", not_after);
}

#[test]
fn ensure_pki_path() {
    use tempdir::TempDir;
    let tmp_dir = TempDir::new("pki").unwrap();

    let cert_store = CertificateStore::new(&tmp_dir.path());
    assert!(cert_store.ensure_pki_path().is_ok());

    let pki = tmp_dir.path().to_owned();
    for dirname in ["rejected", "trusted", "private", "own"].iter() {
        let mut subdir = pki.to_path_buf();
        subdir.push(dirname);
        assert!(subdir.exists());
    }
}

#[test]
fn create_cert_in_pki() {
    use tempdir::TempDir;
    let tmp_dir = TempDir::new("pki").unwrap();
    let cert_store = CertificateStore::new(&tmp_dir.path());
    cert_store.ensure_pki_path();
    // TODO create a cert and verify it and its key can be loaded
}

// TODO create a cert that fails trust and becomes rejected
// TODO create a thumbprint file and match to a rejected file on disk
// TODO create a thumbprint and match to a trusted file on disk, ensuring thumbprints match
// TODO create a thumbprint and match to a trusted file on disk which is different, ensuring error handling

#[test]
fn sign_bytes() {
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
