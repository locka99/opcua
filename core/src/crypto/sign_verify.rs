use openssl::sign::{Signer, Verifier};
use openssl::pkey::PKey;
use openssl::hash::{MessageDigest};

pub fn sign_sha1(data: &[u8], keypair: &PKey) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha1(), &keypair).unwrap();
    signer.update(data).unwrap();
    signer.finish().unwrap()
}

pub fn verify_sha1(data: &[u8], signature: &[u8], keypair: &PKey) -> bool {
    let mut verifier = Verifier::new(MessageDigest::sha1(), &keypair).unwrap();
    verifier.update(data).unwrap();
    verifier.finish(signature).unwrap()
}
