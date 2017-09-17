//! Contains semi-opaque wrappers for various `OpenSSL` types. The Rust bindings for `OpenSSL` do
//! not mark types as implementing debug, thread safety etc. so these wrappers do that so the keys/certs
//! can be contained by structs that have those things.
//!
//! The module also contains convenience methods

use std;
use std::marker::Send;
use std::fmt::{Debug, Formatter};
use std::result::Result;

use openssl::x509;
use openssl::symm::{Cipher, Crypter};
use openssl::symm::Mode;
use openssl::pkey;
use openssl::rsa;
use openssl::sign;
use openssl::hash;

use chrono::{DateTime, UTC, TimeZone};

use opcua_types::{ByteString, StatusCode};
use opcua_types::StatusCode::*;

use crypto::SecurityPolicy;

#[derive(Debug)]
/// Used to create an X509 cert (and private key)
pub struct X509Data {
    pub key_size: u32,
    pub common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub country: String,
    pub state: String,
    pub alt_host_names: Vec<String>,
    pub certificate_duration_days: u32,
}

impl X509Data {
    /// Creates a sample certificate for testing, sample purposes only
    pub fn sample_cert() -> X509Data {
        let alt_host_names = {
            let mut result = Vec::new();
            result.push("localhost".to_string());
            result.push("127.0.0.1".to_string());
            result.push("::1".to_string());
            // Get the machine name / ip address
            if let Ok(machine_name) = std::env::var("COMPUTERNAME") {
                result.push(machine_name);
            }
            if let Ok(machine_name) = std::env::var("NAME") {
                result.push(machine_name);
            }
            result
        };
        X509Data {
            key_size: 2048,
            common_name: "OPC UA Demo Key".to_string(),
            organization: "OPC UA for Rust".to_string(),
            organizational_unit: "OPC UA for Rust".to_string(),
            country: "IE".to_string(),
            state: "Dublin".to_string(),
            alt_host_names,
            certificate_duration_days: 365,
        }
    }
}

/// Thumbprint size is dictated by the OPC UA spec

/// The thumbprint is a 20 byte representation of a certificate that can be used as a hash, a filename
/// or some other purpose.
pub struct Thumbprint {
    pub value: [u8; Thumbprint::THUMBPRINT_SIZE],
}

impl Thumbprint {
    pub const THUMBPRINT_SIZE: usize = 20;

    /// Constructs a thumbprint from a message digest which is expected to be the proper length
    pub fn new(digest: &[u8]) -> Thumbprint {
        if digest.len() != Thumbprint::THUMBPRINT_SIZE {
            panic!("Thumbprint is not the right length");
        }
        let mut value: [u8; Thumbprint::THUMBPRINT_SIZE] = Default::default();
        value.clone_from_slice(digest);
        Thumbprint { value }
    }

    pub fn as_byte_string(&self) -> ByteString {
        ByteString::from_bytes(&self.value)
    }

    /// Returns the thumbprint as a string using hexdecimal values for each byte
    pub fn as_hex_string(&self) -> String {
        // Add a bit of space in case caller intends to append a file extension
        let mut hex_string = String::with_capacity(self.value.len() * 2 + 8);
        for b in self.value.iter() {
            hex_string.push_str(&format!("{:02x}", b))
        }
        hex_string
    }
}

/// This is a wrapper around the `OpenSSL` `X509` cert
#[derive(Clone)]
pub struct X509 {
    pub value: x509::X509,
}

impl Debug for X509 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // This impl will not write out the cert, and exists to keep derive happy
        // on structs that contain an X509 instance
        write!(f, "[x509]")
    }
}

/// This allows certs to be transferred between threads
unsafe impl Send for X509 {}

impl X509 {
    pub fn wrap(value: x509::X509) -> X509 {
        X509 { value }
    }

    pub fn from_byte_string(data: &ByteString) -> Result<X509, StatusCode> {
        if data.is_null() {
            error!("Can't make certificate from null bytestring");
            Err(BAD_CERTIFICATE_INVALID)
        } else if let Ok(cert) = x509::X509::from_der(&data.value.as_ref().unwrap()) {
            Ok(X509::wrap(cert))
        } else {
            error!("Can't make certificate, does bytestring contain .der?");
            Err(BAD_CERTIFICATE_INVALID)
        }
    }

    /// Returns a ByteString representation of the cert which is DER encoded form of X509v3
    pub fn as_byte_string(&self) -> ByteString {
        let der = self.value.to_der().unwrap();
        ByteString::from_bytes(&der)
    }

    pub fn public_key(&self) -> Result<PKey, StatusCode> {
        if let Ok(pkey) = self.value.public_key() {
            let pkey = PKey::wrap(pkey);
            Ok(pkey)
        } else {
            error!("Can't obtain public key from certificate");
            Err(BAD_CERTIFICATE_INVALID)
        }
    }

    pub fn is_time_valid(&self, now: &DateTime<UTC>) -> StatusCode {
        // Issuer time
        let not_before = self.not_before();
        if let Ok(not_before) = not_before {
            if now.lt(&not_before) {
                error!("Certificate < before date)");
                return BAD_CERTIFICATE_TIME_INVALID;
            }
        } else {
            // No before time
            error!("Certificate has no before date");
            return BAD_CERTIFICATE_INVALID;
        }

        // Expiration time
        let not_after = self.not_after();
        if let Ok(not_after) = not_after {
            if now.gt(&not_after) {
                error!("Certificate has expired (> after date)");
                return BAD_CERTIFICATE_TIME_INVALID;
            }
        } else {
            // No after time
            error!("Certificate has no after date");
            return BAD_CERTIFICATE_INVALID;
        }

        GOOD
    }

    /// OPC UA Part 6 MessageChunk structure
    ///
    /// The thumbprint is the SHA1 digest of the DER form of the certificate. The hash is 160 bits
    /// (20 bytes) in length and is sent in some secure conversation headers.
    ///
    /// The thumbprint might be used by the server / client for look-up purposes.
    pub fn thumbprint(&self) -> Thumbprint {
        use openssl::hash::{MessageDigest, hash2};
        let der = self.value.to_der().unwrap();
        let digest = hash2(MessageDigest::sha1(), &der).unwrap();
        Thumbprint::new(&digest)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_before(&self) -> Result<DateTime<UTC>, ()> {
        let date = self.value.not_before().to_string();
        Self::parse_asn1_date(&date)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_after(&self) -> Result<DateTime<UTC>, ()> {
        let date = self.value.not_after().to_string();
        Self::parse_asn1_date(&date)
    }

    fn parse_asn1_date(date: &str) -> Result<DateTime<UTC>, ()> {
        // Parse ASN1 time format
        // MMM DD HH:MM:SS YYYY [GMT]
        let date = if date.ends_with(" GMT") {
            // Not interested in GMT part, ASN1 is always GMT (i.e. UTC)
            &date[..date.len() - 4]
        } else {
            &date
        };
        let result = UTC.datetime_from_str(date, "%b %d %H:%M:%S %Y");
        if result.is_err() {
            println!("Error = {:?}", result.unwrap_err());
            Err(())
        } else {
            Ok(result.unwrap())
        }
    }
}

#[test]
fn parse_asn1_date_test() {
    use chrono::{Datelike, Timelike};

    assert!(X509::parse_asn1_date("").is_err());
    assert!(X509::parse_asn1_date("Jan 69 00:00:00 1970").is_err());
    assert!(X509::parse_asn1_date("Feb 21 00:00:00 1970").is_ok());
    assert!(X509::parse_asn1_date("Feb 21 00:00:00 1970 GMT").is_ok());

    let dt: DateTime<UTC> = X509::parse_asn1_date("Feb 21 12:45:30 1999 GMT").unwrap();
    assert_eq!(dt.month(), 2);
    assert_eq!(dt.day(), 21);
    assert_eq!(dt.hour(), 12);
    assert_eq!(dt.minute(), 45);
    assert_eq!(dt.second(), 30);
    assert_eq!(dt.year(), 1999);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// This is a wrapper around an `OpenSSL` asymmetric key pair
pub struct PKey {
    pub value: pkey::PKey,
}

impl Debug for PKey {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

unsafe impl Send for PKey {}

impl PKey {
    pub fn wrap(pkey: pkey::PKey) -> PKey {
        PKey { value: pkey }
    }

    pub fn new(bit_length: u32) -> PKey {
        PKey {
            value: {
                let rsa = rsa::Rsa::generate(bit_length).unwrap();
                pkey::PKey::from_rsa(rsa).unwrap()
            },
        }
    }

    /// Length in bits
    pub fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }

    /// Size in bytes
    pub fn size(&self) -> usize { self.bit_length() / 8 }

    /// Creates a message digest from the specified block of data and then signs it to return a signature
    fn sign(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        trace!("Key signing");
        if let Ok(mut signer) = sign::Signer::new(message_digest, &self.value) {
            signer.pkey_ctx_mut().set_rsa_padding(rsa::PKCS1_PADDING).unwrap();
            if signer.update(data).is_ok() {
                let result = signer.finish();
                if let Ok(result) = result {
                    trace!("Signature = {:?}", result);
                    signature.copy_from_slice(&result);
                    return Ok(result.len());
                } else {
                    debug!("Can't sign data - error = {:?}", result.unwrap_err());
                }
            }
        }

        {
            use openssl::hash;
            use openssl::rsa;
            let digest_bytes = hash::hash2(message_digest, data).unwrap();

            let mut sig2 = vec![0u8; self.size()];

            self.value.rsa().unwrap().public_encrypt(&digest_bytes, &mut sig2[..], rsa::PKCS1_PADDING);

            trace!("Signature 2 = {:?}", sig2);
        }

        Err(BAD_UNEXPECTED_ERROR)
    }

    /// Verifies that the signature matches the hash / signing key of the supplied data
    fn verify(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        trace!("Key verifying, against signature {:?}, len {}", signature, signature.len());
        if let Ok(mut verifier) = sign::Verifier::new(message_digest, &self.value) {
            verifier.pkey_ctx_mut().set_rsa_padding(rsa::PKCS1_PADDING).unwrap();
            if verifier.update(data).is_ok() {
                let result = verifier.finish(signature);
                if let Ok(result) = result {
                    trace!("Key verified = {:?}", result);
                    return Ok(result);
                } else {
                    debug!("Can't verify key - error = {:?}", result.unwrap_err());
                }
            }
        }
        Err(BAD_UNEXPECTED_ERROR)
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha1(), data, signature)
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha1(), data, signature)
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha256(), data, signature)
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha256(), data, signature)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AesKey {
    pub value: Vec<u8>,
    pub security_policy: SecurityPolicy,
}

impl Debug for AesKey {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[aes]")
    }
}

/// This allows key to be transferred between threads
unsafe impl Send for AesKey {}

impl AesKey {
    pub fn new(security_policy: SecurityPolicy, value: &[u8]) -> AesKey {
        AesKey { value: value.to_vec(), security_policy }
    }

    fn validate_aes_args(cipher: &Cipher, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        if dst.len() < src.len() + cipher.block_size() {
            error!("Dst buffer is too small {} vs {} + {}", src.len(), dst.len(), cipher.block_size());
            Err(BAD_UNEXPECTED_ERROR)
        } else if iv.len() != 16 && iv.len() != 32 {
            // ... It would be nice to compare iv size to be exact to the key size here (should be the
            // same) but AesKey doesn't tell us that info. Have to check elsewhere
            error!("IV is not an expected size, len = {}", iv.len());
            Err(BAD_UNEXPECTED_ERROR)
        } else if src.len() % 16 != 0 {
            panic!("Block size {} is wrong, check stack", src.len());
        } else {
            Ok(())
        }
    }

    fn cipher(&self) -> Cipher {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 => {
                // Aes128_CBC
                Cipher::aes_128_cbc()
            }
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                // Aes256_CBC
                Cipher::aes_256_cbc()
            }
            _ => {
                panic!("Unsupported")
            }
        }
    }

    /// Encrypt or decrypt  data according to the mode
    fn do_cipher(&self, mode: Mode, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        let cipher = self.cipher();

        let _ = Self::validate_aes_args(&cipher, src, iv, dst)?;

        trace!("Encrypting block of size {}", src.len());

        let crypter = Crypter::new(cipher, mode, &self.value, Some(iv));
        if let Ok(mut crypter) = crypter {
            crypter.pad(false);
            let result = crypter.update(src, dst);
            if let Ok(count) = result {
                let result = crypter.finalize(&mut dst[count..]);
                if let Ok(rest) = result {
                    trace!("do cipher size {}", count + rest);
                    Ok(count + rest)
                } else {
                    error!("Encryption error during finalize {:?}", result.unwrap_err());
                    Err(BAD_UNEXPECTED_ERROR)
                }
            } else {
                error!("Encryption error during update {:?}", result.unwrap_err());
                Err(BAD_UNEXPECTED_ERROR)
            }
        } else {
            error!("Encryption Error");
            Err(BAD_UNEXPECTED_ERROR)
        }
    }

    pub fn block_size(&self) -> usize {
        self.cipher().block_size()
    }

    pub fn iv_length(&self) -> usize {
        self.cipher().iv_len().unwrap()
    }

    pub fn key_length(&self) -> usize {
        self.cipher().key_len()
    }

    pub fn encrypt(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        self.do_cipher(Mode::Encrypt, src, iv, dst)
    }

    /// Decrypts data using AES. The initialization vector is the nonce generated for the secure channel
    pub fn decrypt(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        self.do_cipher(Mode::Decrypt, src, iv, dst)
    }
}
