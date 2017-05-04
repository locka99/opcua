//! Certificate manager for OPC UA for Rust.
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Write};

use openssl::x509::*;
use openssl::x509::extension::*;
use openssl::rsa::*;
use openssl::pkey::*;
use openssl::asn1::*;
use openssl::hash::*;

use prelude::*;

/// The name that the server/client's certificate is expected to be
const OWN_CERTIFICATE_NAME: &'static str = "cert.der";
/// The name that the server/client's private key is expected to be
const OWN_PRIVATE_KEY_NAME: &'static str = "private.pem";

/// The directory holding the server/client's own cert
const OWN_CERTIFICATE_DIR: &'static str = "own";
/// The directory holding the server/client's own private key
const OWN_PRIVATE_KEY_DIR: &'static str = "private";
/// The directory holding trusted certificates
const TRUSTED_CERTS_DIR: &'static str = "trusted";
/// The directory holding rejected certificates
const REJECTED_CERTS_DIR: &'static str = "rejected";

pub struct CertificateStore {
    pub pki_path: PathBuf,
}

impl CertificateStore {
    /// This function will use the supplied arguments to create a public/private key pair and from
    /// those create a private key file and self-signed public cert file.
    pub fn create_cert(args: super::X509CreateCertArgs) -> Result<(), ()> {
        // Public cert goes under own/
        let public_cert_path = CertificateStore::make_path(&CertificateStore::own_cert_path(&args.pki_path), OWN_CERTIFICATE_NAME)?;
        // Private key goes under private/
        let private_key_path = CertificateStore::make_path(&CertificateStore::own_private_key_path(&args.pki_path), OWN_PRIVATE_KEY_NAME)?;

        // Create a keypair
        let pkey = {
            let rsa = Rsa::generate(args.key_size).unwrap();
            PKey::from_rsa(rsa).unwrap()
        };

        // Create an X509 cert (the public part) as a .pem
        let cert = {
            let mut builder: X509Builder = X509Builder::new().unwrap();
            let _ = builder.set_version(3);
            let subject_name = {
                let mut name = X509NameBuilder::new().unwrap();
                name.append_entry_by_text("CN", &args.common_name).unwrap();
                name.build()
            };
            let _ = builder.set_subject_name(&subject_name);
            let issuer_name = {
                let mut name = X509NameBuilder::new().unwrap();
                // Common name
                name.append_entry_by_text("CN", &args.common_name).unwrap();
                // Organization
                name.append_entry_by_text("O", &args.organization).unwrap();
                // Organizational Unit
                name.append_entry_by_text("OU", &args.organizational_unit).unwrap();
                // Country
                name.append_entry_by_text("C", &args.country).unwrap();
                // State
                name.append_entry_by_text("ST", &args.state).unwrap();
                name.build()
            };
            let _ = builder.set_issuer_name(&issuer_name);
            builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
            builder.set_not_after(&Asn1Time::days_from_now(args.certificate_duration_days).unwrap()).unwrap();
            builder.set_pubkey(&pkey).unwrap();

            // Alt hostnames
            if !args.alt_host_names.is_empty() {
                let subject_alternative_name = {
                    let mut subject_alternative_name = SubjectAlternativeName::new();
                    for alt_host_name in args.alt_host_names.iter() {
                        subject_alternative_name.dns(alt_host_name);
                    }
                    subject_alternative_name.build(&builder.x509v3_context(None, None)).unwrap()
                };
                builder.append_extension(subject_alternative_name).unwrap();
            }

            // Self-sign
            let _ = builder.sign(&pkey, MessageDigest::sha1());
            builder.build()
        };

        // Write the public cert
        CertificateStore::write_cert(&cert, &public_cert_path, args.overwrite)?;

        // Write the private key
        let pem = pkey.private_key_to_pem().unwrap();
        info!("Writing private key to {}", private_key_path.display());
        CertificateStore::write_to_file(&pem, &private_key_path, args.overwrite)?;

        Ok(())
    }

    /// OPC UA Part 6 MessageChunk structure
    ///
    /// The thumbprint is the SHA1 digest of the DER form of the certificate. The hash is 160 bits
    /// (20 bytes) in length and is sent in some secure conversation headers.
    ///
    /// The thumbprint might be used by the server / client for look-up purposes.
    pub fn thumbprint(cert: &X509) -> Vec<u8> {
        use openssl::hash::{MessageDigest, hash};
        let der = cert.to_der().unwrap();
        hash(MessageDigest::sha1(), &der).unwrap()
    }

    /// Validates the cert and if its unknown, writes the value to the rejected folder so it can
    /// be moved to trusted by user
    pub fn validate_or_reject_cert(&self, cert: &X509) -> StatusCode {
        let result = self.validate_cert(cert);
        if result == BAD_CERTIFICATE_UNTRUSTED {
            // Store result in rejected folder
            let _ = self.write_rejected_cert(cert);
        }
        result
    }

    pub fn validate_cert(&self, cert: &X509) -> StatusCode {
        // TODO

        // BAD_CERTIFICATE_UNTRUSTED
        // BAD_CERTIFICATE_TIME_INVALID
        // BAD_CERTIFICATE_ISSUE_TIME_INVALID
        // BAD_CERTIFICATE_USE_NOT_ALLOWED
        // BAD_CERTIFICATE_ISSUER_USE_NOT_ALLOWED
        // BAD_CERTIFICATE_REVOCATION_UNKNOWN
        // BAD_CERTIFICATE_REVOKED
        // BAD_ISSUER_CERTIFICATE_REVOKED
        // BAD_CERTIFICATE_UNKNOWN

        let cert_file_name = CertificateStore::cert_file_name(&cert);
        let mut cert_path = CertificateStore::rejected_certs_path(&self.pki_path);
        cert_path.push(&cert_file_name);
        if !cert_path.exists() {
            error!("Path for rejected certificates {} does not exist", cert_path.display());
            return BAD_UNEXPECTED_ERROR;
        }

        // compare fingerprint in cert from path to one supplied
        // handle collision

        GOOD
    }

    /// Constructs a certificate file name from the cert's issuer and thumbprint
    fn cert_file_name(cert: &X509) -> String {
        let thumbprint = CertificateStore::thumbprint(cert);
        // Hex name = 20 bytes = 40 chars in hex + 4 for .der ext
        let mut file_name = String::with_capacity(20 * 2 + 4);
        for b in thumbprint.iter() {
            file_name.push_str(&format!("{:02x}", b))
        }
        file_name.push_str(".der");
        file_name
    }

    /// Creates the PKI directory structure
    pub fn ensure_pki_directories(&self) -> Result<(), ()> {
        let mut path = self.pki_path.clone();
        let subdirs = [OWN_CERTIFICATE_DIR, OWN_PRIVATE_KEY_DIR, TRUSTED_CERTS_DIR, REJECTED_CERTS_DIR];
        for subdir in subdirs.iter() {
            path.push(subdir);
            CertificateStore::ensure_dir(&path)?;
            path.pop();
        }
        Ok(())
    }

    /// Ensure the directory exists, creating it if necessary
    fn ensure_dir(path: &Path) -> Result<(), ()> {
        use std;
        if path.exists() {
            if !path.is_dir() {
                error!("{} is not a directory ", path.display());
                return Err(());
            }
        } else {
            let result = std::fs::create_dir_all(path);
            if result.is_err() {
                error!("Cannot make directories for {}", path.display());
                return Err(());
            }
        }
        Ok(())
    }

    pub fn own_private_key_path(pki_path: &Path) -> PathBuf {
        let mut path = PathBuf::from(&pki_path);
        path.push(OWN_PRIVATE_KEY_DIR);
        path
    }

    pub fn own_cert_path(pki_path: &Path) -> PathBuf {
        let mut path = PathBuf::from(&pki_path);
        path.push(OWN_CERTIFICATE_DIR);
        path
    }

    pub fn rejected_certs_path(pki_path: &Path) -> PathBuf {
        let mut path = PathBuf::from(&pki_path);
        path.push(REJECTED_CERTS_DIR);
        path
    }

    pub fn trusted_certs_path(pki_path: &Path) -> PathBuf {
        let mut path = PathBuf::from(&pki_path);
        path.push(TRUSTED_CERTS_DIR);
        path
    }

    fn write_rejected_cert(&self, cert: &X509) -> Result<(), ()> {
        // Store the cert in the rejected / untrusted folder
        let cert_file_name = CertificateStore::cert_file_name(&cert);
        let mut cert_path = CertificateStore::rejected_certs_path(&self.pki_path);
        cert_path.push(&cert_file_name);
        CertificateStore::write_cert(cert, &cert_path, true)
    }

    fn write_cert(cert: &X509, path: &Path, overwrite: bool) -> Result<(), ()> {
        let der = cert.to_der().unwrap();
        info!("Writing X509 cert to {}", path.display());
        CertificateStore::write_to_file(&der, &path, overwrite)?;
        Ok(())
    }

    /// Makes a path
    fn make_path(path: &Path, file_name: &str) -> Result<PathBuf, ()> {
        let mut path = PathBuf::from(&path);
        CertificateStore::ensure_dir(&path)?;
        path.push(file_name);
        Ok(path)
    }

    /// Writes to file or prints an error for the reason why it can't.
    fn write_to_file(bytes: &[u8], file_path: &Path, overwrite: bool) -> Result<(), ()> {
        if !overwrite && file_path.exists() {
            error!("File {} already exists and will not be overwritten. Use --overwrite to disable this safeguard.", file_path.display());
            return Err(())
        }

        let file = File::create(file_path);
        if file.is_err() {
            error!("Could not create file {}", file_path.display());
            return Err(());
        }
        let mut file = file.unwrap();

        let written = file.write(bytes);
        if written.is_err() {
            error!("Could not write bytes to file {}", file_path.display());
            return Err(());
        }
        Ok(())
    }
}