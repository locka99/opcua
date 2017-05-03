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

/// The name that the server/client's certificate is expected to be
const OWN_CERTIFICATE_NAME: &'static str = "cert.der";
/// The name that the server/client's private key is expected to be
const OWN_PRIVATE_KEY_NAME: &'static str = "private.pem";

/// This function will use the supplied arguments to create a public/private key pair and from
/// those create a private key file and self-signed public cert file.
pub fn create_cert(args: super::X509CreateCertArgs) -> Result<(), ()> {
    // Public cert goes under own/
    let public_cert_path = make_path(&args.pki_path, super::OWN_CERTIFICATE_DIR, OWN_CERTIFICATE_NAME)?;
    // Private key goes under private/
    let private_key_path = make_path(&args.pki_path, super::OWN_PRIVATE_KEY_DIR, OWN_PRIVATE_KEY_NAME)?;

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
    let der = cert.to_der().unwrap();
    info!("Writing public X509 cert to {}", public_cert_path.display());
    write_to_file(&der, &public_cert_path, args.overwrite)?;

    // Write the private key
    let pem = pkey.private_key_to_pem().unwrap();
    info!("Writing private key to {}", private_key_path.display());
    write_to_file(&pem, &private_key_path, args.overwrite)?;

    Ok(())
}

/// Makes a path
fn make_path(pki_path: &Path, dir_name: &str, file_name: &str) -> Result<PathBuf, ()> {
    let mut path = PathBuf::from(&pki_path);
    path.push(dir_name);
    super::ensure_dir(&path)?;
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
