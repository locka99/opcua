//! The certificate manager for OPC UA for Rust is responsible for storing and retrieving
//! certificates from disk and for establishing the trustworthiness of those certificates when
//! establishing connections between the application and the client/server it is communicating with.
//!
use std::path::{Path, PathBuf};
use std::fs::{File, metadata};
use std::io::{Write, Read};

use openssl::x509;
use openssl::x509::extension::*;
use openssl::pkey;
use openssl::rsa::*;
use openssl::asn1::*;
use openssl::hash::*;

use prelude::*;

/// The name that the server/client's application instance certificate is expected to be
const OWN_CERTIFICATE_NAME: &'static str = "cert.der";
/// The name that the server/client's application instance private key is expected to be
const OWN_PRIVATE_KEY_NAME: &'static str = "private.pem";

/// The directory holding the server/client's application instance cert
const OWN_CERTIFICATE_DIR: &'static str = "own";
/// The directory holding the server/client's application instance private key
const OWN_PRIVATE_KEY_DIR: &'static str = "private";
/// The directory holding trusted certificates
const TRUSTED_CERTS_DIR: &'static str = "trusted";
/// The directory holding rejected certificates
const REJECTED_CERTS_DIR: &'static str = "rejected";

/// The certificate store manages the storage of a server/client's own certificate & private key
/// and the trust / rejection of certificates from the other end.
pub struct CertificateStore {
    pub pki_path: PathBuf,
    pub check_time: bool,
}

impl CertificateStore {
    /// Sets up the certificate store to the specified PKI directory.
    /// It is not a good idea to be pointing more than one instance of this struct at the same path
    /// on disk.
    pub fn new(pki_path: &Path) -> CertificateStore {
        CertificateStore {
            pki_path: pki_path.to_path_buf(),
            check_time: true,
        }
    }

    /// Creates a self-signed X509v3 certificate and public/private key from the supplied creation args.
    /// The certificate identifies an instance of the application running on a host as well
    /// as the public key. The PKey holds the corresponding public/private key. Note that if
    /// the pkey is stored by cert store, then only the private key will be written. The public key
    /// is only ever stored with the cert.
    ///
    /// See Part 6 Table 23 for full set of requirements
    ///
    /// In particular, application instance cert requires subjectAltName to specify alternate
    /// hostnames / ip addresses that the host runs on.
    pub fn create_cert_and_pkey(args: &X509Data) -> Result<(X509, PKey), String> {
        // Create a public / private keypair
        let pkey = {
            let rsa = Rsa::generate(args.key_size).unwrap();
            pkey::PKey::from_rsa(rsa).unwrap()
        };

        // Create an X509 cert (the public part)
        let cert = {
            let mut builder = x509::X509Builder::new().unwrap();
            // value 2 == version 3 (go figure)
            let _ = builder.set_version(2);
            let subject_name = {
                let mut name = x509::X509NameBuilder::new().unwrap();
                name.append_entry_by_text("CN", &args.common_name).unwrap();
                name.build()
            };
            let _ = builder.set_subject_name(&subject_name);
            let issuer_name = {
                let mut name = x509::X509NameBuilder::new().unwrap();
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

            // For Application Instance Certificate specifies how cert may be used
            let key_usage = KeyUsage::new().
                digital_signature().
                non_repudiation().
                key_encipherment().
                data_encipherment().build().unwrap();
            let _ = builder.append_extension(key_usage);
            let extended_key_usage = ExtendedKeyUsage::new().
                client_auth().
                server_auth().build().unwrap();
            let _ = builder.append_extension(extended_key_usage);

            builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
            builder.set_not_after(&Asn1Time::days_from_now(args.certificate_duration_days).unwrap()).unwrap();
            builder.set_pubkey(&pkey).unwrap();

            // Subject alt names - Alt hostnames, ip addresses for application instance cert
            if !args.alt_host_names.is_empty() {
                let subject_alternative_name = {
                    let mut subject_alternative_name = SubjectAlternativeName::new();
                    for alt_host_name in args.alt_host_names.iter() {
                        subject_alternative_name.dns(alt_host_name);
                    }
                    subject_alternative_name.build(&builder.x509v3_context(None, None)).unwrap()
                };
                let _ = builder.append_extension(subject_alternative_name).unwrap();
            }

            // Self-sign
            let _ = builder.sign(&pkey, MessageDigest::sha256());

            builder.build()
        };

        Ok((X509::wrap(cert), PKey::wrap(pkey)))
    }

    /// Reads a private key from a path on disk disk
    pub fn read_pkey(path: &Path) -> Result<PKey, String> {
        if let Ok(pkey_info) = metadata(path) {
            if let Ok(mut f) = File::open(&path) {
                let mut buffer = Vec::with_capacity(pkey_info.len() as usize);
                let bytes_read = f.read_to_end(&mut buffer);
                drop(f);
                if let Ok(pkey) = pkey::PKey::private_key_from_pem(&buffer) {
                    return Ok(PKey::wrap(pkey));
                }
            }
        }
        Err(format!("Cannot read pkey from path {:?}", path))
    }

    /// Reads the store's own certificate and private key
    pub fn read_own_cert_and_pkey(&self) -> Result<(X509, PKey), String> {
        let own_cert_path = self.own_cert_path();
        if let Ok(cert) = CertificateStore::read_cert(&own_cert_path) {
            let own_private_key_path = self.own_private_key_path();
            if let Ok(pkey) = CertificateStore::read_pkey(&own_private_key_path) {
                Ok((cert, pkey))
            } else {
                Err(format!("Cannot read pkey from path {:?}", own_private_key_path))
            }
        } else {
            Err(format!("Cannot read cert from path {:?}", own_cert_path))
        }
    }

    /// This function will use the supplied arguments to create an Application Instance Certificate
    /// consisting of a X509v3 certificate and public/private key pair. The cert (including pubkey)
    /// and private key will be written to disk under the pki path.
    pub fn create_and_store_application_instance_cert(&self, args: &X509Data, overwrite: bool) -> Result<(X509, PKey), String> {
        // Create the cert and corresponding private key
        let (cert, pkey) = CertificateStore::create_cert_and_pkey(args)?;

        // Public cert goes under own/
        let public_cert_path = CertificateStore::make_and_ensure_file_path(&self.own_cert_dir(), OWN_CERTIFICATE_NAME)?;
        // Private key goes under private/
        let private_key_path = CertificateStore::make_and_ensure_file_path(&self.private_key_dir(), OWN_PRIVATE_KEY_NAME)?;

        // Write the public cert
        CertificateStore::store_cert(&cert, &public_cert_path, overwrite)?;

        // Write the private key
        let pem = pkey.value.private_key_to_pem().unwrap();
        info!("Writing private key to {}", private_key_path.display());
        CertificateStore::write_to_file(&pem, &private_key_path, overwrite)?;

        Ok((cert, pkey))
    }

    /// Validates the cert and if its unknown, writes the value to the rejected folder so it can
    /// be moved to trusted by user
    /// # Errors
    ///
    /// A non `GOOD` status code indicates a failure in the cert or in some action required in
    /// order to validate it.
    ///
    pub fn validate_or_reject_application_instance_cert(&self, cert: &X509) -> StatusCode {
        let result = self.validate_application_instance_cert(cert);
        if result.is_bad() {
            match result {
                BAD_UNEXPECTED_ERROR | BAD_SECURITY_CHECKS_FAILED => {
                    /* DO NOTHING */
                }
                _ => {
                    // Store result in rejected folder
                    let _ = self.store_rejected_cert(cert);
                }
            }
        }
        result
    }

    /// This function is to stop collision errors / tampering where someone renames a cert on disk
    /// to match another cert and somehow bypasses or subverts a check. The disk cert must match
    /// the memory cert or the test is assumed to fail.
    fn ensure_cert_and_file_are_the_same(cert: &X509, cert_path: &Path) -> bool {
        if !cert_path.exists() {
            println!("Can't find cert on disk");
            false
        } else {
            let cert2 = CertificateStore::read_cert(cert_path);
            if cert2.is_err() {
                println!("Can't read cert from disk {:?} - {}", cert_path, cert2.unwrap_err());
                // No cert2 to compare to
                false
            } else {
                // Compare the buffers
                println!("Comparing cert on disk to memory");
                let der = cert.value.to_der().unwrap();
                let der2 = cert2.unwrap().value.to_der().unwrap();
                der == der2
            }
        }
    }

    /// Validates the certificate according to the strictness set in the CertificateStore itself.
    /// Validation might include checking the issue time, expiration time, revocation, trust chain
    /// etc. In the first instance this function will only check if the cert is recognized
    /// and is already contained in the trusted or rejected folder.
    ///
    /// # Errors
    ///
    /// A non `GOOD` status code indicates a failure in the cert or in some action required in
    /// order to validate it.
    ///
    pub fn validate_application_instance_cert(&self, cert: &X509) -> StatusCode {
        let cert_file_name = CertificateStore::cert_file_name(&cert);
        debug!("Validating cert with name on disk {}", cert_file_name);

        // Look for the cert in the rejected folder. If it's rejected there is no purpose going
        // any further
        {
            let mut cert_path = self.rejected_certs_dir();
            if !cert_path.exists() {
                error!("Path for rejected certificates {} does not exist", cert_path.display());
                return BAD_UNEXPECTED_ERROR;
            }
            cert_path.push(&cert_file_name);
            if cert_path.exists() {
                warn!("Certificate {} is untrusted because it resides in the rejected directory", cert_file_name);
                return BAD_SECURITY_CHECKS_FAILED;
            }
        }

        // Check the trusted folder. These checks are more strict to ensure the cert is genuinely
        // trusted
        {
            // Check the trusted folder
            let mut cert_path = self.trusted_certs_dir();
            if !cert_path.exists() {
                error!("Path for rejected certificates {} does not exist", cert_path.display());
                return BAD_UNEXPECTED_ERROR;
            }
            cert_path.push(&cert_file_name);

            // Check if cert is in the trusted folder
            if !cert_path.exists() {
                // ... trust checks based on ca could be added here to add cert straight to trust folder
                warn!("Certificate {} is unknown and untrusted so it will be stored in rejected directory", cert_file_name);
                let _ = self.store_rejected_cert(cert);
                return BAD_CERTIFICATE_UNTRUSTED;
            }

            // Read the cert from the trusted folder to make sure it matches the one supplied
            if !CertificateStore::ensure_cert_and_file_are_the_same(cert, &cert_path) {
                error!("Certificate in memory does not match the one on disk {} so cert will automatically be treated as untrusted", cert_path.display());
                return BAD_UNEXPECTED_ERROR;
            }

            // Now inspect the cert not before / after values to ensure its validity
            if self.check_time {
                use chrono::UTC;
                let now = UTC::now();
                let time_status_code = cert.is_time_valid(&now);
                if time_status_code.is_bad() {
                    return time_status_code;
                }
            }

            // Other tests that we might do
            // ... issuer
            // ... trust (self-signed, ca etc.)
            // ... revocation
        }

        GOOD
    }

    /// Returns a certificate file name from the cert's issuer and thumbprint fields
    pub fn cert_file_name(cert: &X509) -> String {
        let thumbprint = cert.thumbprint();
        // Hex name = 20 bytes = 40 chars in hex + 4 for .der ext
        let mut file_name = String::with_capacity(20 * 2 + 4);
        for b in thumbprint.iter() {
            file_name.push_str(&format!("{:02x}", b))
        }
        file_name.push_str(".der");
        file_name
    }

    /// Creates the PKI directory structure
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    pub fn ensure_pki_path(&self) -> Result<(), String> {
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
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn ensure_dir(path: &Path) -> Result<(), String> {
        use std;
        if path.exists() {
            if !path.is_dir() {
                return Err(format!("{} is not a directory ", path.display()));
            }
        } else {
            let result = std::fs::create_dir_all(path);
            if result.is_err() {
                return Err(format!("Cannot make directories for {}", path.display()));
            }
        }
        Ok(())
    }

    /// Get path to application instance certificate
    fn own_cert_path(&self) -> PathBuf {
        let mut path = self.own_cert_dir();
        path.push(OWN_CERTIFICATE_NAME);
        path
    }

    /// Get path to application instance private key
    fn own_private_key_path(&self) -> PathBuf {
        let mut path = self.private_key_dir();
        path.push(OWN_PRIVATE_KEY_NAME);
        path
    }

    /// Get the path to the application instance key dir
    pub fn private_key_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(OWN_PRIVATE_KEY_DIR);
        path
    }

    /// Get the path to the application instance certificate dir
    pub fn own_cert_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(OWN_CERTIFICATE_DIR);
        path
    }

    /// Get the path to the rejected certs dir
    pub fn rejected_certs_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(REJECTED_CERTS_DIR);
        path
    }

    /// Get the path to the trusted certs dir
    pub fn trusted_certs_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.pki_path);
        path.push(TRUSTED_CERTS_DIR);
        path
    }

    /// Write a cert to the rejected directory. If the write succeeds, the function
    /// returns a path to the written file.
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    pub fn store_rejected_cert(&self, cert: &X509) -> Result<PathBuf, String> {
        // Store the cert in the rejected folder where untrusted certs go
        let cert_file_name = CertificateStore::cert_file_name(&cert);
        let mut cert_path = self.rejected_certs_dir();
        cert_path.push(&cert_file_name);
        CertificateStore::store_cert(cert, &cert_path, true)?;
        Ok(cert_path)
    }

    /// Writes a cert to the specified directory
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn store_cert(cert: &X509, path: &Path, overwrite: bool) -> Result<(), String> {
        let der = cert.value.to_der().unwrap();
        info!("Writing X509 cert to {}", path.display());
        CertificateStore::write_to_file(&der, &path, overwrite)
    }

    /// Reads an X509 certificate in .def format from disk
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn read_cert(path: &Path) -> Result<X509, String> {
        let file = File::open(path);
        if file.is_err() {
            return Err(format!("Could not open cert file {}", path.display()));
        }

        let mut file: File = file.unwrap();
        let mut cert = Vec::new();
        let bytes_read = file.read_to_end(&mut cert);
        if bytes_read.is_err() {
            return Err(format!("Could not read bytes from cert file {}", path.display()));
        }

        let cert = x509::X509::from_der(&cert);
        if cert.is_err() {
            return Err(format!("Could not read cert from cert file {}", path.display()));
        }

        Ok(X509::wrap(cert.unwrap()))
    }

    /// Makes a path
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn make_and_ensure_file_path(path: &Path, file_name: &str) -> Result<PathBuf, String> {
        let mut path = PathBuf::from(&path);
        CertificateStore::ensure_dir(&path)?;
        path.push(file_name);
        Ok(path)
    }

    /// Writes to file or prints an error for the reason why it can't.
    ///
    /// # Errors
    ///
    /// A string description of any failure
    ///
    fn write_to_file(bytes: &[u8], file_path: &Path, overwrite: bool) -> Result<(), String> {
        if !overwrite && file_path.exists() {
            return Err(format!("File {} already exists and will not be overwritten. Use --overwrite to disable this safeguard.", file_path.display()))
        }
        let file = File::create(file_path);
        if file.is_err() {
            return Err(format!("Could not create file {}", file_path.display()));
        }
        let mut file = file.unwrap();

        let written = file.write(bytes);
        if written.is_err() {
            return Err(format!("Could not write bytes to file {}", file_path.display()));
        }
        Ok(())
    }
}