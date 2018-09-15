// X509 certificate wrapper.

use std;
use std::marker::Send;
use std::fmt::{Debug, Formatter};
use std::result::Result;

use openssl::x509;
use openssl::nid::Nid;

use chrono::{DateTime, Utc, TimeZone};

use opcua_types::ByteString;
use opcua_types::service_types::ApplicationDescription;
use opcua_types::status_code::StatusCode;
use opcua_types::status_code::StatusCode::*;

use crypto::pkey::PublicKey;
use crypto::thumbprint::Thumbprint;

const DEFAULT_KEYSIZE: u32 = 2048;
const DEFAULT_COUNTRY: &str = "IE";
const DEFAULT_STATE: &str = "Dublin";

#[derive(Debug)]
/// Used to create an X509 cert (and private key)
pub struct X509Data {
    pub key_size: u32,
    pub common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub country: String,
    pub state: String,
    /// A list of host names. The first hostname is expected to be the application uri. The remainder are dns host names.
    /// Therefore there should be a minimum of 2 entries.
    pub alt_host_names: Vec<String>,
    pub certificate_duration_days: u32,
}

impl From<ApplicationDescription> for X509Data {
    fn from(application_description: ApplicationDescription) -> Self {
        let alt_host_names = Self::alt_host_names(application_description.application_uri.as_ref(), false, true);
        X509Data {
            key_size: DEFAULT_KEYSIZE,
            common_name: application_description.application_name.to_string(),
            organization: application_description.application_name.to_string(),
            organizational_unit: application_description.application_name.to_string(),
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            alt_host_names,
            certificate_duration_days: 365,
        }
    }
}

impl X509Data {
    /// Gets a list of possible dns hostnames for this device
    pub fn computer_hostnames() -> Vec<String> {
        let mut result = Vec::with_capacity(2);
        if let Ok(machine_name) = std::env::var("COMPUTERNAME") {
            result.push(machine_name);
        }
        if let Ok(machine_name) = std::env::var("NAME") {
            result.push(machine_name);
        }
        result
    }

    /// Creates a list of uri + DNS hostnames using the supplied arguments
    pub fn alt_host_names(application_uri: &str, add_localhost: bool, add_computer_name: bool) -> Vec<String> {
        // The first name is the application uri
        let mut result = vec![application_uri.to_string()];
        // The remainder are alternative dns entries
        if add_localhost {
            result.push("localhost".to_string());
            result.push("127.0.0.1".to_string());
            result.push("::1".to_string());
        }
        // Get the machine name / ip address
        if add_computer_name {
            let mut computer_hostnames = Self::computer_hostnames();
            computer_hostnames.drain(..).for_each(|h| result.push(h));
        }
        result
    }

    /// Creates a sample certificate for testing, sample purposes only
    pub fn sample_cert() -> X509Data {
        let alt_host_names = Self::alt_host_names("urn:OPCUADemo", true, true);
        X509Data {
            key_size: 2048,
            common_name: "OPC UA Demo Key".to_string(),
            organization: "OPC UA for Rust".to_string(),
            organizational_unit: "OPC UA for Rust".to_string(),
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            alt_host_names,
            certificate_duration_days: 365,
        }
    }
}


/// This is a wrapper around the `OpenSSL` `X509` cert
#[derive(Clone)]
pub struct X509 {
    value: x509::X509,
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

unsafe impl std::marker::Sync for X509 {}

impl X509 {
    pub fn wrap(value: x509::X509) -> X509 {
        X509 { value }
    }

    pub fn from_der(der: &[u8]) -> Result<Self, ()> {
        if let Ok(value) = x509::X509::from_der(der) {
            Ok(X509 { value })
        } else {
            error!("Cannot produce an x509 cert from the data supplied");
            Err(())
        }
    }

    pub fn from_byte_string(data: &ByteString) -> Result<X509, StatusCode> {
        if data.is_null() {
            error!("Can't make certificate from null bytestring");
            Err(BadCertificateInvalid)
        } else if let Ok(cert) = x509::X509::from_der(&data.value.as_ref().unwrap()) {
            Ok(X509::wrap(cert))
        } else {
            error!("Can't make certificate, does bytestring contain .der?");
            Err(BadCertificateInvalid)
        }
    }

    /// Returns a ByteString representation of the cert which is DER encoded form of X509v3
    pub fn as_byte_string(&self) -> ByteString {
        let der = self.value.to_der().unwrap();
        ByteString::from(&der)
    }

    pub fn public_key(&self) -> Result<PublicKey, StatusCode> {
        if let Ok(pkey) = self.value.public_key() {
            let pkey = PublicKey::wrap_public_key(pkey);
            Ok(pkey)
        } else {
            error!("Can't obtain public key from certificate");
            Err(BadCertificateInvalid)
        }
    }

    fn get_subject_entry(&self, nid: Nid) -> Result<String, ()> {
        let subject_name = self.value.subject_name();
        let mut entries = subject_name.entries_by_nid(nid);
        if let Some(entry) = entries.next() {
            // Asn1StringRef has to be converted out of Asn1 into UTF-8 and then a String
            if let Ok(value) = entry.data().as_utf8() {
                use std::ops::Deref;
                // Value is an OpensslString type here so it has to be converted
                Ok(value.deref().to_string())
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    pub fn common_name(&self) -> Result<String, ()> {
        self.get_subject_entry(Nid::COMMONNAME)
    }

    /// Tests if the certificate is valid for the supplied time using the not before and not
    /// after values on the cert.
    pub fn is_time_valid(&self, now: &DateTime<Utc>) -> StatusCode {
        // Issuer time
        let not_before = self.not_before();
        if let Ok(not_before) = not_before {
            if now.lt(&not_before) {
                error!("Certificate < before date)");
                return BadCertificateTimeInvalid;
            }
        } else {
            // No before time
            error!("Certificate has no before date");
            return BadCertificateInvalid;
        }

        // Expiration time
        let not_after = self.not_after();
        if let Ok(not_after) = not_after {
            if now.gt(&not_after) {
                error!("Certificate has expired (> after date)");
                return BadCertificateTimeInvalid;
            }
        } else {
            // No after time
            error!("Certificate has no after date");
            return BadCertificateInvalid;
        }

        info!("Certificate is valid for this time");
        Good
    }

    /// Tests if the supplied hostname matches any of the dns alt subject name entries on the cert
    pub fn is_hostname_valid(&self, hostname: &str) -> StatusCode {
        trace!("is_hostname_valid against {} on cert", hostname);
        // Look through alt subject names for a matching dns entry
        if let Some(ref alt_names) = self.value.subject_alt_names() {
            // Skip the application uri
            let found = alt_names.iter().skip(1).find(|n| {
                if let Some(dns) = n.dnsname() {
                    // Case insensitive comparison
                    dns.eq_ignore_ascii_case(hostname)
                } else {
                    false
                }
            });
            if found.is_some() {
                info!("Certificate host name {} is good", hostname);
                Good
            } else {
                error!("Cannot find a matching hostname for input {}", hostname);
                BadCertificateHostNameInvalid
            }
        } else {
            error!("Cert has no subject alt names at all");
            // No alt names
            BadCertificateHostNameInvalid
        }
    }

    /// Tests if the supplied application uri matches the uri alt subject name entry on the cert
    pub fn is_application_uri_valid(&self, application_uri: &str) -> StatusCode {
        trace!("is_application_uri_valid against {} on cert", application_uri);
        // Expecting the first subject alternative name to be a uri that matches with the supplied
        // application uri
        if let Some(ref alt_names) = self.value.subject_alt_names() {
            if alt_names.len() > 0 {
                if let Some(cert_application_uri) = alt_names[0].uri() {
                    if cert_application_uri == application_uri {
                        info!("Certificate application uri {} is good", application_uri);
                        Good
                    } else {
                        error!("Cert application uri {} does not match supplied uri {}", cert_application_uri, application_uri);
                        BadCertificateUriInvalid
                    }
                } else {
                    error!("Cert's first subject alt name is not a uri and cannot be compared");
                    BadCertificateUriInvalid
                }
            } else {
                error!("Cert has zero subject alt names");
                BadCertificateUriInvalid
            }
        } else {
            error!("Cert has no subject alt names at all");
            // No alt names
            BadCertificateUriInvalid
        }
    }

    /// OPC UA Part 6 MessageChunk structure
    ///
    /// The thumbprint is the SHA1 digest of the DER form of the certificate. The hash is 160 bits
    /// (20 bytes) in length and is sent in some secure conversation headers.
    ///
    /// The thumbprint might be used by the server / client for look-up purposes.
    pub fn thumbprint(&self) -> Thumbprint {
        use openssl::hash::{MessageDigest, hash};
        let der = self.value.to_der().unwrap();
        let digest = hash(MessageDigest::sha1(), &der).unwrap();
        Thumbprint::new(&digest)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_before(&self) -> Result<DateTime<Utc>, ()> {
        let date = self.value.not_before().to_string();
        Self::parse_asn1_date(&date)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_after(&self) -> Result<DateTime<Utc>, ()> {
        let date = self.value.not_after().to_string();
        Self::parse_asn1_date(&date)
    }

    pub fn to_der(&self) -> Result<Vec<u8>, ()> {
        if let Ok(der) = self.value.to_der() {
            Ok(der)
        } else {
            error!("Cannot turn X509 cert to DER");
            Err(())
        }
    }

    fn parse_asn1_date(date: &str) -> Result<DateTime<Utc>, ()> {
        // Parse ASN1 time format
        // MMM DD HH:MM:SS YYYY [GMT]
        let date = if date.ends_with(" GMT") {
            // Not interested in GMT part, ASN1 is always GMT (i.e. UTC)
            &date[..date.len() - 4]
        } else {
            &date
        };
        let result = Utc.datetime_from_str(date, "%b %d %H:%M:%S %Y");
        if result.is_err() {
            error!("Error = {:?}", result.unwrap_err());
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

    let dt: DateTime<Utc> = X509::parse_asn1_date("Feb 21 12:45:30 1999 GMT").unwrap();
    assert_eq!(dt.month(), 2);
    assert_eq!(dt.day(), 21);
    assert_eq!(dt.hour(), 12);
    assert_eq!(dt.minute(), 45);
    assert_eq!(dt.second(), 30);
    assert_eq!(dt.year(), 1999);
}
