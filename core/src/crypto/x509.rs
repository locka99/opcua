use std;
use std::marker::Send;
use std::fmt::{Debug, Formatter};
use std::result::Result;

use openssl::x509;
use openssl::nid;
use openssl::nid::Nid;

use chrono::{DateTime, Utc, TimeZone};

use opcua_types::ByteString;
use opcua_types::service_types::ApplicationDescription;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;

use crypto::pkey::PKey;
use crypto::thumbprint::Thumbprint;

const DEFAULT_KEYSIZE: u32 = 2048;
const DEFAULT_COUNTRY: &'static str = "IE";
const DEFAULT_STATE: &'static str = "Dublin";

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

impl From<ApplicationDescription> for X509Data {
    fn from(application_description: ApplicationDescription) -> Self {
        let alt_host_names = Self::alt_host_names(application_description.application_uri.as_ref());
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
    pub fn alt_host_names(application_uri: &str) -> Vec<String> {
        let mut result = Vec::new();
        // The first name is the application uri
        result.push(application_uri.to_string());
        // The remainder are alternative dns entries
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
    }


    /// Creates a sample certificate for testing, sample purposes only
    pub fn sample_cert() -> X509Data {
        let alt_host_names = Self::alt_host_names("urn:OPCUADemo");
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

unsafe impl std::marker::Sync for X509 {}

impl X509 {
    pub fn wrap(value: x509::X509) -> X509 {
        X509 { value }
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

    pub fn public_key(&self) -> Result<PKey, StatusCode> {
        if let Ok(pkey) = self.value.public_key() {
            let pkey = PKey::wrap(pkey);
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
        self.get_subject_entry(nid::COMMONNAME)
    }

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

        Good
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
    pub fn not_before(&self) -> Result<DateTime<Utc>, ()> {
        let date = self.value.not_before().to_string();
        Self::parse_asn1_date(&date)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_after(&self) -> Result<DateTime<Utc>, ()> {
        let date = self.value.not_after().to_string();
        Self::parse_asn1_date(&date)
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

    let dt: DateTime<Utc> = X509::parse_asn1_date("Feb 21 12:45:30 1999 GMT").unwrap();
    assert_eq!(dt.month(), 2);
    assert_eq!(dt.day(), 21);
    assert_eq!(dt.hour(), 12);
    assert_eq!(dt.minute(), 45);
    assert_eq!(dt.second(), 30);
    assert_eq!(dt.year(), 1999);
}
