// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

// X509 certificate wrapper.

use std::{
    self,
    collections::HashSet,
    fmt::{self, Debug, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    result::Result,
};

use chrono::{DateTime, TimeZone, Utc};
use openssl::{
    asn1::*,
    hash,
    nid::Nid,
    pkey,
    rsa::*,
    x509::{self, extension::*},
};

use crate::types::{service_types::ApplicationDescription, status_code::StatusCode, ByteString};

use super::{
    hostname,
    pkey::{PrivateKey, PublicKey},
    thumbprint::Thumbprint,
};

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
    /// A list of alternate host names as text. The first entry is expected to be the application uri.
    /// The remainder are treated as IP addresses or DNS names depending on whether they parse as IPv4, IPv6 or neither.
    /// IP addresses are expected to be in their canonical form and you will run into trouble
    /// especially in IPv6 if they are not because string comparison may be used during validation.
    /// e.g. IPv6 canonical format shortens addresses by stripping leading zeros, sequences of zeros
    /// and using lowercase hex.
    pub alt_host_names: Vec<String>,
    /// The number of days the certificate is valid for, i.e. it will be valid from now until now + duration_days.
    pub certificate_duration_days: u32,
}

impl From<(ApplicationDescription, Option<Vec<String>>)> for X509Data {
    fn from(v: (ApplicationDescription, Option<Vec<String>>)) -> Self {
        let (application_description, addresses) = v;
        let application_uri = application_description.application_uri.as_ref();
        let alt_host_names = Self::alt_host_names(application_uri, addresses, false, true, true);
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

impl From<ApplicationDescription> for X509Data {
    fn from(v: ApplicationDescription) -> Self {
        X509Data::from((v, None))
    }
}

impl X509Data {
    /// Gets a list of possible dns hostnames for this device
    pub fn computer_hostnames() -> Vec<String> {
        let mut result = Vec::with_capacity(2);

        if let Ok(hostname) = hostname() {
            if !hostname.is_empty() {
                result.push(hostname);
            }
        }
        if result.is_empty() {
            // Look for environment vars
            if let Ok(machine_name) = std::env::var("COMPUTERNAME") {
                result.push(machine_name);
            }
            if let Ok(machine_name) = std::env::var("NAME") {
                result.push(machine_name);
            }
        }

        result
    }

    /// Creates a list of uri + DNS hostnames using the supplied arguments
    pub fn alt_host_names(
        application_uri: &str,
        addresses: Option<Vec<String>>,
        add_localhost: bool,
        add_computer_name: bool,
        add_ip_addresses: bool,
    ) -> Vec<String> {
        // The first name is the application uri
        let mut result = vec![application_uri.to_string()];

        // Addresses supplied by caller
        if let Some(mut addresses) = addresses {
            result.append(&mut addresses);
        }

        // The remainder are alternative IP/DNS entries
        if add_localhost {
            result.push("localhost".to_string());
            if add_ip_addresses {
                result.push("127.0.0.1".to_string());
                result.push("::1".to_string());
            }
        }
        // Get the machine name / ip address
        if add_computer_name {
            let computer_hostnames = Self::computer_hostnames();
            if add_ip_addresses {
                let mut ipaddresses = HashSet::new();
                // Iterate hostnames, produce a set of ip addresses from lookup, using set to eliminate duplicates
                computer_hostnames.iter().for_each(|h| {
                    ipaddresses.extend(Self::ipaddresses_from_hostname(h));
                });
                result.extend(computer_hostnames);
                result.extend(ipaddresses);
            } else {
                result.extend(computer_hostnames);
            }
        }
        if result.len() == 1 {
            panic!("Could not create any DNS alt host names");
        }
        result
    }

    /// Do a hostname lookup, find matching IP addresses
    fn ipaddresses_from_hostname(hostname: &str) -> Vec<String> {
        // Get ip addresses
        if let Ok(addresses) = (hostname, 0u16).to_socket_addrs() {
            addresses
                .map(|addr| match addr {
                    SocketAddr::V4(addr) => addr.ip().to_string(),
                    SocketAddr::V6(addr) => addr.ip().to_string(),
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Creates a sample certificate for testing, sample purposes only
    pub fn sample_cert() -> X509Data {
        let alt_host_names = Self::alt_host_names("urn:OPCUADemo", None, false, true, true);
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

#[derive(Debug)]
pub struct X509Error;

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X509Error")
    }
}

impl std::error::Error for X509Error {}

/// This is a wrapper around the `OpenSSL` `X509` cert
#[derive(Clone)]
pub struct X509 {
    value: x509::X509,
}

impl Debug for X509 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the cert, and exists to keep derive happy
        // on structs that contain an X509 instance
        write!(f, "[x509]")
    }
}

impl From<x509::X509> for X509 {
    fn from(value: x509::X509) -> Self {
        Self { value }
    }
}

impl X509 {
    pub fn from_der(der: &[u8]) -> Result<Self, X509Error> {
        x509::X509::from_der(der).map(X509::from).map_err(|_| {
            error!("Cannot produce an x509 cert from the data supplied");
            X509Error
        })
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
    pub fn cert_and_pkey(x509_data: &X509Data) -> Result<(Self, PrivateKey), String> {
        // Create a key pair
        let rsa = Rsa::generate(x509_data.key_size).map_err(|err| {
            format!(
                "Cannot create key pair check error {} and key size {}",
                err, x509_data.key_size
            )
        })?;
        let pkey = pkey::PKey::from_rsa(rsa)
            .map_err(|err| format!("Cannot create key pair check error {}", err))?;
        let pkey = PrivateKey::wrap_private_key(pkey);

        // Create an X509 cert to hold the public key
        let cert = Self::from_pkey(&pkey, x509_data)?;

        Ok((cert, pkey))
    }

    pub fn from_pkey(pkey: &PrivateKey, x509_data: &X509Data) -> Result<Self, String> {
        let mut builder = x509::X509Builder::new().unwrap();
        // value 2 == version 3 (go figure)
        let _ = builder.set_version(2);
        let issuer_name = {
            let mut name = x509::X509NameBuilder::new().unwrap();
            // Common name
            name.append_entry_by_text("CN", &x509_data.common_name)
                .unwrap();
            // Organization
            name.append_entry_by_text("O", &x509_data.organization)
                .unwrap();
            // Organizational Unit
            name.append_entry_by_text("OU", &x509_data.organizational_unit)
                .unwrap();
            // Country
            name.append_entry_by_text("C", &x509_data.country).unwrap();
            // State
            name.append_entry_by_text("ST", &x509_data.state).unwrap();
            name.build()
        };
        // Issuer and subject shall be the same for self-signed cert
        let _ = builder.set_subject_name(&issuer_name);
        let _ = builder.set_issuer_name(&issuer_name);

        // For Application Instance Certificate specifies how cert may be used
        let key_usage = KeyUsage::new()
            .digital_signature()
            .non_repudiation()
            .key_encipherment()
            .data_encipherment()
            .key_cert_sign()
            .build()
            .unwrap();
        let _ = builder.append_extension(key_usage);
        let extended_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .server_auth()
            .build()
            .unwrap();
        let _ = builder.append_extension(extended_key_usage);

        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(x509_data.certificate_duration_days).unwrap())
            .unwrap();
        builder.set_pubkey(&pkey.value).unwrap();

        // Random serial number
        {
            use openssl::bn::BigNum;
            use openssl::bn::MsbOption;
            let mut serial = BigNum::new().unwrap();
            serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
            let serial = serial.to_asn1_integer().unwrap();
            let _ = builder.set_serial_number(&serial);
        }

        // Subject alt names - The first is assumed to be the application uri. The remainder
        // are either IP or DNS entries.
        if !x509_data.alt_host_names.is_empty() {
            let subject_alternative_name = {
                let mut subject_alternative_name = SubjectAlternativeName::new();
                x509_data
                    .alt_host_names
                    .iter()
                    .enumerate()
                    .for_each(|(i, alt_host_name)| {
                        if !alt_host_name.is_empty() {
                            if i == 0 {
                                // The first entry is the application uri
                                subject_alternative_name.uri(alt_host_name);
                            } else if alt_host_name.parse::<Ipv4Addr>().is_ok()
                                || alt_host_name.parse::<Ipv6Addr>().is_ok()
                            {
                                // Treat this as an IPv4/IPv6 address
                                subject_alternative_name.ip(alt_host_name);
                            } else {
                                // Treat this as a DNS entry
                                subject_alternative_name.dns(alt_host_name);
                            }
                        }
                    });
                subject_alternative_name
                    .build(&builder.x509v3_context(None, None))
                    .unwrap()
            };
            builder.append_extension(subject_alternative_name).unwrap();
        }

        // Self-sign
        let _ = builder.sign(&pkey.value, hash::MessageDigest::sha256());

        Ok(X509::from(builder.build()))
    }

    pub fn from_byte_string(data: &ByteString) -> Result<X509, StatusCode> {
        if data.is_null() {
            error!("Cannot make certificate from null bytestring");
            Err(StatusCode::BadCertificateInvalid)
        } else if let Ok(cert) = x509::X509::from_der(data.value.as_ref().unwrap()) {
            Ok(X509::from(cert))
        } else {
            error!("Cannot make certificate, does bytestring contain .der?");
            Err(StatusCode::BadCertificateInvalid)
        }
    }

    /// Returns a ByteString representation of the cert which is DER encoded form of X509v3
    pub fn as_byte_string(&self) -> ByteString {
        let der = self.value.to_der().unwrap();
        ByteString::from(&der)
    }

    pub fn public_key(&self) -> Result<PublicKey, StatusCode> {
        self.value
            .public_key()
            .map(PublicKey::wrap_public_key)
            .map_err(|_| {
                error!("Cannot obtain public key from certificate");
                StatusCode::BadCertificateInvalid
            })
    }

    /// Returns the key length in bits (if possible)
    pub fn key_length(&self) -> Result<usize, X509Error> {
        let pub_key = self.value.public_key().map_err(|_| X509Error)?;
        Ok(pub_key.size() * 8)
    }

    fn get_subject_entry(&self, nid: Nid) -> Result<String, X509Error> {
        let subject_name = self.value.subject_name();
        let mut entries = subject_name.entries_by_nid(nid);
        if let Some(entry) = entries.next() {
            // Asn1StringRef has to be converted out of Asn1 into UTF-8 and then a String
            if let Ok(value) = entry.data().as_utf8() {
                use std::ops::Deref;
                // Value is an OpensslString type here so it has to be converted
                Ok(value.deref().to_string())
            } else {
                Err(X509Error)
            }
        } else {
            Err(X509Error)
        }
    }

    // Produces a string such as "CN=foo/C=IE"
    pub fn subject_name(&self) -> String {
        use std::ops::Deref;
        self.value
            .subject_name()
            .entries()
            .map(|e| {
                let v = if let Ok(v) = e.data().as_utf8() {
                    v.deref().to_string()
                } else {
                    "?".into()
                };
                format!("{}={}", e.object(), v)
            })
            .collect::<Vec<String>>()
            .join("/")
    }

    /// Gets the common name out of the cert
    pub fn common_name(&self) -> Result<String, X509Error> {
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
                return StatusCode::BadCertificateTimeInvalid;
            }
        } else {
            // No before time
            error!("Certificate has no before date");
            return StatusCode::BadCertificateInvalid;
        }

        // Expiration time
        let not_after = self.not_after();
        if let Ok(not_after) = not_after {
            if now.gt(&not_after) {
                error!("Certificate has expired (> after date)");
                return StatusCode::BadCertificateTimeInvalid;
            }
        } else {
            // No after time
            error!("Certificate has no after date");
            return StatusCode::BadCertificateInvalid;
        }

        info!("Certificate is valid for this time");
        StatusCode::Good
    }

    fn subject_alt_names(&self) -> Option<Vec<String>> {
        if let Some(ref alt_names) = self.value.subject_alt_names() {
            // Skip the application uri
            let subject_alt_names = alt_names
                .iter()
                .skip(1)
                .map(|n| {
                    if let Some(dnsname) = n.dnsname() {
                        dnsname.to_string()
                    } else if let Some(ip) = n.ipaddress() {
                        if ip.len() == 4 {
                            let mut addr = [0u8; 4];
                            addr[..].clone_from_slice(ip);
                            Ipv4Addr::from(addr).to_string()
                        } else if ip.len() == 16 {
                            let mut addr = [0u8; 16];
                            addr[..].clone_from_slice(ip);
                            Ipv6Addr::from(addr).to_string()
                        } else {
                            "".to_string()
                        }
                    } else {
                        "".to_string()
                    }
                })
                .collect();
            Some(subject_alt_names)
        } else {
            None
        }
    }

    /// Tests if the supplied hostname matches any of the dns alt subject name entries on the cert
    pub fn is_hostname_valid(&self, hostname: &str) -> StatusCode {
        trace!("is_hostname_valid against {} on cert", hostname);
        // Look through alt subject names for a matching entry
        if hostname.is_empty() {
            error!("Hostname is empty");
            StatusCode::BadCertificateHostNameInvalid
        } else if let Some(subject_alt_names) = self.subject_alt_names() {
            let found = subject_alt_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(hostname));
            if found {
                info!("Certificate host name {} is good", hostname);
                StatusCode::Good
            } else {
                let alt_names = subject_alt_names
                    .iter()
                    .map(|n| n.as_ref())
                    .collect::<Vec<&str>>()
                    .join(", ");
                error!(
                    "Cannot find a matching hostname for input {}, alt names = {}",
                    hostname, alt_names
                );
                StatusCode::BadCertificateHostNameInvalid
            }
        } else {
            // No alt names
            error!("Cert has no subject alt names at all");
            StatusCode::BadCertificateHostNameInvalid
        }
    }

    /// Tests if the supplied application uri matches the uri alt subject name entry on the cert
    pub fn is_application_uri_valid(&self, application_uri: &str) -> StatusCode {
        trace!(
            "is_application_uri_valid against {} on cert",
            application_uri
        );
        // Expecting the first subject alternative name to be a uri that matches with the supplied
        // application uri
        if let Some(ref alt_names) = self.value.subject_alt_names() {
            if alt_names.len() > 0 {
                if let Some(cert_application_uri) = alt_names[0].uri() {
                    if cert_application_uri == application_uri {
                        info!("Certificate application uri {} is good", application_uri);
                        StatusCode::Good
                    } else {
                        error!(
                            "Cert application uri {} does not match supplied uri {}",
                            cert_application_uri, application_uri
                        );
                        StatusCode::BadCertificateUriInvalid
                    }
                } else {
                    error!("Cert's first subject alt name is not a uri and cannot be compared");
                    StatusCode::BadCertificateUriInvalid
                }
            } else {
                error!("Cert has zero subject alt names");
                StatusCode::BadCertificateUriInvalid
            }
        } else {
            error!("Cert has no subject alt names at all");
            // No alt names
            StatusCode::BadCertificateUriInvalid
        }
    }

    /// OPC UA Part 6 MessageChunk structure
    ///
    /// The thumbprint is the SHA1 digest of the DER form of the certificate. The hash is 160 bits
    /// (20 bytes) in length and is sent in some secure conversation headers.
    ///
    /// The thumbprint might be used by the server / client for look-up purposes.
    pub fn thumbprint(&self) -> Thumbprint {
        use openssl::hash::{hash, MessageDigest};
        let der = self.value.to_der().unwrap();
        let digest = hash(MessageDigest::sha1(), &der).unwrap();
        Thumbprint::new(&digest)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_before(&self) -> Result<DateTime<Utc>, X509Error> {
        let date = self.value.not_before().to_string();
        Self::parse_asn1_date(&date)
    }

    /// Turn the Asn1 values into useful portable types
    pub fn not_after(&self) -> Result<DateTime<Utc>, X509Error> {
        let date = self.value.not_after().to_string();
        Self::parse_asn1_date(&date)
    }

    pub fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        self.value.to_der().map_err(|e| {
            error!("Cannot turn X509 cert to DER, err = {:?}", e);
            X509Error
        })
    }

    fn parse_asn1_date(date: &str) -> Result<DateTime<Utc>, X509Error> {
        const SUFFIX: &str = " GMT";
        // Parse ASN1 time format
        // MMM DD HH:MM:SS YYYY [GMT]
        let date = if date.ends_with(SUFFIX) {
            // Not interested in GMT part, ASN1 is always GMT (i.e. UTC)
            let end = date.len() - SUFFIX.len();
            &date[..end]
        } else {
            date
        };
        Utc.datetime_from_str(date, "%b %d %H:%M:%S %Y")
            .map_err(|e| {
                error!("Cannot parse ASN1 date, err = {:?}", e);
                X509Error
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// This test checks that a cert will validate dns or ip entries in the subject alt host names
    #[test]
    fn alt_hostnames() {
        crate::console_logging::init();

        let alt_host_names = ["uri:foo", "host2", "www.google.com", "192.168.1.1", "::1"];

        // Create a cert with alt hostnames which are both IP and DNS entries
        let args = X509Data {
            key_size: 2048,
            common_name: "x".to_string(),
            organization: "x.org".to_string(),
            organizational_unit: "x.org ops".to_string(),
            country: "EN".to_string(),
            state: "London".to_string(),
            alt_host_names: alt_host_names.iter().map(|h| h.to_string()).collect(),
            certificate_duration_days: 60,
        };

        let (x509, _pkey) = X509::cert_and_pkey(&args).unwrap();

        assert!(!x509.is_hostname_valid("").is_good());
        assert!(!x509.is_hostname_valid("uri:foo").is_good()); // The application uri should not be valid
        assert!(!x509.is_hostname_valid("192.168.1.0").is_good());
        assert!(!x509.is_hostname_valid("www.cnn.com").is_good());
        assert!(!x509.is_hostname_valid("host1").is_good());

        alt_host_names.iter().skip(1).for_each(|n| {
            println!("Hostname {}", n);
            assert!(x509.is_hostname_valid(n).is_good());
        })
    }
}
