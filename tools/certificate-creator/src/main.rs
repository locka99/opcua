#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate opcua_core;

use std::path::{PathBuf};

use opcua_core::crypto::*;

fn main() {
    let _ = opcua_core::init_logging();
    let (args, overwrite, path) = parse_x509_args();

    let cert_store = CertificateStore::new(&path);
    if let Err(_) = cert_store.create_and_store_cert(&args, overwrite) {
        println!("Certificate creation failed, check above for errors");
    }
}

fn parse_x509_args() -> (X509Data, bool, PathBuf) {
    use clap::*;
    let matches = App::new("OPC UA Certificate Creator")
        .author("Adam Lock <locka99@gmail.com>")
        .about(
            r#"Creates a self-signed private key (private/private.pem) and X509 certificate (own/cert.der) for use with OPC UA for Rust.
The files will be created under the specified under the specified --pkipath value."#)
        .arg(Arg::with_name("keysize")
            .long("keysize")
            .help("Sets the key size(strength)")
            .default_value("2048")
            .takes_value(true)
            .possible_values(&["2048", "4096"])
            .required(false))
        .arg(Arg::with_name("pkipath")
            .long("pkipath")
            .help("Path to the OPC UA for Rust pki/ directory")
            .default_value(".")
            .takes_value(true)
            .required(false))
        .arg(Arg::with_name("overwrite")
            .long("overwrite")
            .help("Overwrites existing files"))
        .arg(Arg::with_name("althostname")
            .long("althostname")
            .help("Alternate hostnames / ip addresses. Use this arg as many times as you like.")
            .takes_value(true)
            .multiple(true)
            .required(false))
        .arg(Arg::with_name("CN")
            .long("CN")
            .help("Specifies the Common Name for the cert")
            .default_value("OPC UA Demo Key")
            .takes_value(true))
        .arg(Arg::with_name("O")
            .long("O")
            .help("Specifies the Organization for the cert")
            .default_value("OPC UA for Rust")
            .takes_value(true))
        .arg(Arg::with_name("OU")
            .long("OU")
            .help("Specifies the Organization Unit for the cert")
            .default_value("Certificate Creator")
            .takes_value(true))
        .arg(Arg::with_name("C")
            .long("C")
            .help("Specifies the Country for the cert")
            .default_value("IE")
            .takes_value(true))
        .arg(Arg::with_name("ST")
            .long("ST")
            .help("Specifies the State for the cert")
            .default_value("Dublin")
            .takes_value(true))
        .get_matches();

    let pki_path = matches.value_of("pkipath").unwrap().to_string();
    let key_size = value_t_or_exit!(matches, "keysize", u32);
    let overwrite = matches.is_present("overwrite");

    let common_name = matches.value_of("CN").unwrap().to_string();
    let organization = matches.value_of("O").unwrap().to_string();
    let organizational_unit = matches.value_of("OU").unwrap().to_string();
    let country = matches.value_of("C").unwrap().to_string();
    let state = matches.value_of("ST").unwrap().to_string();

    let alt_host_names = {
        let mut result = Vec::new();

        let values = matches.values_of("althostname");
        if let Some(values) = values {
            for v in values {
                result.push(v.to_string());
            }
        }

        // Get the machine name / ip address
        if let Ok(machine_name) = std::env::var("COMPUTERNAME") {
            result.push(machine_name);
        }
        if let Ok(machine_name) = std::env::var("NAME") {
            result.push(machine_name);
        }

        result
    };

    if alt_host_names.is_empty() {
        warn!("No alt host names were supplied or could be inferred. Certificate may be useless without at least one.")
    }

    (X509Data {
        key_size: key_size,
        common_name: common_name,
        organization: organization,
        organizational_unit: organizational_unit,
        country: country,
        state: state,
        alt_host_names: alt_host_names,
        certificate_duration_days: 365,
    }, overwrite, PathBuf::from(&pki_path))
}