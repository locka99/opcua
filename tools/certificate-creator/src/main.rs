#[macro_use]
extern crate clap;

extern crate opcua_core;

use std::path::PathBuf;

use opcua_core::crypto::*;

fn main() {
    if let Ok((args, overwrite, path)) = parse_x509_args() {
        println!("Creating certificate...");

        println!("  Key size = {}", args.key_size);
        println!("  CN (common name) = \"{}\"", args.common_name);
        println!("  O (organization) = \"{}\"", args.organization);
        println!("  OU (organizational unit) = \"{}\"", args.organizational_unit);
        println!("  C (country) = \"{}\"", args.country);
        println!("  ST (state) = \"{}\"", args.state);
        println!("  Duration = {} days", args.certificate_duration_days);
        for i in args.alt_host_names.iter().enumerate() {
            if i.0 == 0 {
                println!("  Application URI = \"{}\"", i.1);
            } else {
                println!("  DNS = \"{}\"", i.1);
            }
        }

        let cert_store = CertificateStore::new(&path);
        if let Err(_) = cert_store.create_and_store_application_instance_cert(&args, overwrite) {
            eprintln!("Certificate creation failed, check above for errors");
        } else {
            println!("Certificate and private key have been written to {} and {}",
                     cert_store.own_cert_path().to_string_lossy(), cert_store.own_private_key_path().to_string_lossy());
        }
    } else {
        eprintln!("Invalid arguments, check above for errors");
    }
}

fn parse_x509_args() -> Result<(X509Data, bool, PathBuf), ()> {
    use clap::*;
    let matches = App::new("OPC UA Certificate Creator")
        .author("Adam Lock <locka99@gmail.com>")
        .about(
            r#"OPC UA for Rust Certificate Creator.

This will creates a self-signed key (private/private.pem) and X509 certificate (own/cert.der) for
use with OPC UA clients and servers. Use the flags to control what the certificate contains. For
convenience some values will be prefilled from defaults, but for production purposes all defaults
should be overridden.

Files will be created under the specified under the specified --pkipath value."#)
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
            .value_name("path")
            .takes_value(true)
            .required(false))
        .arg(Arg::with_name("duration")
            .long("duration")
            .help("The duration in days of this certificate before it expires")
            .value_name("days")
            .default_value("365")
            .takes_value(true)
            .required(false))
        .arg(Arg::with_name("overwrite")
            .long("overwrite")
            .help("Overwrites existing files"))
        .arg(Arg::with_name("uri")
            .long("application-uri")
            .help("The application's uri used by OPC UA for authentication purposes.")
            .default_value("urn:OPCUAForRust")
            .takes_value(true))
        .arg(Arg::with_name("hostnames")
            .long("hostnames")
            .help("Explicitly add the specified DNS names to the cert.")
            .takes_value(true)
            .value_names(&["dns1", "dns2"])
            .multiple(true)
            .required(false))
        .arg(Arg::with_name("add-computer-name")
            .long("add-computer-name")
            .help("Add this computer's name (inferred from COMPUTERNAME / NAME environment variables) to the DNS names.")
            .value_name("flag")
            .takes_value(true)
            .default_value("true"))
        .arg(Arg::with_name("add-localhost-name")
            .long("add-localhost-name")
            .help("Add localhost, 127.0.0.1, ::1 to the DNS names.")
            .value_name("flag")
            .takes_value(true)
            .default_value("false"))
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
    let certificate_duration_days = value_t_or_exit!(matches, "duration", u32);

    let common_name = matches.value_of("CN").unwrap().to_string();
    let organization = matches.value_of("O").unwrap().to_string();
    let organizational_unit = matches.value_of("OU").unwrap().to_string();
    let country = matches.value_of("C").unwrap().to_string();
    let state = matches.value_of("ST").unwrap().to_string();
    let application_uri = matches.value_of("uri").unwrap().to_string();
    let add_localhost = value_t_or_exit!(matches, "add-localhost-name", bool);
    let add_computer_name = value_t_or_exit!(matches, "add-computer-name", bool);

    if certificate_duration_days == 0 {
        eprintln!("Duration is zero days!?");
        return Err(());
    }

    // Create alt host names for application uri, localhost and computer name if required
    let mut alt_host_names = X509Data::alt_host_names(&application_uri, add_localhost, add_computer_name);

    // Add the host names that were supplied by argument
    if let Some(hostnames) = matches.values_of("hostnames") {
        for h in hostnames {
            alt_host_names.push(h.to_string());
        }
    }
    if alt_host_names.len() == 1 {
        eprintln!("No alt host names were supplied or could be inferred. Certificate is useless without at least one DNS entry.");
        return Err(());
    }

    Ok((X509Data {
        key_size,
        common_name,
        organization,
        organizational_unit,
        country,
        state,
        alt_host_names,
        certificate_duration_days,
    }, overwrite, PathBuf::from(&pki_path)))
}