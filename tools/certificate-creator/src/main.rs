use std::path::PathBuf;

use opcua_crypto::*;

fn main() {
    if let Ok((x509_data, overwrite, path)) = parse_x509_args() {
        println!("Creating certificate...");
        println!("  Key size = {}", x509_data.key_size);
        println!("  CN (common name) = \"{}\"", x509_data.common_name);
        println!("  O (organization) = \"{}\"", x509_data.organization);
        println!("  OU (organizational unit) = \"{}\"", x509_data.organizational_unit);
        println!("  C (country) = \"{}\"", x509_data.country);
        println!("  ST (state) = \"{}\"", x509_data.state);
        println!("  Duration = {} days", x509_data.certificate_duration_days);
        for i in x509_data.alt_host_names.iter().enumerate() {
            if i.0 == 0 {
                println!("  Application URI = \"{}\"", i.1);
            } else {
                println!("  DNS = \"{}\"", i.1);
            }
        }

        let cert_store = CertificateStore::new(&path);
        if cert_store.create_and_store_application_instance_cert(&x509_data, overwrite).is_err() {
            eprintln!("Certificate creation failed, check above for errors");
        } else {
            println!("Certificate and private key have been written to {} and {}",
                     cert_store.own_cert_path().to_string_lossy(), cert_store.own_private_key_path().to_string_lossy());
        }
    }
}

struct Args {
    help: bool,
    overwrite: bool,
    key_size: u16,
    pki_path: String,
    duration: u32,
    application_uri: String,
    hostnames: String,
    add_computer_name: bool,
    add_localhost_name: bool,
    common_name: String,
    organization: String,
    organizational_unit: String,
    country: String,
    state: String,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            overwrite: args.contains(["-o", "--overwrite"]),
            key_size: args.opt_value_from_str("--key-size")?.unwrap_or(DEFAULT_KEY_SIZE),
            pki_path: args.opt_value_from_str("--pkipath")?.unwrap_or(String::from(DEFAULT_PKI_PATH)),
            duration: args.opt_value_from_str("--duration")?.unwrap_or(DEFAULT_DURATION),
            application_uri: args.opt_value_from_str("--application-uri")?.unwrap_or(String::from(DEFAULT_APPLICATION_URI)),
            hostnames: args.opt_value_from_str("--hostnames")?.unwrap_or(String::from("")),
            add_computer_name: args.contains("--add-computer-name"),
            add_localhost_name: args.contains("--add-localhost-name"),
            common_name: args.opt_value_from_str("--CN")?.unwrap_or(String::from(DEFAULT_CN)),
            organization: args.opt_value_from_str("--O")?.unwrap_or(String::from(DEFAULT_O)),
            organizational_unit: args.opt_value_from_str("--OU")?.unwrap_or(String::from(DEFAULT_OU)),
            country: args.opt_value_from_str("--C")?.unwrap_or(String::from(DEFAULT_C)),
            state: args.opt_value_from_str("--ST")?.unwrap_or(String::from(DEFAULT_ST)),
        })
    }

    pub fn usage() {
        println!(r#"OPC UA Certificate Creator

This creates a self-signed key (private/private.pem) and X509 certificate (own/cert.der) for
use with OPC UA clients and servers. Use the flags to control what the certificate contains. For
convenience some values will be prefilled from defaults, but for production purposes all defaults
should be overridden.

Usage:
  -h, --help            Show help.
  -o, --overwrite       Overwrites existing files.
  --key-size size       Sets the key size in bits - [2048, 4096] (default: {})
  --pkipath path        Path to the OPC UA for Rust pki/ directory. (default: {})
  --duration days       The duration in days of this certificate before it expires. (default: {})
  --application-uri     The application's uri used by OPC UA for authentication purposes. (default: {})
  --add-computer-name   Add this computer's name (inferred from COMPUTERNAME / NAME environment variables) to the alt host names.
  --add-localhost-name  Add localhost, 127.0.0.1, ::1 to the alt host names.
  --hostnames names     Comma separated list of DNS/IP names to add as subject alt host names.
  --CN name             Specifies the Common Name for the cert (default: {}).
  --O name              Specifies the Organization for the cert (default: {}).
  --OU name             Specifies the Organization Unit for the cert (default: {}).
  --C name              Specifies the Country for the cert (default: {}).
  --ST name             "Specifies the State for the cert. (default: {})"#,
                 DEFAULT_KEY_SIZE, DEFAULT_PKI_PATH, DEFAULT_DURATION, DEFAULT_APPLICATION_URI, DEFAULT_CN, DEFAULT_O, DEFAULT_OU, DEFAULT_C, DEFAULT_ST);
    }
}

const DEFAULT_KEY_SIZE: u16 = 2048;
const DEFAULT_PKI_PATH: &'static str = ".";
const DEFAULT_DURATION: u32 = 365;
const DEFAULT_APPLICATION_URI: &'static str = "urn:OPCUAForRust";
const DEFAULT_CN: &'static str = "OPC UA Demo Key";
const DEFAULT_O: &'static str = "OPC UA for Rust";
const DEFAULT_OU: &'static str = "Certificate Creator";
const DEFAULT_C: &'static str = "IE";
const DEFAULT_ST: &'static str = "Dublin";

fn parse_x509_args() -> Result<(X509Data, bool, PathBuf), ()> {
    // Read command line arguments
    let args = Args::parse_args()
        .map_err(|_| Args::usage())?;
    if args.help || ![2048u16, 4096u16].contains(&args.key_size) || args.duration == 0 {
        Args::usage();
        Err(())
    } else {
        let pki_path = args.pki_path;
        let key_size = args.key_size as u32;
        let overwrite = args.overwrite;
        let certificate_duration_days = args.duration;

        let common_name = args.common_name;
        let organization = args.organization;
        let organizational_unit = args.organizational_unit;
        let country = args.country;
        let state = args.state;
        let application_uri = args.application_uri;
        let add_localhost = args.add_localhost_name;
        let add_computer_name = args.add_computer_name;

        // Create alt host names for application uri, localhost and computer name if required
        let hostnames: Vec<String> = args.hostnames.split(",").map(|s| s.to_string()).collect();
        let alt_host_names = X509Data::alt_host_names(&application_uri, Some(hostnames), add_localhost, add_computer_name);

        // Add the host names that were supplied by argument
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
}