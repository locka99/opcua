use std::path::PathBuf;

use opcua::crypto::*;

fn main() {
    if let Ok((x509_data, overwrite, pki_path, cert_path, pkey_path)) = parse_x509_args() {
        println!("Creating certificate...");
        println!("  Key size = {}", x509_data.key_size);
        println!("  CN (common name) = \"{}\"", x509_data.common_name);
        println!("  O (organization) = \"{}\"", x509_data.organization);
        println!(
            "  OU (organizational unit) = \"{}\"",
            x509_data.organizational_unit
        );
        println!("  C (country) = \"{}\"", x509_data.country);
        println!("  ST (state) = \"{}\"", x509_data.state);
        println!("  Duration = {} days", x509_data.certificate_duration_days);

        x509_data
            .alt_host_names
            .iter()
            .enumerate()
            .for_each(|(idx, addr)| {
                if idx == 0 {
                    println!("  Application URI = \"{}\"", addr);
                } else {
                    println!("  DNS = \"{}\"", addr);
                }
            });

        // Make paths relative
        let cert_path = {
            let mut path = pki_path.clone();
            path.push(cert_path);
            path
        };
        let pkey_path = {
            let mut path = pki_path;
            path.push(pkey_path);
            path
        };

        let _ = CertificateStore::create_certificate_and_key(
            &x509_data, overwrite, &cert_path, &pkey_path,
        )
        .map_err(|err| {
            eprintln!(
                "Certificate creation failed, check above and reason \"{}\" for errors",
                err
            );
        })
        .map(|_| {
            println!(
                "Certificate and private key have been written to {} and {}",
                cert_path.display(),
                pkey_path.display()
            );
        });
    }
}

struct Args {
    help: bool,
    overwrite: bool,
    key_size: u16,
    pki_path: String,
    cert_path: String,
    pkey_path: String,
    duration: u32,
    application_uri: String,
    hostnames: String,
    add_computer_name: bool,
    add_localhost_name: bool,
    add_ip_addresses: bool,
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
            key_size: args
                .opt_value_from_str("--key-size")?
                .unwrap_or(DEFAULT_KEY_SIZE),
            pki_path: args
                .opt_value_from_str("--pki-path")?
                .unwrap_or_else(|| String::from(DEFAULT_PKI_PATH)),
            cert_path: args
                .opt_value_from_str("--cert-name")?
                .unwrap_or_else(|| String::from(DEFAULT_CERT_PATH)),
            pkey_path: args
                .opt_value_from_str("--pkey-name")?
                .unwrap_or_else(|| String::from(DEFAULT_PKEY_PATH)),
            duration: args
                .opt_value_from_str("--duration")?
                .unwrap_or(DEFAULT_DURATION),
            application_uri: args
                .opt_value_from_str("--application-uri")?
                .unwrap_or_else(|| String::from(DEFAULT_APPLICATION_URI)),
            hostnames: args
                .opt_value_from_str("--hostnames")?
                .unwrap_or_else(|| String::from("")),
            add_computer_name: args.contains("--add-computer-name"),
            add_localhost_name: args.contains("--add-localhost-name"),
            add_ip_addresses: args.contains("--add-ip-addresses"),
            common_name: args
                .opt_value_from_str("--CN")?
                .unwrap_or_else(|| String::from(DEFAULT_CN)),
            organization: args
                .opt_value_from_str("--O")?
                .unwrap_or_else(|| String::from(DEFAULT_O)),
            organizational_unit: args
                .opt_value_from_str("--OU")?
                .unwrap_or_else(|| String::from(DEFAULT_OU)),
            country: args
                .opt_value_from_str("--C")?
                .unwrap_or_else(|| String::from(DEFAULT_C)),
            state: args
                .opt_value_from_str("--ST")?
                .unwrap_or_else(|| String::from(DEFAULT_ST)),
        })
    }

    pub fn usage() {
        println!(
            r#"OPC UA Certificate Creator

This creates a self-signed key and X509 certificate for use with OPC UA clients and servers.
Use the flags to control what the certificate contains. For convenience some values will be
prefilled from defaults, but for production purposes all defaults should be overridden.

Usage:
  -h, --help            Show help.
  -o, --overwrite       Overwrites existing files.
  --key-size size       Sets the key size in bits - [2048, 4096] (default: {})
  --pki-path path       Path to write the certificate and key. (default: {})
  --cert-name           Name of certificate file relative to pki-path. (default: {})
  --pkey-name           Name of private key file relative to pki-path. (default: {})
  --duration days       The duration in days of this certificate before it expires. (default: {})
  --application-uri     The application's uri used by OPC UA for authentication purposes. (default: {})
  --add-computer-name   Add this computer's name (inferred from COMPUTERNAME / NAME environment variables) to the alt host names.
  --add-localhost-name  Add localhost (and also 127.0.0.1, ::1 if --add-ip-addresses) to the alt host names.
  --add-ip-addresses    Add IP addresses from host name lookup to the alt host names.
  --hostnames names     Comma separated list of DNS/IP names to add as subject alt host names.
  --CN name             Specifies the Common Name for the cert (default: {}).
  --O name              Specifies the Organization for the cert (default: {}).
  --OU name             Specifies the Organization Unit for the cert (default: {}).
  --C name              Specifies the Country for the cert (default: {}).
  --ST name             "Specifies the State for the cert. (default: {})"#,
            DEFAULT_KEY_SIZE,
            DEFAULT_PKI_PATH,
            DEFAULT_CERT_PATH,
            DEFAULT_PKEY_PATH,
            DEFAULT_DURATION,
            DEFAULT_APPLICATION_URI,
            DEFAULT_CN,
            DEFAULT_O,
            DEFAULT_OU,
            DEFAULT_C,
            DEFAULT_ST
        );
    }
}

const DEFAULT_KEY_SIZE: u16 = 2048;
const DEFAULT_PKI_PATH: &str = ".";
const DEFAULT_DURATION: u32 = 365;
const DEFAULT_APPLICATION_URI: &str = "urn:OPCUAForRust";
const DEFAULT_CN: &str = "OPC UA Demo Key";
const DEFAULT_O: &str = "OPC UA for Rust";
const DEFAULT_OU: &str = "Certificate Creator";
const DEFAULT_C: &str = "IE";
const DEFAULT_ST: &str = "Dublin";
const DEFAULT_CERT_PATH: &str = "cert.der";
const DEFAULT_PKEY_PATH: &str = "private.pem";

fn parse_x509_args() -> Result<(X509Data, bool, PathBuf, PathBuf, PathBuf), ()> {
    // Read command line arguments
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help || ![2048u16, 4096u16].contains(&args.key_size) || args.duration == 0 {
        Args::usage();
        Err(())
    } else {
        let pki_path = args.pki_path;
        let cert_path = args.cert_path;
        let pkey_path = args.pkey_path;
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
        let add_ip_addresses = args.add_ip_addresses;

        // Create alt host names for application uri, localhost and computer name if required
        let hostnames: Vec<String> = args.hostnames.split(',').map(|s| s.to_string()).collect();
        let alt_host_names = X509Data::alt_host_names(
            &application_uri,
            Some(hostnames),
            add_localhost,
            add_computer_name,
            add_ip_addresses,
        );

        // Add the host names that were supplied by argument
        if alt_host_names.len() == 1 {
            eprintln!("No alt host names were supplied or could be inferred. Certificate is useless without at least one DNS entry.");
            return Err(());
        }

        Ok((
            X509Data {
                key_size,
                common_name,
                organization,
                organizational_unit,
                country,
                state,
                alt_host_names,
                certificate_duration_days,
            },
            overwrite,
            PathBuf::from(&pki_path),
            PathBuf::from(&cert_path),
            PathBuf::from(&pkey_path),
        ))
    }
}
