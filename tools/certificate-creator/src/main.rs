#[macro_use]
extern crate clap;

#[cfg(feature = "crypto")]
extern crate openssl;

#[cfg(feature = "crypto")]
mod creator;

#[derive(Debug)]
pub struct Args {
    pub key_size: u32,
    pub pki_path: String,
    pub overwrite: bool,
    pub common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub country: String,
    pub state: String,
    pub alt_host_names: Vec<String>,
    pub certificate_duration_days: u32,
}

#[cfg(feature = "crypto")]
fn main() {
    let args = parse_args();
    if let Err(_) = creator::run(args) {
        println!("Certificate creation failed, check above for errors");
    }
}

#[cfg(not(feature = "crypto"))]
fn main() {
    let args = parse_args();
    print!("Args = {:#?}", args);
    panic!("This tool doesn't do anything without crypto, e.g. \"cargo build --features crypto\"");
}

fn parse_args() -> Args {
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

    Args {
        pki_path: pki_path,
        key_size: key_size,
        overwrite: overwrite,
        common_name: common_name,
        organization: organization,
        organizational_unit: organizational_unit,
        country: country,
        state: state,
        alt_host_names: alt_host_names,
        certificate_duration_days: 365,
    }
}