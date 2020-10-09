fn main() {
    eprintln!(r#"Needs to be run with "cargo test -- --test-threads=1 --ignored""#);
}

pub const CLIENT_USERPASS_ID: &str = "sample1";
pub const CLIENT_X509_ID: &str = "x509";

#[cfg(test)]
mod tests;

#[cfg(test)]
mod harness;