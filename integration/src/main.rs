fn main() {
    eprintln!(r#"Needs to be run with "cargo test -- --test-threads=1 --ignored""#);
}

pub const CLIENT_USERPASS_ID: &str = "sample";
pub const CLIENT_X509_ID: &str = "x509";

pub const CLIENT_ENDPOINT_ANONYMOUS_NONE: &str = "sample_none";
pub const CLIENT_ENDPOINT_ANONYMOUS_BASIC128RSA15_SIGN_ENCRYPT: &str = "sample_basic128rsa15_signencrypt";
pub const CLIENT_ENDPOINT_ANONYMOUS_BASIC128RSA15_SIGN: &str = "sample_basic128rsa15_sign";
pub const CLIENT_ENDPOINT_ANONYMOUS_BASIC256_SIGN_ENCRYPT: &str = "sample_basic256_signencrypt";
pub const CLIENT_ENDPOINT_ANONYMOUS_BASIC256_SIGN: &str = "sample_basic256_sign";
pub const CLIENT_ENDPOINT_ANONYMOUS_BASIC256SHA256_SIGN_ENCRYPT: &str = "sample_basic256sha256_signencrypt";
pub const CLIENT_ENDPOINT_ANONYMOUS_BASIC256SHA256_SIGN: &str = "sample_basic256sha256_sign";
pub const CLIENT_ENDPOINT_USERPASS_BASIC256_SIGN_ENCRYPT: &str = "sample_userpass_basic256_signencrypt";
pub const CLIENT_ENDPOINT_X509_BASIC256_SIGN_ENCRYPT: &str = "sample_x509_basic256_signencrypt";

#[cfg(test)]
mod tests;

#[cfg(test)]
mod harness;