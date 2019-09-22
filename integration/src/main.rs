fn main() {
    eprintln!(r#"Needs to be run with "cargo test -- --test-threads=1 --ignored""#);
}


pub const ENDPOINT_ID_NONE: &str = "sample_none";
pub const ENDPOINT_ID_BASIC128RSA15_SIGN_ENCRYPT: &str = "sample_basic128rsa15_signencrypt";
pub const ENDPOINT_ID_BASIC128RSA15_SIGN: &str = "sample_basic128rsa15_sign";
pub const ENDPOINT_ID_BASIC256_SIGN_ENCRYPT: &str = "sample_basic256_signencrypt";
pub const ENDPOINT_ID_BASIC256_SIGN: &str = "sample_basic256_sign";
pub const ENDPOINT_ID_BASIC256SHA256_SIGN_ENCRYPT: &str = "sample_basic256sha256_signencrypt";
pub const ENDPOINT_ID_BASIC256SHA256_SIGN: &str = "sample_basic256sha256_sign";

#[cfg(test)]
mod tests;

#[cfg(test)]
mod harness;