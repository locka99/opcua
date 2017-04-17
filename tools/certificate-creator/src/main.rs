#[cfg(feature = "crypto")]
extern crate openssl;

#[cfg(feature = "crypto")]
fn main() {
    use openssl::*;
    // TODO This is a placeholder, where the certificate creator will generate a certificate compatible
    // with OPC UA for Rust.

}

#[cfg(not(feature = "crypto"))]
fn main() {
    panic!("This tool doesn't work without crypto")
}
