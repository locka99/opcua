#[cfg(feature = "crypto")]
extern crate openssl;

#[cfg(feature = "crypto")]
fn main() {
    use openssl::ssl::*;
    use openssl::x509::*;

    let mut builder: X509Builder = X509Builder::new().unwrap();

    /// use openssl::x509::{X509, X509NameBuilder};

    let mut issuer_name = X509NameBuilder::new().unwrap();
    // Common name
    issuer_name.append_entry_by_text("CN", "www.example.com").unwrap();
    // Organization
    issuer_name.append_entry_by_text("O", "Some organization").unwrap();
    // Organization Unit
    //..

    // Country
    issuer_name.append_entry_by_text("C", "US").unwrap();
    // State
    issuer_name.append_entry_by_text("ST", "CA").unwrap();
    let issuer_name = issuer_name.build();

    builder.set_issuer_name(&issuer_name);

    let cert = builder.build();
}

#[cfg(not(feature = "crypto"))]
fn main() {
    panic!("This tool doesn't work without crypto")
}
