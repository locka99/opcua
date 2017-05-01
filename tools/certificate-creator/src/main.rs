#[cfg(feature = "crypto")]
extern crate openssl;

#[cfg(feature = "crypto")]
fn main() {
    use openssl::ssl::*;
    use openssl::x509::*;
    use openssl::asn1::*;

    let common_name = "www.example.com";
    let organization = "Some organization";
    let organization_unit = "Unit name";

    let country = "US";
    let state = "CA";

    let cert = {
        let mut builder: X509Builder = X509Builder::new().unwrap();
        let issuer_name = {
            let mut issuer_name = X509NameBuilder::new().unwrap();
            // Common name
            issuer_name.append_entry_by_text("CN", common_name).unwrap();
            // Organization
            issuer_name.append_entry_by_text("O", organization).unwrap();
            // Organization Unit
            //.. organization_unit
            // Country
            issuer_name.append_entry_by_text("C", country).unwrap();
            // State
            issuer_name.append_entry_by_text("ST", state).unwrap();
            issuer_name.build()
        };
        builder.set_issuer_name(&issuer_name);
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.build()
    };
}

#[cfg(not(feature = "crypto"))]
fn main() {
    panic!("This tool doesn't work without crypto")
}
