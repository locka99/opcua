use std::str::FromStr;

use crate::SecurityPolicy;

#[test]
fn is_deprecated() {
    // Deprecated
    assert!(SecurityPolicy::Basic256.is_deprecated());
    assert!(SecurityPolicy::Basic128Rsa15.is_deprecated());
    // Not deprecated
    assert!(!SecurityPolicy::None.is_deprecated());
    assert!(!SecurityPolicy::Basic256Sha256.is_deprecated());
    assert!(!SecurityPolicy::Aes128Sha256RsaOaep.is_deprecated());
    assert!(!SecurityPolicy::Aes256Sha256RsaPss.is_deprecated());
}

#[test]
fn from_str() {
    // Invalid from_str
    assert_eq!(
        SecurityPolicy::from_str("").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str("none").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str(" None").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str("Basic256 ").unwrap(),
        SecurityPolicy::Unknown
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#").unwrap(),
        SecurityPolicy::Unknown
    );

    // Valid from str will take either the short name or the URI
    assert_eq!(
        SecurityPolicy::from_str("None").unwrap(),
        SecurityPolicy::None
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#None").unwrap(),
        SecurityPolicy::None
    );
    assert_eq!(
        SecurityPolicy::from_str("Basic128Rsa15").unwrap(),
        SecurityPolicy::Basic128Rsa15
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15")
            .unwrap(),
        SecurityPolicy::Basic128Rsa15
    );
    assert_eq!(
        SecurityPolicy::from_str("Basic256").unwrap(),
        SecurityPolicy::Basic256
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Basic256").unwrap(),
        SecurityPolicy::Basic256
    );
    assert_eq!(
        SecurityPolicy::from_str("Basic256Sha256").unwrap(),
        SecurityPolicy::Basic256Sha256
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
            .unwrap(),
        SecurityPolicy::Basic256Sha256
    );
    assert_eq!(
        SecurityPolicy::from_str("Aes128-Sha256-RsaOaep").unwrap(),
        SecurityPolicy::Aes128Sha256RsaOaep
    );
    assert_eq!(
        SecurityPolicy::from_str(
            "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
        )
        .unwrap(),
        SecurityPolicy::Aes128Sha256RsaOaep
    );
    assert_eq!(
        SecurityPolicy::from_str("Aes256-Sha256-RsaPss").unwrap(),
        SecurityPolicy::Aes256Sha256RsaPss
    );
    assert_eq!(
        SecurityPolicy::from_str("http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss")
            .unwrap(),
        SecurityPolicy::Aes256Sha256RsaPss
    );
}

#[test]
fn to_uri() {
    assert_eq!(
        SecurityPolicy::None.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#None"
    );
    assert_eq!(
        SecurityPolicy::Basic128Rsa15.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    );
    assert_eq!(
        SecurityPolicy::Basic256.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
    );
    assert_eq!(
        SecurityPolicy::Basic256Sha256.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    );
    assert_eq!(
        SecurityPolicy::Aes128Sha256RsaOaep.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
    );
    assert_eq!(
        SecurityPolicy::Aes256Sha256RsaPss.to_uri(),
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    );
}

#[test]
fn is_valid_keylength() {
    assert!(SecurityPolicy::Basic128Rsa15.is_valid_keylength(1024));
    assert!(SecurityPolicy::Basic128Rsa15.is_valid_keylength(2048));
    assert!(!SecurityPolicy::Basic128Rsa15.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Basic128Rsa15.is_valid_keylength(512));

    assert!(SecurityPolicy::Basic256.is_valid_keylength(1024));
    assert!(SecurityPolicy::Basic256.is_valid_keylength(2048));
    assert!(!SecurityPolicy::Basic256.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Basic256.is_valid_keylength(512));

    assert!(SecurityPolicy::Basic256Sha256.is_valid_keylength(2048));
    assert!(SecurityPolicy::Basic256Sha256.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Basic256Sha256.is_valid_keylength(1024));
    assert!(!SecurityPolicy::Basic256Sha256.is_valid_keylength(8192));

    assert!(SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(2048));
    assert!(SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(1024));
    assert!(!SecurityPolicy::Aes128Sha256RsaOaep.is_valid_keylength(8192));

    assert!(SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(2048));
    assert!(SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(4096));
    assert!(!SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(1024));
    assert!(!SecurityPolicy::Aes256Sha256RsaPss.is_valid_keylength(8192));
}
