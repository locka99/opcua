//! This module contains crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.

pub mod types;
pub mod certificate_store;
pub mod encrypt_decrypt;

pub use self::types::*;
pub use self::certificate_store::*;
pub use self::encrypt_decrypt::*;

// 128Rsa15
//
// A suite of algorithms that uses RSA15 as Key-Wrap-algorithm and 128-Bit for encryption algorithms.
//
// -> SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
// -> SymmetricEncryptionAlgorithm – Aes128 – (http://www.w3.org/2001/04/xmlenc#aes128-cbc).
// -> AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
// -> AsymmetricKeyWrapAlgorithm – KwRsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
// -> AsymmetricEncryptionAlgorithm – Rsa15 – (http://www.w3.org/2001/04/xmlenc#rsa-1_5).
// -> KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
// -> DerivedSignatureKeyLength – 128.
// -> MinAsymmetricKeyLength – 1024
// -> MaxAsymmetricKeyLength – 2048
// -> CertificateSignatureAlgorithm – Sha1
//
// If a certificate or any certificate in the chain is not signed with a hash that is Sha1 or stronger then the certificate shall be rejected.

// Security Basic 256
//
// A suite of algorithms that are for 256-Bit encryption, algorithms include:
//
// -> SymmetricSignatureAlgorithm – HmacSha1 – (http://www.w3.org/2000/09/xmldsig#hmac-sha1).
// -> SymmetricEncryptionAlgorithm – Aes256 – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
// -> AsymmetricSignatureAlgorithm – RsaSha1 – (http://www.w3.org/2000/09/xmldsig#rsa-sha1).
// -> AsymmetricKeyWrapAlgorithm – KwRsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p).
// -> AsymmetricEncryptionAlgorithm – RsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
// -> KeyDerivationAlgorithm – PSha1 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
// -> DerivedSignatureKeyLength – 192.
// -> MinAsymmetricKeyLength – 1024
// -> MaxAsymmetricKeyLength – 2048
// -> CertificateSignatureAlgorithm –
//
// Sha1 [deprecated] or Sha256 [recommended]
//
// If a certificate or any certificate in the chain is not signed with a hash that is Sha1 or stronger then the certificate shall be rejected.
// Release 1.03 17 OPC Unified Architecture, Part 7
// Both Sha1 and Sha256 shall be supported. However, it is recommended to use Sha256 since Sha1 is considered not secure anymore.

// Security Basic 256 Sha256
//
// A suite of algorithms that are for 256-Bit encryption, algorithms include.
//
// -> SymmetricSignatureAlgorithm – Hmac_Sha256 – (http://www.w3.org/2000/09/xmldsig#hmac-sha256).
// -> SymmetricEncryptionAlgorithm – Aes256_CBC – (http://www.w3.org/2001/04/xmlenc#aes256-cbc).
// -> AsymmetricSignatureAlgorithm – Rsa_Sha256 – (http://www.w3.org/2001/04/xmldsig#rsa-sha256).
// -> AsymmetricKeyWrapAlgorithm – KwRsaOaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p).
// -> AsymmetricEncryptionAlgorithm – Rsa_Oaep – (http://www.w3.org/2001/04/xmlenc#rsa-oaep).
// -> KeyDerivationAlgorithm – PSHA256 – (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256).
// -> DerivedSignatureKeyLength – 256
// -> MinAsymmetricKeyLength – 2048
// -> MaxAsymmetricKeyLength – 4096
// -> CertificateSignatureAlgorithm – Sha256
//
// If a certificate or any certificate in the chain is not signed with a hash that is Sha256 or stronger
// then the certificate shall be rejected. Support for this security profile may require support for
// a second application instance certificate, with a larger keysize. Applications shall support
// multiple Application Instance Certificates if required by supported Security Polices and use
// the certificate that is required for a given security endpoint.

