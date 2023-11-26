// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Functions related to encrypting / decrypting passwords in a UserNameIdentityToken.
//!
//! The code here determines how or if to encrypt the password depending on the security policy
//! and user token policy.

use std::io::{Cursor, Write};
use std::str::FromStr;

use crate::types::{
    encoding::{read_u32, write_u32},
    service_types::{SignatureData, UserNameIdentityToken, UserTokenPolicy, X509IdentityToken},
    status_code::StatusCode,
    ByteString, UAString,
};

use super::{KeySize, PrivateKey, RsaPadding, SecurityPolicy, X509};

/// Create a filled in UserNameIdentityToken by using the supplied channel security policy, user token policy, nonce, cert, user name and password.
pub fn make_user_name_identity_token(
    channel_security_policy: SecurityPolicy,
    user_token_policy: &UserTokenPolicy,
    nonce: &[u8],
    cert: &Option<X509>,
    user: &str,
    pass: &str,
) -> Result<UserNameIdentityToken, StatusCode> {
    // This is a condensed version of Table 187 Opc Part 4 that details the EncryptionAlgorithm
    // selection.
    //
    // This is mostly along the lines of: The UserTokenPolicy.SecurityPolicy takes precedence over the
    // SecureChannel.SecurityPolicy, except there's a distinction between the cases when
    // UserTokenPolicy.SecurityPolicy is null/empty and explicitly set to SecurityPolicy::None. In
    // the first case, the SecureChannel.SecurityPolicy is to be used, and in the latter case the
    // policy is explicitly set to None.
    //
    let security_policy = if user_token_policy.security_policy_uri.is_empty() {
        // If no SecurityPolicy is explicitly set for UserIdentityToken, use the one defined in
        // SecureChannel.
        channel_security_policy
    } else {
        let security_policy =
            SecurityPolicy::from_str(user_token_policy.security_policy_uri.as_ref()).unwrap();
        if security_policy == SecurityPolicy::Unknown {
            SecurityPolicy::None
        } else {
            security_policy
        }
    };

    // Now it should be a matter of using the policy (or lack thereof) to encrypt the password
    // using the secure channel's cert and nonce.
    let (password, encryption_algorithm) = match security_policy {
        SecurityPolicy::None => {
            // Plain text
            if channel_security_policy == SecurityPolicy::None {
                warn!("A user identity's password is being sent over the network in plain text. This could be a serious security issue");
            }
            (ByteString::from(pass.as_bytes()), UAString::null())
        }
        SecurityPolicy::Unknown => {
            // This should only happen if channel_security_policy were Unknown when it shouldn't be
            panic!("Don't know how to make the token for this server");
        }
        security_policy => {
            // Create a password which is encrypted using the secure channel info and the user token policy for the endpoint
            let password = legacy_password_encrypt(
                pass,
                nonce,
                cert.as_ref().unwrap(),
                security_policy.asymmetric_encryption_padding(),
            )?;
            let encryption_algorithm =
                UAString::from(security_policy.asymmetric_encryption_algorithm());
            (password, encryption_algorithm)
        }
    };

    Ok(UserNameIdentityToken {
        policy_id: user_token_policy.policy_id.clone(),
        user_name: UAString::from(user),
        password,
        encryption_algorithm,
    })
}

/// Decrypt the password inside of a user identity token.
pub fn decrypt_user_identity_token_password(
    user_identity_token: &UserNameIdentityToken,
    server_nonce: &[u8],
    server_key: &PrivateKey,
) -> Result<String, StatusCode> {
    if user_identity_token.encryption_algorithm.is_empty() {
        // Assumed to be UTF-8 plain text
        user_identity_token.plaintext_password()
    } else {
        // Determine the padding from the algorithm.
        let encryption_algorithm = user_identity_token.encryption_algorithm.as_ref();
        let padding = match encryption_algorithm {
            super::algorithms::ENC_RSA_15 => RsaPadding::Pkcs1,
            super::algorithms::ENC_RSA_OAEP => RsaPadding::OaepSha1,
            super::algorithms::ENC_RSA_OAEP_SHA256 => RsaPadding::OaepSha256,
            _ => {
                error!("decrypt_user_identity_token_password has rejected unsupported user identity encryption algorithm \"{}\"", encryption_algorithm);
                return Err(StatusCode::BadIdentityTokenInvalid);
            }
        };
        legacy_password_decrypt(
            &user_identity_token.password,
            server_nonce,
            server_key,
            padding,
        )
    }
}

/// Encrypt a client side user's password using the server nonce and cert. This is described in table 176
/// OPC UA part 4. This function is prefixed "legacy" because 1.04 describes another way of encrypting passwords.
pub fn legacy_password_encrypt(
    password: &str,
    server_nonce: &[u8],
    server_cert: &X509,
    padding: RsaPadding,
) -> Result<ByteString, StatusCode> {
    // Message format is size, password, nonce
    let plaintext_size = 4 + password.len() + server_nonce.len();
    let mut src = Cursor::new(vec![0u8; plaintext_size]);

    // Write the length of the data to be encrypted excluding the length itself)
    write_u32(&mut src, (plaintext_size - 4) as u32)?;
    src.write(password.as_bytes())
        .map_err(|_| StatusCode::BadEncodingError)?;
    src.write(server_nonce)
        .map_err(|_| StatusCode::BadEncodingError)?;

    // Encrypt the data with the public key from the server's certificate
    let public_key = server_cert.public_key()?;

    let cipher_size = public_key.calculate_cipher_text_size(plaintext_size, padding);
    let mut dst = vec![0u8; cipher_size];
    let actual_size = public_key
        .public_encrypt(&src.into_inner(), &mut dst, padding)
        .map_err(|_| StatusCode::BadEncodingError)?;

    assert_eq!(actual_size, cipher_size);

    Ok(ByteString::from(dst))
}

/// Decrypt the client's password using the server's nonce and private key. This function is prefixed
/// "legacy" because 1.04 describes another way of encrypting passwords.
pub fn legacy_password_decrypt(
    secret: &ByteString,
    server_nonce: &[u8],
    server_key: &PrivateKey,
    padding: RsaPadding,
) -> Result<String, StatusCode> {
    if secret.is_null() {
        Err(StatusCode::BadDecodingError)
    } else {
        // Decrypt the message
        let src = secret.value.as_ref().unwrap();
        let mut dst = vec![0u8; src.len()];
        let actual_size = server_key
            .private_decrypt(src, &mut dst, padding)
            .map_err(|_| StatusCode::BadEncodingError)?;

        let mut dst = Cursor::new(dst);
        let plaintext_size = read_u32(&mut dst)? as usize;
        if plaintext_size + 4 != actual_size {
            Err(StatusCode::BadDecodingError)
        } else {
            let dst = dst.into_inner();
            let nonce_len = server_nonce.len();
            let nonce_begin = actual_size - nonce_len;
            let nonce = &dst[nonce_begin..(nonce_begin + nonce_len)];
            if nonce != server_nonce {
                Err(StatusCode::BadDecodingError)
            } else {
                let password = &dst[4..nonce_begin];
                let password = String::from_utf8(password.to_vec())
                    .map_err(|_| StatusCode::BadEncodingError)?;
                Ok(password)
            }
        }
    }
}

/// Verify that the X509 identity token supplied to a server contains a valid signature.
pub fn verify_x509_identity_token(
    token: &X509IdentityToken,
    user_token_signature: &SignatureData,
    security_policy: SecurityPolicy,
    server_cert: &X509,
    server_nonce: &[u8],
) -> Result<(), StatusCode> {
    // Since it is not obvious at all from the spec what the user token signature is supposed to be, I looked
    // at the internet for clues:
    //
    // https://stackoverflow.com/questions/46683342/securing-opensecurechannel-messages-and-x509identitytoken
    // https://forum.prosysopc.com/forum/opc-ua/clarification-on-opensecurechannel-messages-and-x509identitytoken-specifications/
    //
    // These suggest that the signature is produced by appending the server nonce to the server certificate
    // and signing with the user certificate's private key.
    //
    // This is the same as the standard handshake between client and server but using the identity cert. It would have been nice
    // if the spec actually said this.

    let signing_cert = super::x509::X509::from_byte_string(&token.certificate_data)?;
    let result = super::verify_signature_data(
        user_token_signature,
        security_policy,
        &signing_cert,
        server_cert,
        server_nonce,
    );
    if result.is_good() {
        Ok(())
    } else {
        Err(result)
    }
}
