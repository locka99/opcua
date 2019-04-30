//! Functions related to encrypting / decrypting passwords in a UserNameIdentityToken.
//!
//! The code here determines how or if to encrypt the password depending on the security policy
//! and user token policy.

use std::io::{Cursor, Write};
use std::str::FromStr;

use opcua_types::{
    UAString, ByteString,
    status_code::StatusCode,
    encoding::{write_u32, read_u32},
    service_types::{UserTokenPolicy, UserNameIdentityToken},
};

use super::{X509, PrivateKey, KeySize, SecurityPolicy, RsaPadding};

/// Create a filled in UserNameIdentityToken by using the supplied channel security policy, user token policy, nonce, cert, user name and password.
pub fn make_user_name_identity_token(channel_security_policy: SecurityPolicy, user_token_policy: &UserTokenPolicy, nonce: &[u8], cert: Option<X509>, user: &str, pass: &str) -> Result<UserNameIdentityToken, StatusCode> {
    // Create a user token security policy by looking at the uri it wants to use
    let token_security_policy = if user_token_policy.security_policy_uri.is_empty() {
        SecurityPolicy::None
    } else {
        let security_policy = SecurityPolicy::from_str(user_token_policy.security_policy_uri.as_ref()).unwrap();
        if security_policy != SecurityPolicy::Unknown {
            security_policy
        } else {
            SecurityPolicy::None
        }
    };

    // Table 179 Opc Part 4 provides a table of which encryption algorithm to use
    let security_policy = if channel_security_policy == SecurityPolicy::None {
        if user_token_policy.security_policy_uri.is_empty() {
            SecurityPolicy::None
        } else if token_security_policy != SecurityPolicy::None {
            SecurityPolicy::None
        } else {
            token_security_policy
        }
    } else {
        if user_token_policy.security_policy_uri.is_empty() {
            channel_security_policy
        } else if token_security_policy != SecurityPolicy::None && channel_security_policy != token_security_policy {
            token_security_policy
        } else if channel_security_policy == token_security_policy {
            token_security_policy
        } else if token_security_policy == SecurityPolicy::None {
            SecurityPolicy::None
        } else {
            SecurityPolicy::None
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
            let password = legacy_password_encrypt(pass, nonce, &cert.unwrap(), security_policy.padding())?;
            let encryption_algorithm = UAString::from(security_policy.asymmetric_encryption_algorithm());
            (password, encryption_algorithm)
        }
    };

    Ok(UserNameIdentityToken {
        policy_id: user_token_policy.policy_id.clone(),
        user_name: UAString::from(user.as_ref()),
        password,
        encryption_algorithm,
    })
}

/// Decrypt the password inside of a user identity token.
pub fn decrypt_user_identity_token_password(user_identity_token: &UserNameIdentityToken, server_nonce: &[u8], server_key: &PrivateKey) -> Result<String, StatusCode> {
    if user_identity_token.encryption_algorithm.is_empty() {
        // Assumed to be UTF-8 plain text
        user_identity_token.plaintext_password()
    } else {
        // Determine the padding from the algorithm.
        let padding = match user_identity_token.encryption_algorithm.as_ref() {
            super::algorithms::ENC_RSA_15 => RsaPadding::PKCS1,
            super::algorithms::ENC_RSA_OAEP => RsaPadding::OAEP,
            _ => { return Err(StatusCode::BadSecurityPolicyRejected); }
        };
        legacy_password_decrypt(&user_identity_token.password, server_nonce, server_key, padding)
    }
}

/// Encrypt a client side user's password using the server nonce and cert. This is described in table 176
/// OPC UA part 4. This function is prefixed "legacy" because 1.04 describes another way of encrypting passwords.
pub fn legacy_password_encrypt(password: &str, server_nonce: &[u8], server_cert: &X509, padding: RsaPadding) -> Result<ByteString, StatusCode> {
    // Message format is size, password, nonce
    let plaintext_size = 4 + password.len() + server_nonce.len();
    let mut src = Cursor::new(vec![0u8; plaintext_size]);

    // Write the length of the data to be encrypted excluding the length itself)
    write_u32(&mut src, (plaintext_size - 4) as u32)?;
    src.write(password.as_bytes()).map_err(|_| StatusCode::BadEncodingError)?;
    src.write(server_nonce).map_err(|_| StatusCode::BadEncodingError)?;

    // Encrypt the data with the public key from the server's certificate
    let public_key = server_cert.public_key()?;

    let cipher_size = public_key.calculate_cipher_text_size(plaintext_size, padding);
    let mut dst = vec![0u8; cipher_size];
    let actual_size = public_key.public_encrypt(&src.into_inner(), &mut dst, padding).map_err(|_| StatusCode::BadEncodingError)?;

    assert_eq!(actual_size, cipher_size);

    Ok(ByteString::from(dst))
}

/// Decrypt the client's password using the server's nonce and private key. This function is prefixed
/// "legacy" because 1.04 describes another way of encrypting passwords.
pub fn legacy_password_decrypt(secret: &ByteString, server_nonce: &[u8], server_key: &PrivateKey, padding: RsaPadding) -> Result<String, StatusCode> {
    if secret.is_null() {
        Err(StatusCode::BadDecodingError)
    } else {
        // Decrypt the message
        let src = secret.value.as_ref().unwrap();
        let mut dst = vec![0u8; src.len()];
        let actual_size = server_key.private_decrypt(&src, &mut dst, padding).map_err(|_| StatusCode::BadEncodingError)?;

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
