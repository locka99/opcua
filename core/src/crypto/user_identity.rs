use std::io::{Cursor, Write};

use opcua_types::{
    ByteString, status_code::StatusCode, encoding::{write_u32, read_u32},
};

use super::{X509, PrivateKey, KeySize};
use crate::crypto::RsaPadding;

/// Encrypt a client side user's password using the server nonce and cert. This function is prefixed
/// "legacy" because 1.04 describes another way of encrypting passwords.
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
pub fn legacy_password_decrypt(secret: ByteString, server_nonce: &[u8], server_key: &PrivateKey, padding: RsaPadding) -> Result<String, StatusCode> {
    if secret.is_null() {
        Err(StatusCode::BadDecodingError)
    } else {
        // Decrypt the message
        let src = secret.value.unwrap();
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
