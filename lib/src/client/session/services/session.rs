use std::sync::Arc;

use crypto::{certificate_store::CertificateStore, user_identity::make_user_name_identity_token};

use crate::{
    client::{
        session::{process_service_result, process_unexpected_response},
        IdentityToken, Session,
    },
    core::{
        comms::{secure_channel::SecureChannel, url::hostname_from_url},
        supported_message::SupportedMessage,
    },
    crypto::{self, SecurityPolicy},
    types::{
        ActivateSessionRequest, AnonymousIdentityToken, ByteString, CancelRequest,
        CloseSessionRequest, CreateSessionRequest, ExtensionObject, IntegerId, NodeId, ObjectId,
        SignatureData, StatusCode, UAString, UserNameIdentityToken, UserTokenPolicy, UserTokenType,
        X509IdentityToken,
    },
};

impl Session {
    /// Sends a [`CreateSessionRequest`] to the server, returning the session id of the created
    /// session. Internally, the session will store the authentication token which is used for requests
    /// subsequent to this call.
    ///
    /// See OPC UA Part 4 - Services 5.6.2 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(NodeId)` - Success, session id
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub(crate) async fn create_session(&self) -> Result<NodeId, StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();

        let client_nonce = self.channel.client_nonce();
        let server_uri = UAString::null();
        let session_name = self.session_name.clone();

        let (client_certificate, _) = {
            let certificate_store = trace_write_lock!(self.certificate_store);
            certificate_store.read_own_cert_and_pkey_optional()
        };

        let client_certificate = if let Some(ref client_certificate) = client_certificate {
            client_certificate.as_byte_string()
        } else {
            ByteString::null()
        };

        let request = CreateSessionRequest {
            request_header: self.make_request_header(),
            client_description: self.application_description.clone(),
            server_uri,
            endpoint_url,
            session_name,
            client_nonce,
            client_certificate,
            requested_session_timeout: self.session_timeout,
            max_response_message_size: 0,
        };

        let response = self.send(request).await?;

        if let SupportedMessage::CreateSessionResponse(response) = response {
            process_service_result(&response.response_header)?;

            let session_id = {
                self.session_id.store(Arc::new(response.session_id.clone()));
                response.session_id.clone()
            };
            self.auth_token
                .store(Arc::new(response.authentication_token));

            self.channel.update_from_created_session(
                &response.server_nonce,
                &response.server_certificate,
            )?;

            let security_policy = self.channel.security_policy();

            if security_policy != SecurityPolicy::None {
                if let Ok(server_certificate) =
                    crypto::X509::from_byte_string(&response.server_certificate)
                {
                    // Validate server certificate against hostname and application_uri
                    let hostname =
                        hostname_from_url(self.session_info.endpoint.endpoint_url.as_ref())
                            .map_err(|_| StatusCode::BadUnexpectedError)?;
                    let application_uri =
                        self.session_info.endpoint.server.application_uri.as_ref();

                    let certificate_store = trace_write_lock!(self.certificate_store);
                    let result = certificate_store.validate_or_reject_application_instance_cert(
                        &server_certificate,
                        security_policy,
                        Some(&hostname),
                        Some(application_uri),
                    );
                    if result.is_bad() {
                        return Err(result);
                    }
                } else {
                    return Err(StatusCode::BadCertificateInvalid);
                }
            }

            Ok(session_id)
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Sends an [`ActivateSessionRequest`] to the server to activate this session
    ///
    /// See OPC UA Part 4 - Services 5.6.3 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub(crate) async fn activate_session(&self) -> Result<(), StatusCode> {
        // Do this in a block to release the lock before awaiting any async calls.
        let (server_cert, server_nonce, user_identity_token, user_token_signature) = {
            let secure_channel = trace_read_lock!(self.channel.secure_channel);

            let (user_identity_token, user_token_signature) =
                self.user_identity_token(&secure_channel)?;

            let server_cert = secure_channel.remote_cert();
            let server_nonce = secure_channel.remote_nonce_as_byte_string();

            (
                server_cert,
                server_nonce,
                user_identity_token,
                user_token_signature,
            )
        };

        let locale_ids = if self.session_info.preferred_locales.is_empty() {
            None
        } else {
            let locale_ids = self
                .session_info
                .preferred_locales
                .iter()
                .map(UAString::from)
                .collect();
            Some(locale_ids)
        };

        let security_policy = self.channel.security_policy();
        let client_signature = match security_policy {
            SecurityPolicy::None => SignatureData::null(),
            _ => {
                let (_, client_pkey) = {
                    let certificate_store = trace_write_lock!(self.certificate_store);
                    certificate_store.read_own_cert_and_pkey_optional()
                };

                // Create a signature data
                if client_pkey.is_none() {
                    error!("Cannot create client signature - no pkey!");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_cert.is_none() {
                    error!("Cannot sign server certificate because server cert is null");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_nonce.is_empty() {
                    error!("Cannot sign server certificate because server nonce is empty");
                    return Err(StatusCode::BadUnexpectedError);
                }

                let server_cert = server_cert.unwrap().as_byte_string();
                let signing_key = client_pkey.as_ref().unwrap();
                crypto::create_signature_data(
                    signing_key,
                    security_policy,
                    &server_cert,
                    &server_nonce,
                )?
            }
        };

        let request = ActivateSessionRequest {
            request_header: self.make_request_header(),
            client_signature,
            client_software_certificates: None,
            locale_ids,
            user_identity_token,
            user_token_signature,
        };

        let response = self.send(request).await?;

        if let SupportedMessage::ActivateSessionResponse(response) = response {
            // trace!("ActivateSessionResponse = {:#?}", response);
            process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Create a user identity token from config and the secure channel.
    fn user_identity_token(
        &self,
        channel: &SecureChannel,
    ) -> Result<(ExtensionObject, SignatureData), StatusCode> {
        let server_cert = &channel.remote_cert();
        let server_nonce = &channel.remote_nonce();

        let user_identity_token = &self.session_info.user_identity_token;
        let user_token_type = match user_identity_token {
            IdentityToken::Anonymous => UserTokenType::Anonymous,
            IdentityToken::UserName(_, _) => UserTokenType::UserName,
            IdentityToken::X509(_, _) => UserTokenType::Certificate,
        };

        let endpoint = &self.session_info.endpoint;
        let policy = endpoint.find_policy(user_token_type);

        match policy {
            None => {
                error!(
                    "Cannot find user token type {:?} for this endpoint, cannot connect",
                    user_token_type
                );
                Err(StatusCode::BadSecurityPolicyRejected)
            }
            Some(policy) => {
                let security_policy = if policy.security_policy_uri.is_null() {
                    // Assume None
                    SecurityPolicy::None
                } else {
                    SecurityPolicy::from_uri(policy.security_policy_uri.as_ref())
                };

                if security_policy == SecurityPolicy::Unknown {
                    error!("Unknown security policy {}", policy.security_policy_uri);
                    return Err(StatusCode::BadSecurityPolicyRejected);
                }

                match &user_identity_token {
                    IdentityToken::Anonymous => {
                        let identity_token = AnonymousIdentityToken {
                            policy_id: policy.policy_id.clone(),
                        };
                        let identity_token = ExtensionObject::from_encodable(
                            ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary,
                            &identity_token,
                        );
                        Ok((identity_token, SignatureData::null()))
                    }
                    IdentityToken::UserName(user, pass) => {
                        let identity_token =
                            self.make_user_name_identity_token(channel, policy, user, pass)?;
                        let identity_token = ExtensionObject::from_encodable(
                            ObjectId::UserNameIdentityToken_Encoding_DefaultBinary,
                            &identity_token,
                        );
                        Ok((identity_token, SignatureData::null()))
                    }
                    IdentityToken::X509(cert_path, private_key_path) => {
                        let Some(server_cert) = &server_cert else {
                            error!("Cannot create an X509IdentityToken because the remote server has no cert with which to create a signature");
                            return Err(StatusCode::BadCertificateInvalid);
                        };
                        let certificate_data =
                            CertificateStore::read_cert(cert_path).map_err(|e| {
                                error!(
                                    "Certificate cannot be loaded from path {}, error = {}",
                                    cert_path.to_str().unwrap(),
                                    e
                                );
                                StatusCode::BadSecurityPolicyRejected
                            })?;
                        let private_key =
                            CertificateStore::read_pkey(private_key_path).map_err(|e| {
                                error!(
                                    "Private key cannot be loaded from path {}, error = {}",
                                    private_key_path.to_str().unwrap(),
                                    e
                                );
                                StatusCode::BadSecurityPolicyRejected
                            })?;
                        let user_token_signature = crypto::create_signature_data(
                            &private_key,
                            security_policy,
                            &server_cert.as_byte_string(),
                            &ByteString::from(server_nonce),
                        )?;

                        // Create identity token
                        let identity_token = X509IdentityToken {
                            policy_id: policy.policy_id.clone(),
                            certificate_data: certificate_data.as_byte_string(),
                        };
                        let identity_token = ExtensionObject::from_encodable(
                            ObjectId::X509IdentityToken_Encoding_DefaultBinary,
                            &identity_token,
                        );

                        Ok((identity_token, user_token_signature))
                    }
                }
            }
        }
    }

    /// Create a user name identity token.
    fn make_user_name_identity_token(
        &self,
        secure_channel: &SecureChannel,
        user_token_policy: &UserTokenPolicy,
        user: &str,
        pass: &str,
    ) -> Result<UserNameIdentityToken, StatusCode> {
        let channel_security_policy = secure_channel.security_policy();
        let nonce = secure_channel.remote_nonce();
        let cert = secure_channel.remote_cert();
        make_user_name_identity_token(
            channel_security_policy,
            user_token_policy,
            nonce,
            &cert,
            user,
            pass,
        )
    }

    /// Close the session by sending a [`CloseSessionRequest`] to the server.
    ///
    /// This is not accessible by users, they must instead call `disconnect` to properly close the session.
    pub(crate) async fn close_session(&self) -> Result<(), StatusCode> {
        let request = CloseSessionRequest {
            delete_subscriptions: true,
            request_header: self.make_request_header(),
        };
        let response = self.send(request).await?;
        if let SupportedMessage::CloseSessionResponse(_) = response {
            Ok(())
        } else {
            error!("close_session failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }

    /// Cancels an outstanding service request by sending a [`CancelRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.6.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `request_handle` - Handle to the outstanding request to be cancelled.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - Success, number of cancelled requests
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn cancel(&self, request_handle: IntegerId) -> Result<u32, StatusCode> {
        let request = CancelRequest {
            request_header: self.make_request_header(),
            request_handle,
        };
        let response = self.send(request).await?;
        if let SupportedMessage::CancelResponse(response) = response {
            process_service_result(&response.response_header)?;
            Ok(response.cancel_count)
        } else {
            Err(process_unexpected_response(response))
        }
    }
}
