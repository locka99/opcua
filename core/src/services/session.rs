use types::*;
use super::types::*;

// CreateSessionRequest = 459,
#[derive(Debug)]
pub struct CreateSessionRequest {
    /// Common request parameters. The authenticationToken is always omitted.
    pub request_header: RequestHeader,

    /// Information that describes the Client application.
    pub client_description: ApplicationDescription,

    /// This value is only specified if the EndpointDescription has a gatewayServerUri.
    /// This value is the applicationUri from the EndpointDescription 
    /// which is the applicationUri for the underlying Server.
    pub server_uri: UAString,

    /// The network address that the Client used to access the Session Endpoint.
    /// The HostName portion of the URL should be one of the HostNames for the application
    /// that are specified in the Server’s ApplicationInstanceCertificate (see 7.2).
    /// The Server shall raise an AuditUrlMismatchEventType event if the URL does not
    /// match the Server’s HostNames. AuditUrlMismatchEventType event type is defined
    /// in Part 5. The Server uses this information for diagnostics and to
    ///  determine the set of EndpointDescriptions to return in the response.
    pub endpoint_url: UAString,

    /// Human readable string that identifies the Session. The Server makes this
    /// name and the sessionId visible in its AddressSpace for diagnostic purposes.
    /// The Client should provide a name that is unique for the instance of the Client.
    /// If this parameter is not specified the Server shall assign a value.
    pub session_name: UAString,

    /// A random number that should never be used in any other request. This
    /// number shall have a minimum length of 32 bytes. Profiles may increase the
    /// required length. The Server shall use this value to prove possession of its
    /// Application Instance Certificate in the response.
    pub client_nonce: ByteString,

    /// The Application Instance Certificate issued to the Client. If the
    /// securityPolicyUri is None, the Server shall ignore the ApplicationInstanceCertificate.
    pub client_certificate: ByteString,

    /// Requested maximum number of milliseconds that a Session should remain open
    /// without activity. If the Client fails to issue a Service request within this
    /// interval, then the Server shall automatically terminate the Client Session.
    pub requested_session_timeout: Duration,

    /// The maximum size, in bytes, for the body of any response message.
    /// The Server should return a Bad_ResponseTooLarge service fault if a response
    /// message exceeds this limit. The value zero indicates that this parameter is not used.
    pub max_response_message_size: UInt32,
}

// CreateSessionResponse = 462,
#[derive(Debug)]
pub struct CreateSessionResponse {
    /// Common response parameters
    pub response_header: ResponseHeader,

    /// A unique NodeId assigned by the Server to the Session. This identifier is used
    /// to access the diagnostics information for the Session in the Server AddressSpace.
    /// It is also used in the audit logs and any events that report information related
    ///  to the Session.
    pub session_id: NodeId,

    /// A unique identifier assigned by the Server to the Session. This identifier shall
    /// be passed in the RequestHeader of each request and is used with the
    /// SecureChannelId to determine whether a Client has access to the Session.
    /// This identifier shall not be reused in a way that the Client or the Server has
    /// a chance of confusing them with a previous or existing Session.
    pub authentication_token: SessionAuthenticationToken,

    /// Actual maximum number of milliseconds that a Session shall remain open
    /// without activity. The Server should attempt to honour the Client request
    /// for this parameter, but may negotiate this value up or down to meet its
    /// own constraints.
    pub revised_session_timeout: Duration,

    /// A random number that should never be used in any other request.
    /// This number shall have a minimum length of 32 bytes.
    /// The Client shall use this value to prove possession of its Application
    /// Instance Certificate in the ActivateSession request.
    /// This value may also be used to prove possession of the userIdentityToken it
    /// specified in the ActivateSession request.
    pub server_nonce: ByteString,

    /// The Application Instance Certificate issued to the Server.
    /// A Server shall prove possession by using the private key to sign the Nonce
    /// provided by the Client in the request. The Client shall verify that this
    /// Certificate is the same as the one it used to create the SecureChannel.
    /// If the securityPolicyUri is NONE and none of the UserTokenPolicies requires
    /// encryption, the Client shall ignore the ApplicationInstanceCertificate.
    pub server_certificate: ByteString,

    /// List of Endpoints that the server supports.
    /// The Server shall return a set of EndpointDescriptions available for
    /// the serverUri specified in the request.
    /// The Client shall verify this list with the list from a Discovery Endpoint
    /// if it used a Discovery
    pub server_endpoints: Vec<EndpointDescription>,

    /// This parameter is deprecated and the array shall be empty.
    pub server_software_certificates: Vec<SignedSoftwareCertificate>,

    /// This is a signature generated with the private key associated with
    /// the serverCertificate. This parameter is calculated by appending the
    /// clientNonce to the clientCertificate and signing the resulting sequence of bytes.
    /// The SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm specified
    /// in the SecurityPolicy for the Endpoint.
    pub server_signature: SignatureData,

    /// The maximum size, in bytes, for the body of any request message.
    /// The Client Communication Stack should return a Bad_RequestTooLarge 
    /// error to the application if a request message exceeds this limit.
    /// The value zero indicates that this parameter is not used.
    pub max_request_message_size: UInt32,
}

#[derive(Debug)]
pub struct ActivateSessionRequest {
    /// Common request parameters. The authenticationToken is always omitted.
    pub request_header: RequestHeader,

    pub client_signature: SignatureData,

    pub client_software_certificates: Vec<SignedSoftwareCertificate>,

    pub user_identity_token: UserIdentityToken,

    pub user_token_signature: SignatureData,
}

#[derive(Debug)]
pub struct ActivateSessionResponse {
    /// Common response parameters
    pub response_header: ResponseHeader,

    pub server_nonce: ByteString,

    pub results: Vec<StatusCode>,

    pub diagnostic_infos: Vec<DiagnosticInfo>,
}

/*
Bad_IdentityTokenInvalid
See Table 172 for the description of this result code.
Bad_IdentityTokenRejected
See Table 172 for the description of this result code.
Bad_UserAccessDenied
See Table 172 for the description of this result code.
Bad_ApplicationSignatureInvalid
The signature provided by the client application is missing or invalid.
Bad_UserSignatureInvalid
The user token signature is missing or invalid.
Bad_NoValidCertificates
The Client did not provide at least one Software Certificate that is valid and meets the profile requirements for the Server.
Bad_IdentityChangeNotSupported
The Server does not support changing the user identity assigned to the session
*/

#[derive(Debug)]
pub struct CloseSessionRequest {
    /// Common request parameters. The authenticationToken is always omitted.
    pub request_header: RequestHeader,

    /// If the value is TRUE, the Server deletes all Subscriptions associated with the Session.
    /// If the value is FALSE, the Server keeps the Subscriptions associated with the Session until
    /// they timeout based on their own lifetime.
    pub delete_subscriptions: Boolean,
}

#[derive(Debug)]
pub struct CloseSessionResponse {
    /// Common response parameters
    pub response_header: ResponseHeader,
}
