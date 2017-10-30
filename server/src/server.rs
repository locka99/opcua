//! The server module defines types related to the server, it's current running state
//! and end point information.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::thread;

use opcua_types::*;
use opcua_types::profiles;

use opcua_core::prelude::*;
use opcua_core::config::Config;

use constants;
use address_space::types::AddressSpace;
use comms::tcp_transport::*;
use config::{ServerEndpoint, ServerConfig};
use util::PollingAction;

#[derive(Clone)]
/// Structure that captures diagnostics information for the server
pub struct ServerDiagnostics {}

impl ServerDiagnostics {
    pub fn new() -> ServerDiagnostics {
        ServerDiagnostics {}
    }
}

/// Server state is any state associated with the server as a whole that individual sessions might
/// be interested in. That includes configuration info, address space etc.
pub struct ServerState {
    /// The application URI
    pub application_uri: UAString,
    /// The product URI
    pub product_uri: UAString,
    /// The application name
    pub application_name: LocalizedText,
    /// The protocol, hostname and port formatted as a url, but less the path
    pub base_endpoint: String,
    /// The time the server started
    pub start_time: DateTime,
    /// The list of namespaces
    pub namespaces: Vec<String>,
    /// The list of servers (by urn)
    pub servers: Vec<String>,
    /// Server configuration
    pub config: Arc<Mutex<ServerConfig>>,
    /// Certificate store for certs
    pub certificate_store: Arc<Mutex<CertificateStore>>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: Option<X509>,
    /// Server private key pair
    pub server_pkey: Option<PKey>,
    /// The address space
    pub address_space: Arc<Mutex<AddressSpace>>,
    /// The next subscription id - subscriptions are shared across the whole server. Initial value
    /// is a random u32.
    pub last_subscription_id: UInt32,
    /// Maximum number of subscriptions per session, 0 means no limit (danger)
    pub max_subscriptions: usize,
    /// Minimum publishing interval
    pub min_publishing_interval: Duration,
    /// Maxmimum keep alive count
    pub max_keep_alive_count: UInt32,
    /// Sets the abort flag that terminates the associated server
    pub abort: bool,
    /// Diagnostic information
    pub diagnostics: ServerDiagnostics,
}

impl ServerState {
    pub fn endpoints(&self, transport_profile_uris: Option<Vec<UAString>>) -> Option<Vec<EndpointDescription>> {
        // Filter endpoints based on profile_uris
        debug!("Endpoints requested {:?}", transport_profile_uris);
        if let Some(transport_profile_uris) = transport_profile_uris {
            if !transport_profile_uris.is_empty() {
                // As we only support binary transport, the result is None if the supplied profile_uris does not contain that profile
                let found_binary_transport = transport_profile_uris.iter().find(|profile_uri| {
                    profile_uri.as_ref() == profiles::TRANSPORT_PROFILE_URI_BINARY
                });
                if found_binary_transport.is_none() {
                    error!("Client wants to connect with a non binary transport {:#?}", transport_profile_uris);
                    return None;
                }
            }
        }
        // Return the endpoints
        let config = self.config.lock().unwrap();
        Some(config.endpoints.iter().map(|(_, e)| self.new_endpoint_description(&config, e, true)).collect())
    }

    pub fn endpoint_exists(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> bool {
        self.find_endpoint(endpoint_url, security_policy, security_mode).is_some()
    }

    /// Find a single endpoint that matches the specified url, security policy and message security mode
    pub fn find_endpoint(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> Option<ServerEndpoint> {
        let config = self.config.lock().unwrap();
        let base_endpoint_url = config.base_endpoint_url();
        let endpoint = config.endpoints.iter().find(|&(_, e)| {
            // Test end point's security_policy_uri and matching url
            if let Ok(_) = url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url) {
                if e.security_policy() == security_policy && e.message_security_mode() == security_mode {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        });
        if endpoint.is_some() {
            Some(endpoint.unwrap().1.clone())
        } else {
            None
        }
    }

    /// Make matching endpoint descriptions for the specified url.
    /// If none match then None will be passed, therefore if Some is returned it will be guaranteed
    /// to contain at least one result.
    pub fn new_endpoint_descriptions(&self, endpoint_url: &str) -> Option<Vec<EndpointDescription>> {
        debug!("find_endpoint, url = {}", endpoint_url);
        let config = self.config.lock().unwrap();
        let base_endpoint_url = config.base_endpoint_url();
        let endpoints: Vec<EndpointDescription> = config.endpoints.iter().filter(|&(_, e)| {
            // Test end point's security_policy_uri and matching url
            if let Ok(result) = url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url) {
                result
            } else {
                false
            }
        }).map(|(_, e)| self.new_endpoint_description(&config, e, false)).collect();
        if endpoints.is_empty() { None } else { Some(endpoints) }
    }

    /// Constructs a new endpoint description using the server's info and that in an Endpoint
    fn new_endpoint_description(&self, config: &ServerConfig, endpoint: &ServerEndpoint, all_fields: bool) -> EndpointDescription {
        let base_endpoint_url = config.base_endpoint_url();

        let mut user_identity_tokens = Vec::with_capacity(2);
        if endpoint.supports_anonymous() {
            user_identity_tokens.push(UserTokenPolicy::new_anonymous());
        }
        if !endpoint.user_token_ids.is_empty() {
            user_identity_tokens.push(UserTokenPolicy::new_user_pass());
        }

        // CreateSession doesn't need all the endpoint description
        // and docs say not to bother sending the server and server
        // certificate info.
        let (server, server_certificate) = if all_fields {
            (ApplicationDescription {
                application_uri: self.application_uri.clone(),
                product_uri: self.product_uri.clone(),
                application_name: self.application_name.clone(),
                application_type: ApplicationType::Server,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            }, self.server_certificate_as_byte_string())
        } else {
            (ApplicationDescription {
                application_uri: UAString::null(),
                product_uri: UAString::null(),
                application_name: LocalizedText::null(),
                application_type: ApplicationType::Server,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            }, ByteString::null())
        };

        EndpointDescription {
            endpoint_url: endpoint.endpoint_url(&base_endpoint_url).into(),
            server,
            server_certificate,
            security_mode: endpoint.message_security_mode(),
            security_policy_uri: UAString::from(endpoint.security_policy().to_uri()),
            user_identity_tokens: Some(user_identity_tokens),
            transport_profile_uri: UAString::from(profiles::TRANSPORT_PROFILE_URI_BINARY),
            security_level: 1,
        }
    }

    pub fn server_certificate_as_byte_string(&self) -> ByteString {
        if self.server_certificate.is_some() {
            self.server_certificate.as_ref().unwrap().as_byte_string()
        } else {
            ByteString::null()
        }
    }

    pub fn create_subscription_id(&mut self) -> UInt32 {
        self.last_subscription_id += 1;
        self.last_subscription_id
    }

    pub fn authenticate_endpoint(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode, user_identity_token: &ExtensionObject) -> StatusCode {
        // Get security from endpoint url
        if let Some(endpoint) = self.find_endpoint(endpoint_url, security_policy, security_mode) {
            // Now validate the user identity token
            if user_identity_token.is_null() || user_identity_token.is_empty() {
                // Empty tokens are treated as anonymous
                if endpoint.supports_anonymous() {
                    GOOD
                } else {
                    BAD_IDENTITY_TOKEN_REJECTED
                }
            } else {
                // Read the token out from the extension object
                info!("Reading a user identity token from a bytestring");
                if let Ok(object_id) = user_identity_token.node_id.as_object_id() {
                    match object_id {
                        ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary => {
                            if endpoint.supports_anonymous() {
                                GOOD
                            } else {
                                BAD_IDENTITY_TOKEN_REJECTED
                            }
                        }
                        ObjectId::UserIdentityToken_Encoding_DefaultBinary => {
                            let result = user_identity_token.decode_inner::<UserNameIdentityToken>();
                            if let Ok(token) = result {
                                if self.validate_username_identity_token(&endpoint, &token) {
                                    GOOD
                                }
                                else {
                                    BAD_IDENTITY_TOKEN_REJECTED
                                }
                            }
                            else {
                                // Garbage in the extension object
                                error!("User name identity token could not be decoded");
                                BAD_IDENTITY_TOKEN_REJECTED
                            }
                        }
                        _ => {
                            BAD_IDENTITY_TOKEN_REJECTED
                        }
                    }
                } else {
                    BAD_IDENTITY_TOKEN_REJECTED
                }
            }
        } else {
            BAD_TCP_ENDPOINT_URL_INVALID
        }
    }

    /// Validate the username identity token
    pub fn validate_username_identity_token(&self, _: &ServerEndpoint, _: &UserNameIdentityToken) -> bool {
        // TODO need to check the specified endpoint to the user identity token and validate it
        // iterate ids in endpoint, for each id, find equivalent user in config, compare name & pass 
        false
    }
}

/// The Server represents a running instance of OPC UA. There can be more than one server running
/// at a time providing they do not share the same thread or listen on the same ports.
pub struct Server {
    /// The server state is everything that sessions share - address space, configuration etc.
    pub server_state: Arc<Mutex<ServerState>>,
    /// List of open connections
    pub connections: Vec<Arc<Mutex<TcpTransport>>>,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Server {
        if !config.is_valid() {
            panic!("Cannot create a server using an invalid configuration.");
        }

        // Set from config
        let application_name = config.application_name.clone();
        let application_uri = UAString::from(config.application_uri.as_ref());
        let product_uri = UAString::from(config.product_uri.as_ref());
        let namespaces = vec!["http://opcfoundation.org/UA/".to_string(), "urn:OPCUA-Rust-Internal".to_string(), config.application_uri.clone()];
        let start_time = DateTime::now();
        let servers = vec![config.application_uri.clone()];
        let base_endpoint = format!("opc.tcp://{}:{}", config.tcp_config.host, config.tcp_config.port);
        let max_subscriptions = config.max_subscriptions as usize;
        let address_space = Arc::new(Mutex::new(AddressSpace::new()));
        let diagnostics = ServerDiagnostics::new();
        // TODO max string, byte string and array lengths

        // Security, pki auto create cert
        let pki_path = PathBuf::from(&config.pki_dir);
        let certificate_store = CertificateStore::new(&pki_path);
        let (server_certificate, server_pkey) = if certificate_store.ensure_pki_path().is_err() {
            error!("Folder for storing certificates cannot be examined so server has no application instance certificate or private key.");
            (None, None)
        } else {
            let result = certificate_store.read_own_cert_and_pkey();
            if let Ok(result) = result {
                let (cert, pkey) = result;
                (Some(cert), Some(pkey))
            } else {
                // For sample projects, this value will be true and as a convenience we will create
                // a certificate and private key if they do not exist.
                if config.create_sample_keypair {
                    info!("Creating sample application instance certificate and private key");
                    let result = certificate_store.create_and_store_application_instance_cert(&X509Data::sample_cert(), false);
                    if let Err(err) = result {
                        error!("Certificate creation failed, error = {}", err);
                        (None, None)
                    } else {
                        let (cert, pkey) = result.unwrap();
                        (Some(cert), Some(pkey))
                    }
                } else {
                    error!("Application instance certificate and private key could not be read - {}", result.unwrap_err());
                    (None, None)
                }
            }
        };
        if server_certificate.is_none() || server_pkey.is_none() {
            error!("Server is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }
        let certificate_store = Arc::new(Mutex::new(certificate_store));
        let config = Arc::new(Mutex::new(config.clone()));

        let server_state = ServerState {
            application_uri,
            product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from(application_name),
            },
            namespaces,
            servers,
            base_endpoint,
            start_time,
            config,
            certificate_store,
            server_certificate,
            server_pkey,
            address_space,
            last_subscription_id: 0,
            max_subscriptions,
            min_publishing_interval: constants::MIN_PUBLISHING_INTERVAL,
            max_keep_alive_count: constants::MAX_KEEP_ALIVE_COUNT,
            diagnostics,
            abort: false,
        };

        // Set some values in the address space from the server state
        {
            let mut address_space = server_state.address_space.lock().unwrap();
            address_space.set_server_state(&server_state);
        }

        Server {
            server_state: Arc::new(Mutex::new(server_state)),
            connections: Vec::new()
        }
    }

    // Terminates the running server
    pub fn abort(&mut self) {
        let mut server_state = self.server_state.lock().unwrap();
        server_state.abort = true;
    }

    /// Runs the server
    pub fn run(&mut self) {
        let (host, port, _) = {
            let server_state = self.server_state.lock().unwrap();
            let config = server_state.config.lock().unwrap();
            (config.tcp_config.host.clone(), config.tcp_config.port, server_state.base_endpoint.clone())
        };
        let sock_addr = (host.as_str(), port);
        let listener = TcpListener::bind(&sock_addr).unwrap();

        {
            let server_state = self.server_state.lock().unwrap();
            let config = server_state.config.lock().unwrap();

            info!("OPC UA Server: {}", server_state.application_name);
            info!("Supported endpoints:");
            for (id, endpoint) in &config.endpoints {
                let users: Vec<String> = endpoint.user_token_ids.iter().map(|id| id.clone()).collect();
                let users = users.join(", ");

                info!("Endpoint \"{}\": {}", id, endpoint.path);
                info!("  Security Mode:    {}", endpoint.security_mode);
                info!("  Security Policy:  {}", endpoint.security_policy);
                info!("  Supported user tokens - {}", users);
            }
        }
        info!("Waiting for Connection");

        // This iterator runs forever, just accept()'ing the next incoming connection.
        for stream in listener.incoming() {
            if self.is_abort() {
                info!("Server is aborting");
                break;
            }
            info!("Handling new connection {:?}", stream);
            match stream {
                Ok(stream) => {
                    self.handle_connection(stream);
                }
                Err(err) => {
                    warn!("Got an error on stream {:?}", err);
                }
            }
            // Clear out dead sessions
            self.remove_dead_connections();
        }
    }

    fn is_abort(&mut self) -> bool {
        let server_state = self.server_state.lock().unwrap();
        server_state.abort
    }

    fn remove_dead_connections(&mut self) {
        // Go through all connections, removing those that have terminated
        self.connections.retain(|connection| {
            // Try to obtain the lock on the transport and the session and check if session is terminated
            // if it is, then we'll use its termination status to sweep it out.
            let mut lock = connection.try_lock();
            if let Ok(ref mut connection) = lock {
                let mut lock = connection.session.try_lock();
                if let Ok(ref mut session) = lock {
                    if session.terminated {
                        info!("Removing terminated session");
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            }
        });
    }

    /// Creates a polling action that happens continuously on an interval. The supplied
    /// function receives the address space which it can do what it likes with.
    ///
    /// This function is be updating values in the address space individually or en masse.
    /// The returned PollingAction will ensure the function is called for as long as it is
    /// in scope. Once the action is dropped, the function will no longer be called.
    pub fn create_address_space_polling_action<F>(&mut self, interval_ms: u32, action: F) -> PollingAction
        where F: 'static + FnMut(&mut AddressSpace) + Send {
        let mut action = action;
        let address_space = {
            let server_state = self.server_state.lock().unwrap();
            server_state.address_space.clone()
        };
        PollingAction::new(interval_ms, move || {
            // Call the provided closure with the address space
            action(&mut address_space.lock().unwrap());
        })
    }

    /// Handles the incoming request
    fn handle_connection(&mut self, stream: TcpStream) {
        trace!("Connection thread spawning");
        // Spawn a thread for the connection
        let session = Arc::new(Mutex::new(TcpTransport::new(self.server_state.clone())));
        self.connections.push(session.clone());
        thread::spawn(move || {
            session.lock().unwrap().run(stream);
            info!("Session thread is terminated");
        });
    }
}
