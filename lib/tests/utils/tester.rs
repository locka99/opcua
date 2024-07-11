use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua::{
    async_server::{
        node_manager::memory::InMemoryNodeManager, ServerBuilder, ServerHandle, ServerUserToken,
        ANONYMOUS_USER_TOKEN_ID,
    },
    client::{Client, ClientBuilder, IdentityToken, Session, SessionEventLoop},
    crypto::SecurityPolicy,
    types::{MessageSecurityMode, StatusCode},
};
use tokio::net::TcpListener;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::{TestNodeManager, TestNodeManagerImpl, CLIENT_USERPASS_ID, CLIENT_X509_ID};

pub struct Tester {
    pub handle: ServerHandle,
    pub client: Client,
    pub token: CancellationToken,
    _guard: DropGuard,
    pub addr: SocketAddr,
    pub test_id: u16,
}

pub static TEST_COUNTER: AtomicU16 = AtomicU16::new(0);

#[allow(unused)]
const USER_X509_CERTIFICATE_PATH: &str = "./tests/x509/user_cert.der";
#[allow(unused)]
const USER_X509_PRIVATE_KEY_PATH: &str = "./tests/x509/user_private_key.pem";

pub fn hostname() -> String {
    // To avoid certificate trouble, use the computer's own name for the endpoint
    let mut names = opcua::crypto::X509Data::computer_hostnames();
    if names.is_empty() {
        "localhost".to_string()
    } else {
        names.remove(0)
    }
}

#[allow(unused)]
pub async fn setup() -> (Tester, Arc<TestNodeManager>, Arc<Session>) {
    let (server, nm) = test_server();
    let mut tester = Tester::new(server, false).await;
    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    (tester, nm, session)
}

#[allow(unused)]
pub fn client_user_token() -> IdentityToken {
    IdentityToken::UserName(
        CLIENT_USERPASS_ID.to_owned(),
        format!("{CLIENT_USERPASS_ID}_password"),
    )
}

#[allow(unused)]
pub fn client_x509_token() -> IdentityToken {
    IdentityToken::X509(
        PathBuf::from(USER_X509_CERTIFICATE_PATH),
        PathBuf::from(USER_X509_PRIVATE_KEY_PATH),
    )
}

pub fn default_server() -> ServerBuilder {
    let endpoint_path = "/";
    let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID, CLIENT_USERPASS_ID, CLIENT_X509_ID];
    let mut builder = ServerBuilder::new()
        .application_name("intagration_server")
        .application_uri("urn:integration_server")
        .create_sample_keypair(true)
        .host(hostname())
        .trust_client_certs(true)
        .add_user_token(
            CLIENT_USERPASS_ID,
            ServerUserToken::user_pass(
                CLIENT_USERPASS_ID,
                &format!("{CLIENT_USERPASS_ID}_password"),
            ),
        )
        .add_user_token(
            CLIENT_X509_ID,
            ServerUserToken::x509(CLIENT_X509_ID, &PathBuf::from(USER_X509_CERTIFICATE_PATH)),
        )
        .add_endpoint(
            "none",
            (
                endpoint_path,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic128rsa15_sign",
            (
                endpoint_path,
                SecurityPolicy::Basic128Rsa15,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic128rsa15_sign_encrypt",
            (
                endpoint_path,
                SecurityPolicy::Basic128Rsa15,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256_sign",
            (
                endpoint_path,
                SecurityPolicy::Basic256,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256_sign_encrypt",
            (
                endpoint_path,
                SecurityPolicy::Basic256,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256sha256_sign",
            (
                endpoint_path,
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256sha256_sign_encrypt",
            (
                endpoint_path,
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "endpoint_aes128sha256rsaoaep_sign",
            (
                endpoint_path,
                SecurityPolicy::Aes128Sha256RsaOaep,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "endpoint_aes128sha256rsaoaep_sign_encrypt",
            (
                endpoint_path,
                SecurityPolicy::Aes128Sha256RsaOaep,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "endpoint_aes256sha256rsapss_sign",
            (
                endpoint_path,
                SecurityPolicy::Aes256Sha256RsaPss,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "endpoint_aes256sha256rsapss_sign_encrypt",
            (
                endpoint_path,
                SecurityPolicy::Aes256Sha256RsaPss,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        );

    let limits = builder.limits_mut();
    limits.max_message_size = 1024 * 1024 * 64;
    limits.max_array_length = 100_000;
    limits.subscriptions.max_queued_notifications = 200;

    builder
}

pub fn default_client(test_id: u16, quick_timeout: bool) -> ClientBuilder {
    let client = ClientBuilder::new()
        .application_name("integration_client")
        .application_uri("x")
        .pki_dir(format!("./pki-client/{test_id}"))
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_initial(Duration::from_millis(200))
        .max_array_length(100_000)
        .max_message_size(1024 * 1024 * 64);
    let client = if quick_timeout {
        client.session_retry_limit(1)
    } else {
        client
    };
    client
}

#[allow(unused)]
pub fn test_server() -> (ServerBuilder, Arc<TestNodeManager>) {
    let mgr = Arc::new(InMemoryNodeManager::new(TestNodeManagerImpl::new(2)));
    (default_server().with_node_manager(mgr.clone()), mgr)
}

impl Tester {
    async fn listener() -> TcpListener {
        TcpListener::bind(format!("{}:0", hostname()))
            .await
            .unwrap()
    }

    #[allow(unused)]
    pub async fn new_default_server(quick_timeout: bool) -> Self {
        opcua::console_logging::init();

        let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let listener = Self::listener().await;
        let addr = listener.local_addr().unwrap();

        let server = default_server()
            .discovery_urls(vec![format!("opc.tcp://{}:{}", hostname(), addr.port())])
            .pki_dir(format!("./pki-server/{test_id}"));

        let (server, handle) = server.build().unwrap();
        let token = CancellationToken::new();

        tokio::task::spawn(server.run_with(listener, token.clone()));

        let client = default_client(test_id, quick_timeout).client().unwrap();

        Self {
            handle,
            client,
            _guard: token.clone().drop_guard(),
            token,
            addr,
            test_id,
        }
    }

    #[allow(unused)]
    pub async fn new(server: ServerBuilder, quick_timeout: bool) -> Self {
        opcua::console_logging::init();

        let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let listener = Self::listener().await;
        let token = CancellationToken::new();
        let addr = listener.local_addr().unwrap();

        let server = server
            .pki_dir(format!("./pki-server/{test_id}"))
            .discovery_urls(vec![format!("opc.tcp://{}:{}", hostname(), addr.port())]);

        let (server, handle) = server.build().unwrap();

        tokio::task::spawn(server.run_with(listener, token.clone()));

        let client = default_client(test_id, quick_timeout).client().unwrap();

        Self {
            handle,
            client,
            _guard: token.clone().drop_guard(),
            token,
            addr,
            test_id,
        }
    }

    #[allow(unused)]
    pub async fn new_custom_client(server: ServerBuilder, client: ClientBuilder) -> Self {
        opcua::console_logging::init();

        let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let listener = Self::listener().await;
        let token = CancellationToken::new();
        let addr = listener.local_addr().unwrap();

        let server = server
            .pki_dir(format!("./pki-server/{test_id}"))
            .discovery_urls(vec![format!("opc.tcp://{}:{}", hostname(), addr.port())]);
        let client = client.pki_dir(format!("./pki-client/{test_id}"));

        let (server, handle) = server.build().unwrap();

        tokio::task::spawn(server.run_with(listener, token.clone()));

        let client = client.client().unwrap();

        Self {
            handle,
            client,
            _guard: token.clone().drop_guard(),
            token,
            addr,
            test_id,
        }
    }

    pub async fn connect(
        &mut self,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_identity: IdentityToken,
    ) -> Result<(Arc<Session>, SessionEventLoop), StatusCode> {
        self.client
            .new_session_from_endpoint(
                (
                    &self.endpoint() as &str,
                    security_policy.to_str(),
                    security_mode,
                ),
                user_identity,
            )
            .await
    }

    #[allow(unused)]
    pub async fn connect_default(
        &mut self,
    ) -> Result<(Arc<Session>, SessionEventLoop), StatusCode> {
        self.connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await
    }

    pub fn endpoint(&self) -> String {
        format!("opc.tcp://{}:{}/", hostname(), self.addr.port())
    }
}
