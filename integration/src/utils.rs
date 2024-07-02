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
    async_server::{ServerBuilder, ServerHandle, ServerUserToken},
    client::{Client, ClientBuilder, IdentityToken, Session, SessionEventLoop},
    crypto::SecurityPolicy,
    types::{MessageSecurityMode, StatusCode, UserTokenPolicy},
};
use tokio::net::TcpListener;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{CLIENT_USERPASS_ID, CLIENT_X509_ID};

pub struct Tester {
    pub handle: ServerHandle,
    pub client: Client,
    pub token: CancellationToken,
    _guard: DropGuard,
    pub addr: SocketAddr,
    pub test_id: u16,
}

pub static TEST_COUNTER: AtomicU16 = AtomicU16::new(0);

const USER_X509_CERTIFICATE_PATH: &str = "./x509/user_cert.der";
const USER_X509_PRIVATE_KEY_PATH: &str = "./x509/user_private_key.pem";

pub fn default_server(port: u16, test_id: u16) -> ServerBuilder {
    let endpoint_path = "/";
    let user_token_ids = vec![
        opcua::server::prelude::ANONYMOUS_USER_TOKEN_ID,
        CLIENT_USERPASS_ID,
        CLIENT_X509_ID,
    ];
    ServerBuilder::new()
        .application_name("intagration_server")
        .application_uri("urn:integration_server")
        .discovery_urls(vec![format!("opc.tcp://127.0.0.1:{port}")])
        .create_sample_keypair(true)
        .pki_dir(format!("./pki-server/{test_id}"))
        .host("127.0.0.1")
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
        )
}

impl Tester {
    pub async fn new(server: ServerBuilder, quick_timeout: bool) -> Self {
        let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let server = server.pki_dir(format!("./pki-server/{test_id}"));

        let (server, handle) = server.build().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = CancellationToken::new();
        let addr = listener.local_addr().unwrap();

        tokio::task::spawn(server.run_with(listener, token.clone()));

        let client = ClientBuilder::new()
            .application_name("integration_client")
            .application_uri("x")
            .pki_dir(format!("./pki-client/{test_id}"))
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(200));

        let client = if quick_timeout {
            client.session_retry_limit(1)
        } else {
            client
        };
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

    pub async fn new_custom_client(server: ServerBuilder, client: ClientBuilder) -> Self {
        let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let server = server.pki_dir(format!("./pki-server/{test_id}"));
        let client = client.pki_dir(format!("./pki-client/{test_id}"));

        let (server, handle) = server.build().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = CancellationToken::new();
        let addr = listener.local_addr().unwrap();

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
        token_policy: UserTokenPolicy,
        user_identity: IdentityToken,
    ) -> Result<(Arc<Session>, SessionEventLoop), StatusCode> {
        self.client
            .new_session_from_endpoint(
                (
                    self.handle.info().base_endpoint().as_ref(),
                    security_policy.to_str(),
                    security_mode,
                    token_policy,
                ),
                user_identity,
            )
            .await
    }

    pub async fn connect_default(
        &mut self,
    ) -> Result<(Arc<Session>, SessionEventLoop), StatusCode> {
        self.connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            UserTokenPolicy::anonymous(),
            IdentityToken::Anonymous,
        )
        .await
    }
}
