use std::path::PathBuf;

use opcua_core::config::Config;

use config::{ServerConfig, ServerEndpoint};
use server::Server;

pub struct ServerBuilder {
    config: ServerConfig,
}

impl ServerBuilder {
    pub fn new() -> Self {
        ServerBuilder {
            config: ServerConfig::default()
        }
    }

    /// Yields a [`Client`] from the values set by the builder. If the builder is not in a valid state
    /// it will return `None`.
    ///
    /// [`Server`]: ../server/struct.Server.html
    pub fn server(self) -> Option<Server> {
        if self.is_valid() {
            Some(Server::new(self.config))
        } else {
            None
        }
    }

    /// Yields a [`ClientConfig`] from the values set by the builder.
    ///
    /// [`ServerConfig`]: ../config/struct.ServerConfig.html
    pub fn config(self) -> ServerConfig {
        self.config
    }

    pub fn is_valid(&self) -> bool {
        self.config.is_valid()
    }

    /// Sets the application name.
    pub fn application_name<T>(mut self, application_name: T) -> Self where T: Into<String> {
        self.config.application_name = application_name.into();
        self
    }

    /// Sets the application uri
    pub fn application_uri<T>(mut self, application_uri: T) -> Self where T: Into<String> {
        self.config.application_uri = application_uri.into();
        self
    }

    /// Sets the product uri.
    pub fn product_uri<T>(mut self, product_uri: T) -> Self where T: Into<String> {
        self.config.product_uri = product_uri.into();
        self
    }

    /// Sets whether the client should generate its own key pair if there is none found in the pki
    /// directory.
    pub fn create_sample_keypair(mut self, create_sample_keypair: bool) -> Self {
        self.config.create_sample_keypair = create_sample_keypair;
        self
    }

    /// Sets the pki directory where client's own key pair is stored and where `/trusted` and
    /// `/rejected` server certificates are stored.
    pub fn pki_dir<T>(mut self, pki_dir: T) -> Self where T: Into<PathBuf> {
        self.config.pki_dir = pki_dir.into();
        self
    }

    /// Adds an endpoint to the list of endpoints the client knows of.
    pub fn endpoint<T>(mut self, endpoint_id: T, endpoint: ServerEndpoint) -> Self where T: Into<String> {
        self.config.endpoints.insert(endpoint_id.into(), endpoint);
        self
    }

    /// Adds multiple endpoints to the list of endpoints the client knows of.
    pub fn endpoints<T>(mut self, endpoints: Vec<(T, ServerEndpoint)>) -> Self where T: Into<String> {
        for e in endpoints {
            self.config.endpoints.insert(e.0.into(), e.1);
        };
        self
    }
}