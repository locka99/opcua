use url::Url;

use crate::types::*;

/// MQTT scheme
pub const MQTT_SCHEME: &'static str = "mqtt";

/// Default MQTT port
pub const MQTT_DEFAULT_PORT: u16 = 8333;

/// Default
pub const WSS_DEFAULT_PORT: u16 = 443;

/// Configuration of an MQTT connection
pub struct MQTTConfig {
    domain: String,
    port: u16,
    path: String,
    qos: BrokerTransportQualityOfService,
}

impl TryFrom<&str> for MQTTConfig {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(url) = Url::parse(value) {
            let scheme = url.scheme();
            if scheme == MQTT_SCHEME {
                let domain = url.domain().unwrap_or("");
                let port = url.port().unwrap_or(MQTT_DEFAULT_PORT);
                let path = url.path();
                Ok(MQTTConfig::new(domain, port, path))
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }
}

impl MQTTConfig {
    pub fn new<S, T>(domain: S, port: u16, path: T) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        Self {
            domain: domain.into(),
            port,
            path: path.into(),
            qos: BrokerTransportQualityOfService::AtLeastOnce,
        }
    }

    pub fn as_url(&self) -> String {
        return format!(
            "{}://{}:{}{}",
            MQTT_SCHEME, self.domain, self.port, self.path
        );
    }
}
