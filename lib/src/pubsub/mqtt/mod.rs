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
        return format!("mqtt://{}:{}{}", self.domain, self.port, self.path);
    }
}
